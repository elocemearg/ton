/* Functions for getting a list of all the broadcast-enabled and/or
 * multicast-enabled network interfaces we have available. This is very
 * OS-dependent so most functions are defined twice, once for Windows and
 * once for Linux. */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>

#include "netif.h"
#include "utils.h"
#include "defaults.h"

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#include <ws2ipdef.h> /* for struct sockaddr_in6 */
#include <iphlpapi.h> /* for GetAdaptersAddresses() */
#else
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#endif

static struct ttt_netif *
ttt_netif_new(void) {
    struct ttt_netif *iface = malloc(sizeof(struct ttt_netif));
    if (iface == NULL) {
        return NULL;
    }
    memset(iface, 0, sizeof(*iface));
    iface->sock = -1;
    return iface;
}

void
ttt_netif_list_free(struct ttt_netif *list, int close_sockets) {
    struct ttt_netif *cur, *next;
    for (cur = list; cur != NULL; cur = next) {
        next = cur->next;
        if (cur->sock >= 0) {
            closesocket(cur->sock);
        }
        free(cur);
    }
}

static int
netif_fam_addr_cmp(const void *v1, const void *v2) {
    const struct ttt_netif *n1 = *(const struct ttt_netif **) v1;
    const struct ttt_netif *n2 = *(const struct ttt_netif **) v2;
    if (n1->family < n2->family)
        return -1;
    else if (n1->family > n2->family)
        return 1;
    else {
        switch (n1->family) {
            case AF_INET:
                return memcmp(&((const struct sockaddr_in *) &n1->if_addr)->sin_addr,
                        &((const struct sockaddr_in *) &n2->if_addr)->sin_addr,
                        sizeof(struct in_addr));
            case AF_INET6:
                return memcmp(&((const struct sockaddr_in6 *) &n1->if_addr)->sin6_addr,
                        &((const struct sockaddr_in6 *) &n2->if_addr)->sin6_addr,
                        sizeof(struct in6_addr));
            default:
                return 0;
        }
    }
}

static void
netif_list_sort(struct ttt_netif **first, struct ttt_netif **last) {
    struct ttt_netif **array = NULL;
    struct ttt_netif *prev;
    int count = 0;
    int pos = 0;

    /* Count how many elements are in the list, and if there are fewer than
     * two, it's already sorted */
    for (struct ttt_netif *i = *first; i; i = i->next) {
        count++;
    }
    if (count < 2)
        return;

    /* Allocate an array, one for a pointer to each item */
    array = malloc(sizeof(struct ttt_netif *) * count);
    if (array == NULL) {
        ttt_error(1, errno, "netif_list_sort: out of memory");
    }

    /* Put all the item pointers into an array */
    pos = 0;
    for (struct ttt_netif *i = *first; i; i = i->next) {
        array[pos++] = i;
    }

    /* Sort the array */
    qsort(array, count, sizeof(array[0]), netif_fam_addr_cmp);

    /* Fix the linked list pointers */
    prev = NULL;
    for (pos = 0; pos < count; ++pos) {
        if (prev == NULL) {
            *first = array[pos];
        }
        else {
            prev->next = array[pos];
        }
        prev = array[pos];
    }
    prev->next = NULL;
    *last = prev;

    free(array);
}

static void
netif_remove_duplicates(struct ttt_netif **first, struct ttt_netif **last) {
    struct ttt_netif *prev, *cur, *next;
    prev = NULL;
    for (cur = *first; cur; cur = next) {
        next = cur->next;
        if (prev != NULL && netif_fam_addr_cmp((const void *) &prev, (const void *) &cur) == 0) {
            /* This is the same address and family as prev, so remove it
             * from the list */
            prev->next = next;
            cur->next = NULL;
            ttt_netif_list_free(cur, 1);
        }
        else {
            prev = cur;
        }
    }
    *last = prev;
}

#ifdef UNIX
static struct ttt_netif *
get_if_addrs(int address_families_flags, unsigned int required_iff_flags) {
    struct ifaddrs *ifs = NULL;
    int rc = 0;
    struct ttt_netif *first = NULL;
    struct ttt_netif *last = NULL;
    int sock = -1;
    struct addrinfo *ipv6_bcast = NULL;
    struct addrinfo hints;

    rc = getifaddrs(&ifs);
    if (rc != 0) {
        return NULL;
    }

    if (ifs == NULL) {
        return NULL;
    }

    /* Get the IPv6 broadcast address, which isn't really a broadcast address
     * but we're going to call it one */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    rc = getaddrinfo("ff02::1", NULL, &hints, &ipv6_bcast);
    if (rc != 0) {
        ttt_error(0, 0, "getaddrinfo() failed on IPv6 address ff02::1: %s", gai_strerror(rc));
    }

    /* Get a socket so we can use ioctls - we won't use it to connect
     * to anything. */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ttt_socket_error(0, "socket");
        goto fail;
    }

    for (struct ifaddrs *iface = ifs; iface; iface = iface->ifa_next) {
        /* Only look at those interfaces which match the capabilities we want,
         * which have an address, and which are either AF_INET or AF_INET6
         * where that address family is requested in address_families_flags. */
        if ((iface->ifa_flags & required_iff_flags) == required_iff_flags &&
                iface->ifa_addr != NULL &&
                ((iface->ifa_addr->sa_family == AF_INET && (address_families_flags & TTT_IPV4) != 0) ||
                 (iface->ifa_addr->sa_family == AF_INET6 && (address_families_flags & TTT_IPV6) != 0))) {
            struct ifreq ifreq;
            struct ttt_netif *netif = ttt_netif_new();
            int socklen;

            /* Populate netif with the information in iface */
            socklen = (iface->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            memcpy(&netif->if_addr, iface->ifa_addr, socklen);
            netif->if_addr_len = socklen;
            netif->family = iface->ifa_addr->sa_family;

            if (iface->ifa_broadaddr != NULL) {
                /* getifaddrs() tells us what the broadcast address is for
                 * this interface. */
                socklen = (iface->ifa_broadaddr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                memcpy(&netif->bc_addr, iface->ifa_broadaddr, socklen);
                netif->bc_addr_len = socklen;
                netif->bc_valid = 1;
            }
            else if (netif->family == AF_INET6 && ipv6_bcast != NULL) {
                /* If this is an IPv6 address, iface->ifa_broadaddr won't be
                 * filled in but we use the standard IPv6 "all nodes on the
                 * local network" address ff02::1 */
                memcpy(&netif->bc_addr, ipv6_bcast->ai_addr, ipv6_bcast->ai_addrlen);
                netif->bc_addr_len = ipv6_bcast->ai_addrlen;
                netif->bc_valid = 1;
            }
            else {
                /* No broadcast address for this interface. */
                netif->bc_addr_len = 0;
                netif->bc_valid = 0;
            }

            strncpy(ifreq.ifr_name, iface->ifa_name, IFNAMSIZ);
            ifreq.ifr_name[IFNAMSIZ - 1] = '\0';

            rc = ioctl(sock, SIOCGIFINDEX, &ifreq);
            if (rc != 0) {
                ttt_error(0, errno, "ioctl SIOCGIFINDEX %s", iface->ifa_name);
                ttt_netif_list_free(netif, 0);
            }
            else {
                netif->if_index_ipv4 = ifreq.ifr_ifindex;
                netif->if_index_ipv6 = ifreq.ifr_ifindex;
                netif->next = NULL;

                /* Add netif to our list */
                if (first == NULL) {
                    first = netif;
                }
                if (last == NULL) {
                    last = netif;
                }
                else {
                    last->next = netif;
                    last = netif;
                }
            }
        }
    }

    netif_list_sort(&first, &last);
    netif_remove_duplicates(&first, &last);

end:
    if (ipv6_bcast != NULL)
        freeaddrinfo(ipv6_bcast);
    if (ifs != NULL)
        freeifaddrs(ifs);
    return first;

fail:
    ttt_netif_list_free(first, 0);
    first = NULL;
    last = NULL;
    goto end;
}

struct ttt_netif *
ttt_get_multicast_ifs(int address_families_flags) {
    return get_if_addrs(address_families_flags, IFF_MULTICAST | IFF_UP);
}

struct ttt_netif *
ttt_get_broadcast_ifs(int address_families_flags) {
    /* IPv6 disabled for now until we can listen on both IPv4 and IPv6 */
    return get_if_addrs(address_families_flags, IFF_BROADCAST | IFF_UP);
}
#endif

#ifdef WINDOWS

static int
is_useful_interface(IP_ADAPTER_ADDRESSES *addr, int multicast_only) {
    if ((addr->Flags & IP_ADAPTER_RECEIVE_ONLY) != 0)
        return 0;
    if (multicast_only && (addr->Flags & IP_ADAPTER_NO_MULTICAST) != 0)
        return 0;
    if (addr->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        return 0;
    return 1;
}

static struct ttt_netif *
get_if_addrs(int address_families_flags, int multicast_only) {
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    ULONG addrs_size;
    ULONG ret;
    struct ttt_netif *first = NULL, *last = NULL;

    /* Microsoft recommends allocating 15KB and calling GetAdaptersAddress
     * with a progressively larger buffer until it's big enough.
     * https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
     */
    addrs_size = 15 * 1024;
    addrs = malloc(addrs_size);
    if (addrs == NULL)
        return NULL;

    do {
        ret = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &addrs_size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            IP_ADAPTER_ADDRESSES *new_addrs;
            addrs_size *= 2;
            new_addrs = realloc(addrs, addrs_size);
            if (new_addrs == NULL) {
                free(addrs);
                return NULL;
            }
            addrs = new_addrs;
        }
    } while (ret == ERROR_BUFFER_OVERFLOW);

    if (ret != ERROR_SUCCESS) {
        free(addrs);
        return NULL;
    }

    for (IP_ADAPTER_ADDRESSES *addr = addrs; addr; addr = addr->Next) {
        if (is_useful_interface(addr, multicast_only)) {
            /* Iterate over all addresses assigned to this interface - there
             * may be more than one, and they may be different address
             * families. */
            for (PIP_ADAPTER_UNICAST_ADDRESS ua = addr->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
                struct ttt_netif *netif;

                /* Check that the address family for this interface is
                 * compatible with the address families we're accepting... */
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    if ((address_families_flags & TTT_IPV4) == 0)
                        continue;
                }
                else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    if ((address_families_flags & TTT_IPV6) == 0)
                        continue;
                }
                else {
                    /* Reject anything that isn't IPv4 or IPv6 */
                    continue;
                }

                /* If we get here, then this address of this interface is of
                 * interest to us. Add it to the list of items we'll return. */
                netif = ttt_netif_new();
                netif->family = ua->Address.lpSockaddr->sa_family;
                netif->if_addr_len = ua->Address.iSockaddrLength;
                memcpy(&netif->if_addr, ua->Address.lpSockaddr, netif->if_addr_len);

                netif->bc_valid = 0;
                netif->bc_addr_len = 0;
                netif->if_index_ipv4 = addr->IfIndex;
                netif->if_index_ipv6 = addr->Ipv6IfIndex;
                netif->next = NULL;

                if (first == NULL) {
                    first = netif;
                }
                if (last == NULL) {
                    last = netif;
                }
                else {
                    last->next = netif;
                    last = netif;
                }
            }
        }
    }

    netif_list_sort(&first, &last);
    netif_remove_duplicates(&first, &last);

    free(addrs);
    return first;
}

struct ttt_netif *
ttt_get_multicast_ifs(int address_families_flags) {
    return get_if_addrs(address_families_flags, 1);
}

struct ttt_netif *
ttt_get_broadcast_ifs(int address_families_flags) {
    /* Only using multicast on Windows currently */
    return NULL;
}
#endif

/* List of multicast interface addresses. We populate this the first time
 * multicast_interfaces_subscribe() is called. */
static struct ttt_netif *multicast_ifs = NULL;

/* Subscribe or unsubscribe all multicast-enabled interfaces to/from
 * multicast_addr_str on the given socket. */
static int
multicast_interfaces_change_membership(int sock, const char *multicast_addr_str, int subscribe) {
    struct addrinfo hints;
    struct addrinfo *multicast_addr = NULL;
    int num_multicast_succeeded = 0;
    int rc;
    struct ttt_netif *prev;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(multicast_addr_str, NULL, &hints, &multicast_addr);
    if (rc != 0) {
        ttt_error(0, 0, "getaddrinfo: %s: %s", multicast_addr_str, gai_strerror(rc));
        return -1;
    }

    if (multicast_addr->ai_family != AF_INET && multicast_addr->ai_family != AF_INET6) {
        ttt_error(0, 0, "Multicast group address %s not recognised as IPv4 or IPv6 (ai_family %d)", multicast_addr_str, multicast_addr->ai_family);
        freeaddrinfo(multicast_addr);
        return -1;
    }

    if (multicast_ifs == NULL) {
        errno = 0;
        /* This list will stick globally, so get both IPv4 and IPv6 interfaces
         * regardless of what family multicast_addr is. */
        multicast_ifs = ttt_get_multicast_ifs(TTT_IP_BOTH);
        if (multicast_ifs == NULL && errno != 0) {
            ttt_error(0, errno, "failed to get list of multicast interfaces");
        }
    }

    prev = NULL;
    for (struct ttt_netif *netif = multicast_ifs; netif; netif = netif->next) {
        /* Go through every multicast-enabled interface and enable it to
         * receive multicast messages to multicast_addr_str.
         * This might not work on some interfaces, but we return the number
         * of interfaces on which we successfully called setsockopt. */
        if (netif->family == AF_INET && multicast_addr->ai_family == AF_INET) {
            struct ip_mreq group;
            group.imr_multiaddr.s_addr = ((struct sockaddr_in *) multicast_addr->ai_addr)->sin_addr.s_addr;
            group.imr_interface.s_addr = ((struct sockaddr_in *) &netif->if_addr)->sin_addr.s_addr;
            if (setsockopt(sock, IPPROTO_IP, subscribe ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, (char *) &group, sizeof(group)) == 0) {
                num_multicast_succeeded++;
            }
        }
        if (netif->family == AF_INET6 && multicast_addr->ai_family == AF_INET6) {
            struct ipv6_mreq group;
            if (prev == NULL || prev->family != AF_INET6 || prev->if_index_ipv6 != netif->if_index_ipv6) {
                /* Don't need to subscribe to the same multicast group for
                 * every IPv6 address an interface has - just once per
                 * interface is enough. If this interface is a different
                 * address family or interface index number from the previous,
                 * make the call to join the group with this interface. */
                memcpy(&group.ipv6mr_multiaddr, &((struct sockaddr_in6 *) multicast_addr->ai_addr)->sin6_addr, sizeof(group.ipv6mr_multiaddr));
                group.ipv6mr_interface = netif->if_index_ipv6;
                if (setsockopt(sock, IPPROTO_IPV6, subscribe ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP, (char *) &group, sizeof(group)) == 0) {
                    num_multicast_succeeded++;
                }
            }
        }
        prev = netif;
    }
    freeaddrinfo(multicast_addr);

    return num_multicast_succeeded;
}

int
multicast_interfaces_subscribe(int sock, const char *multicast_addr_str) {
    return multicast_interfaces_change_membership(sock, multicast_addr_str, 1);
}

int
multicast_interfaces_unsubscribe(int sock, const char *multicast_addr_str) {
    return multicast_interfaces_change_membership(sock, multicast_addr_str, 0);
}
