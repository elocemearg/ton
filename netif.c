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

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#include <ws2ipdef.h> /* for struct sockaddr_in6 */
#include <iphlpapi.h> /* for GetAdaptersAddresses() */
#else
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

#ifdef UNIX
static struct sockaddr **
get_if_addrs(int *num_output_ifs, unsigned int required_iff_flags, int include_ipv6, int use_broadaddr) {
    struct ifaddrs *ifs = NULL;
    int rc = 0;
    int num_input_ifs = 0;
    struct sockaddr **sockaddrs = NULL;
    int num_sockaddrs = 0;

    *num_output_ifs = 0;

    rc = getifaddrs(&ifs);
    if (rc != 0) {
        return NULL;
    }

    for (struct ifaddrs *iface = ifs; iface; iface = iface->ifa_next) {
        num_input_ifs++;
    }

    if (num_input_ifs == 0) {
        if (ifs) {
            freeifaddrs(ifs);
        }
        return NULL;
    }

    sockaddrs = malloc(sizeof(struct sockaddr *) * num_input_ifs);
    if (sockaddrs == NULL) {
        goto fail;
    }
    memset(sockaddrs, 0, sizeof(struct sockaddr *) * num_input_ifs);

    for (struct ifaddrs *iface = ifs; iface; iface = iface->ifa_next) {
        if ((iface->ifa_flags & required_iff_flags) == required_iff_flags) {
            struct sockaddr *sa;
            if (use_broadaddr)
                sa = iface->ifa_broadaddr;
            else
                sa = iface->ifa_addr;
            if (sa && (sa->sa_family == AF_INET || (sa->sa_family == AF_INET6 && include_ipv6))) {
                int socklen = (sa->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                sockaddrs[num_sockaddrs] = malloc(socklen);
                if (sockaddrs[num_sockaddrs] == NULL) {
                    goto fail;
                }
                memcpy(sockaddrs[num_sockaddrs], sa, socklen);
                num_sockaddrs++;
            }
        }
    }

end:
    freeifaddrs(ifs);
    *num_output_ifs = num_sockaddrs;
    return sockaddrs;

fail:
    for (int i = 0; i < num_sockaddrs; ++i) {
        free(sockaddrs[i]);
    }
    free(sockaddrs);
    sockaddrs = NULL;
    num_sockaddrs = 0;
    goto end;
}

struct sockaddr **
ttt_get_multicast_if_addrs(int *num_ifaces) {
    return get_if_addrs(num_ifaces, IFF_MULTICAST | IFF_UP, 0, 0);
}

struct sockaddr **
ttt_get_broadcast_if_addrs(int *num_ifaces) {
    /* IPv6 disabled for now until we can listen on both IPv4 and IPv6 */
    return get_if_addrs(num_ifaces, IFF_BROADCAST | IFF_UP, 0, 1);
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

static struct sockaddr **
get_if_addrs(int *num_output_ifs_r, int include_ipv6, int use_broadaddr, int multicast_only) {
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    ULONG addrs_size;
    ULONG ret;
    int num_output_ifs = 0;
    struct sockaddr **returned_addrs = NULL;

    if (num_output_ifs_r != NULL)
        *num_output_ifs_r = 0;

    if (use_broadaddr) {
        /* Not supporting broadcasts on Windows at the moment. */
        return NULL;
    }

    /* Microsoft recommends allocating 15KB and calling GetAdaptersAddress
     * with a progressively larger buffer until it's big enough.
     * https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
     */
    addrs_size = 15 * 1024;
    addrs = malloc(addrs_size);
    if (addrs == NULL)
        return NULL;

    do {
        ret = GetAdaptersAddresses(include_ipv6 ? AF_UNSPEC : AF_INET, 0,
                NULL, addrs, &addrs_size);
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

    /* Count the number of applicable interfaces */
    for (IP_ADAPTER_ADDRESSES *addr = addrs; addr; addr = addr->Next) {
        if (is_useful_interface(addr, multicast_only)) {
            num_output_ifs++;
        }
    }

    if (num_output_ifs > 0) {
        /* Allocate an array of struct sockaddr pointers and copy the addresses
         * into it. */
        int if_index = 0;
        returned_addrs = malloc(sizeof(struct sockaddr *) * num_output_ifs);
        memset(returned_addrs, 0, sizeof(struct sockaddr *) * num_output_ifs);
        for (IP_ADAPTER_ADDRESSES *addr = addrs; addr; addr = addr->Next) {
            if (is_useful_interface(addr, multicast_only)) {
                PIP_ADAPTER_UNICAST_ADDRESS ua = addr->FirstUnicastAddress;
                if (ua == NULL)
                    continue;
                assert(if_index < num_output_ifs);
                returned_addrs[if_index] = malloc(ua->Address.iSockaddrLength);
                if (returned_addrs[if_index] == NULL) {
                    goto fail;
                }
                memcpy(returned_addrs[if_index], ua->Address.lpSockaddr, ua->Address.iSockaddrLength);
                if_index++;
            }
        }
        num_output_ifs = if_index;
    }

end:
    free(addrs);
    if (num_output_ifs_r)
        *num_output_ifs_r = num_output_ifs;
    return returned_addrs;

fail:
    for (int i = 0; i < num_output_ifs; i++) {
        free(returned_addrs[i]);
    }
    free(returned_addrs);
    returned_addrs = NULL;
    num_output_ifs = 0;
    goto end;
}

/* Both of these functions could pass 1 as the second argument to include
 * IPv6 addresses, but only when we fully support them by listening on IPv6
 * as well. */
struct sockaddr **
ttt_get_multicast_if_addrs(int *num_ifaces) {
    return get_if_addrs(num_ifaces, 0, 0, 1);
}

struct sockaddr **
ttt_get_broadcast_if_addrs(int *num_ifaces) {
    return get_if_addrs(num_ifaces, 0, 1, 0);
}
#endif

void
ttt_free_addrs(struct sockaddr **addrs, int num_addrs) {
    if (addrs) {
        for (int i = 0; i < num_addrs; i++) {
            free(addrs[i]);
        }
        free(addrs);
    }
}
