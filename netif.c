#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#ifdef WINDOWS
#include <winsock.h>
#else
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

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
    return get_if_addrs(num_ifaces, IFF_BROADCAST | IFF_UP, 1, 1);
}

void
ttt_free_addrs(struct sockaddr **addrs, int num_addrs) {
    if (addrs) {
        for (int i = 0; i < num_addrs; i++) {
            free(addrs[i]);
        }
        free(addrs);
    }
}
