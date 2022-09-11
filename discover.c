#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include <sys/types.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "utils.h"
#include "netif.h"
#include "encryption.h"
#include "discover.h"
#include "session.h"
#include "accept.h"

/* Magic number of discovery datagram: "TTT1" */
#define TTT_DISCOVER_MAGIC 0x54545431UL

/* Magic number of encrypted part of discovery datagram, once decrypted:
 * "ttt1" */
#define TTT_DISCOVER_MAGIC2 0x74747431UL

#define TTT_ENC_PLAIN 0 /* not permitted by default */
#define TTT_ENC_AES_256_CBC 1

#define DISCOVER_TIMESTAMP_TOLERANCE_SEC 300

#define DISCOVER_RD_OFFSET_MAGIC 0
#define DISCOVER_RD_OFFSET_ENC 4
#define DISCOVER_RD_OFFSET_PLEN 7
#define DISCOVER_RD_OFFSET_PAYLOAD 8
/* Raw datagram data is as follows. All integers are in network byte order.
 * A valid TTT datagram is no more than 263 bytes.
 *
 * Position  Type      Description
 * 0-3       uint32    Magic number 0x54545431
 * 4-5       uint16    Encryption type.
 *                       0 = no encryption.
 *                       1 = AES-256-CBC.
 * 6         uint8     Reserved. Announcers must set this to 0.
 * 7         uint8     Payload length in bytes. Maximum length 255.
 * 8+        byte[payload_length]
 *                     Encrypted payload.
 */

#define DISCOVER_P_OFFSET_MAGIC 0
#define DISCOVER_P_OFFSET_CRC 4
#define DISCOVER_P_OFFSET_CRC_DATA_START 8
#define DISCOVER_P_OFFSET_RANDOM 8
#define DISCOVER_P_OFFSET_TIMESTAMP 24
#define DISCOVER_P_OFFSET_INV_PORT 28
#define DISCOVER_P_LENGTH 30
/* Unencrypted payload is as follows. All integers are in network byte
 * order.
 *
 * Position  Type      Description
 * 0-3       uint32    Magic number 0x54545432
 * 4-7       uint32    CRC32 of payload bytes 8 to (plaintext payload length-1) inclusive.
 * 8-23      byte[16]  16 random bytes generated by sender.
 * 24-27     uint32    Lower 32 bits of Unix timestamp, to protect against
 *                       replay attacks.
 * 28-29     uint16    Invitation port number.
 * 30+                 Reserved for future expansion
 *
 * The encrypted payload may be up to 255 bytes long. If there are any bytes
 * after byte position 29 they should be ignored. This area may be used in
 * later versions.
 */

struct ttt_discover_result {
    uint32_t magic;
    PORT invitation_port;
};

static uint32_t
uint32_ntoh(const char *buf, int offset) {
    return ntohl(*(const uint32_t *)(buf + offset));
}

static uint16_t
uint16_ntoh(const char *buf, int offset) {
    return ntohs(*(const uint16_t *)(buf + offset));
}

static void
uint32_hton(char *buf, int offset, uint32_t value) {
    value = htonl(value);
    memcpy(buf + offset, &value, sizeof(value));
}

static void
uint16_hton(char *buf, int offset, uint16_t value) {
    value = htons(value);
    memcpy(buf + offset, &value, sizeof(value));
}

static uint32_t
crc32(const char *data, size_t length) {
    static uint32_t crc32_table[256] = {0};
    static int crc32_table_generated = 0;
    uint32_t checksum = 0xFFFFFFFFU;

    if (!crc32_table_generated) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t ch = i;
            uint32_t crc = 0;
            for (int j = 0; j < 8; j++) {
                uint32_t b = (ch ^ crc) & 1;
                crc >>= 1;
                if (b)
                    crc ^= 0xEDB88320;
                ch >>= 1;
            }
            crc32_table[i] = crc;
        }
        crc32_table_generated = 1;
    }

    for (size_t i = 0; i < length; i++) {
        const uint32_t b = (checksum ^ data[i]) & 0xff;
        checksum = (checksum >> 8) ^ crc32_table[b];
    }
    return checksum ^ 0xFFFFFFFFU;
}

static int
validate_datagram(void *datagram, int datagram_length, const char *secret,
        size_t secret_length, int allow_unencrypted, int verbose,
        struct ttt_discover_result *result) {
    unsigned long magic;
    unsigned long crc32_exp, crc32_obs;
    unsigned short enc;
    unsigned short enc_payload_length;
    unsigned short inv_port;
    unsigned long datagram_timestamp, ts_diff;
    int payload_length;
    time_t now;
    char *enc_payload_start;
    char payload[256];

    if (datagram_length < 8 || datagram_length > 263) {
        if (verbose)
            ttt_error(0, 0, "validate_datagram: invalid length %d", datagram_length);
        return -1;
    }

    magic = uint32_ntoh(datagram, DISCOVER_RD_OFFSET_MAGIC);
    enc = uint16_ntoh(datagram, DISCOVER_RD_OFFSET_ENC);
    enc_payload_length = uint16_ntoh(datagram, DISCOVER_RD_OFFSET_PLEN - 1) & 0xff;
    enc_payload_start = ((char *) datagram) + DISCOVER_RD_OFFSET_PAYLOAD;

    if (magic != TTT_DISCOVER_MAGIC) {
        if (verbose)
            ttt_error(0, 0, "validate_datagram: first magic number incorrect (expected 0x%08lx, observed 0x%08lx)", TTT_DISCOVER_MAGIC, magic);
        return -1;
    }

    if (enc != 0 && enc != 1) {
        if (verbose)
            ttt_error(0, 0, "validate_datagram: invalid encryption type %hu", enc);
        return -1;
    }

    if (enc == 0) {
        if (!allow_unencrypted) {
            if (verbose)
                ttt_error(0, 0, "validate_datagram: datagram is not encrypted, rejecting it.");
            return -1;
        }
        memcpy(payload, enc_payload_start, enc_payload_length);
        payload_length = enc_payload_length;
    }
    else {
        payload_length = ttt_aes_256_cbc_decrypt(enc_payload_start, enc_payload_length, payload, sizeof(payload), secret, secret_length);
        if (payload_length < 0) {
            if (verbose)
                ttt_error(0, 0, "validate_datagram: announcement not encrypted with expected passphrase");
            return -1;
        }
    }

    if (verbose > 1) {
        ttt_dump_hex(payload, payload_length, "decrypted payload");
    }

    magic = uint32_ntoh(payload, DISCOVER_P_OFFSET_MAGIC);
    crc32_exp = uint32_ntoh(payload, DISCOVER_P_OFFSET_CRC);

    if (magic != TTT_DISCOVER_MAGIC2) {
        if (verbose)
            ttt_error(0, 0, "validate_datagram: second magic number incorrect (expected 0x%08lx, observed 0x%08lx)", TTT_DISCOVER_MAGIC2, magic);
        return -1;
    }

    crc32_obs = crc32(payload + DISCOVER_P_OFFSET_CRC_DATA_START, payload_length - DISCOVER_P_OFFSET_CRC_DATA_START);
    if (crc32_obs != crc32_exp) {
        if (verbose)
            ttt_error(0, 0, "validate_datagram: CRC32 incorrect (expected 0x%08lx, calculated 0x%08lx)", crc32_exp, crc32_obs);
        return -1;
    }

    datagram_timestamp = uint32_ntoh(payload, DISCOVER_P_OFFSET_TIMESTAMP);
    now = time(NULL);
    ts_diff = (unsigned long) (now & 0xFFFFFFFF) - datagram_timestamp;
    if (abs((int32_t)ts_diff) > DISCOVER_TIMESTAMP_TOLERANCE_SEC) {
        if (verbose)
            ttt_error(0, 0, "validate_datagram: timestamp out of date, difference %d seconds", abs((int32_t) ts_diff));
        return -1;
    }

    inv_port = uint16_ntoh(payload, DISCOVER_P_OFFSET_INV_PORT);

    result->magic = magic;
    result->invitation_port = inv_port;

    return 0;
}

static int
make_announce_datagram(char *dest, int dest_max, const char *secret,
        size_t secret_length, int enc_type, PORT invitation_port) {
    char plain[256];
    int plain_payload_length;
    int encrypted_payload_length;

    uint32_hton(dest, DISCOVER_RD_OFFSET_MAGIC, TTT_DISCOVER_MAGIC);
    uint16_hton(dest, DISCOVER_RD_OFFSET_ENC, enc_type);

    memset(plain, 0, sizeof(plain));
    uint32_hton(plain, DISCOVER_P_OFFSET_MAGIC, TTT_DISCOVER_MAGIC2);
    ttt_set_random_bytes(plain + DISCOVER_P_OFFSET_RANDOM, 16);
    uint32_hton(plain, DISCOVER_P_OFFSET_TIMESTAMP, (uint32_t) (time(NULL) & 0xFFFFFFFF));
    uint16_hton(plain, DISCOVER_P_OFFSET_INV_PORT, invitation_port);

    plain_payload_length = DISCOVER_P_LENGTH;

    uint32_hton(plain, DISCOVER_P_OFFSET_CRC, crc32(plain + DISCOVER_P_OFFSET_CRC_DATA_START, plain_payload_length - DISCOVER_P_OFFSET_CRC_DATA_START));

    if (enc_type == TTT_ENC_PLAIN) {
        if (dest_max < DISCOVER_RD_OFFSET_PAYLOAD + plain_payload_length) {
            ttt_error(0, 0, "make_announce_datagram: dest_max is too small (%d < %d)", dest_max, DISCOVER_RD_OFFSET_PAYLOAD + plain_payload_length);
            return -1;
        }
        memcpy(dest + DISCOVER_RD_OFFSET_PAYLOAD, plain, plain_payload_length);
        encrypted_payload_length = plain_payload_length;
    }
    else if (enc_type == TTT_ENC_AES_256_CBC) {
        encrypted_payload_length = ttt_aes_256_cbc_encrypt(plain,
                plain_payload_length, dest + DISCOVER_RD_OFFSET_PAYLOAD,
                dest_max - DISCOVER_RD_OFFSET_PAYLOAD, secret, secret_length);
        if (encrypted_payload_length < 0) {
            ttt_error(0, 0, "make_announce_datagram: ttt_aes_256_cbc_encrypt() failed");
            return -1;
        }
    }
    else {
        ttt_error(0, 0, "make_announce_datagram: unrecognised enc_type %d", enc_type);
        return -1;
    }

    uint16_hton(dest, 6, encrypted_payload_length);
    return 8 + encrypted_payload_length;
}

static void
sockaddr_set_port(struct sockaddr *sa, PORT port) {
    if (sa->sa_family == AF_INET) {
        ((struct sockaddr_in *) sa)->sin_port = htons(port);
    }
    else if (sa->sa_family == AF_INET6) {
        ((struct sockaddr_in6 *) sa)->sin6_port = htons(port);
    }
}

int
make_multicast_receiver(int address_family, const char *multicast_addr_str, PORT port) {
    struct addrinfo hints;
    struct addrinfo *addrinfo = NULL;
    char port_str[20];
    int listener = -1;
    int rc;
#ifdef WINDOWS
    const BOOL one = 1;
#else
    const int one = 1;
#endif

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%hu", port);

    rc = getaddrinfo(NULL, port_str, &hints, &addrinfo);
    if (rc != 0) {
        ttt_error(0, 0, "make_multicast_receiver: getaddrinfo: %s", gai_strerror(rc));
        goto fail;
    }

    /* Create a socket and bind it to the given port, so we receive any
     * datagrams sent to us on that port. */
    listener = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (listener < 0) {
        ttt_socket_error(0, "make_multicast_receiver: socket");
        goto fail;
    }

    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof(one)) != 0) {
        ttt_socket_error(0, "make_multicast_receiver: setsockopt SO_REUSEADDR");
        goto fail;
    }

    if (address_family == AF_INET6) {
        /* Make this an IPv6-only socket, so we can bind to the same port
         * with an IPv4 socket. */
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, (const char *) &one, sizeof(one)) != 0) {
            ttt_socket_error(0, "make_multicast_receiver: setsockopt IPV6_V6ONLY");
        }
    }

    rc = bind(listener, addrinfo->ai_addr, addrinfo->ai_addrlen);
    if (rc != 0) {
        ttt_socket_error(0, "make_multicast_receiver: bind");
        goto fail;
    }

    rc = multicast_interfaces_subscribe(listener, multicast_addr_str);
    if (rc <= 0) {
        ttt_socket_error(0, "failed to join multicast group %s on any interface", multicast_addr_str);
        goto fail;
    }

end:
    if (addrinfo)
        freeaddrinfo(addrinfo);

    return listener;

fail:
    if (listener >= 0) {
        closesocket(listener);
    }
    listener = -1;
    goto end;
}


int
tttdlctx_init(struct tttdlctx *ctx,
        const char *secret, size_t secret_length) {
    memset(ctx, 0, sizeof(*ctx));
    if (secret_length > 0) {
        ctx->secret = malloc(secret_length);
        if (ctx->secret == NULL)
            goto fail;
        memcpy(ctx->secret, secret, secret_length);
        ctx->secret_length = secret_length;
    }

    ctx->multicast_rendezvous_addr4 = strdup(TTT_MULTICAST_RENDEZVOUS_ADDR);
    ctx->multicast_rendezvous_addr6 = strdup(TTT_MULTICAST_RENDEZVOUS_ADDR_IPv6);
    ctx->allow_unencrypted = 0;
    ctx->listen_port = TTT_DEFAULT_DISCOVER_PORT;
    ctx->listening_cb = NULL;
    ctx->listening_cb_cookie = NULL;
    ctx->announcement_cb = NULL;
    ctx->announcement_cb_cookie = NULL;
    ctx->verbose = 0;
    ctx->address_families = TTT_IP_BOTH;

    return 0;

fail:
    tttdlctx_destroy(ctx);
    return -1;
}

void
tttdlctx_set_port(struct tttdlctx *ctx, PORT port) {
    ctx->listen_port = port;
}

int
tttdlctx_set_multicast_addr(struct tttdlctx *ctx, const char *addr, int ipv6) {
    char *new_addr = strdup(addr);
    if (new_addr == NULL)
        return -1;
    if (ipv6) {
        free(ctx->multicast_rendezvous_addr6);
        ctx->multicast_rendezvous_addr6 = new_addr;
    }
    else {
        free(ctx->multicast_rendezvous_addr4);
        ctx->multicast_rendezvous_addr4 = new_addr;
    }
    return 0;
}

void
tttdlctx_destroy(struct tttdlctx *ctx) {
    free(ctx->secret);
    free(ctx->multicast_rendezvous_addr4);
    free(ctx->multicast_rendezvous_addr6);
}

void
tttdlctx_set_listening_callback(struct tttdlctx *ctx, tttdl_listening_cb listening_cb) {
    ctx->listening_cb = listening_cb;
}

void
tttdlctx_set_listening_callback_cookie(struct tttdlctx *ctx, void *cookie) {
    ctx->listening_cb_cookie = cookie;
}

void
tttdlctx_set_announcement_callback(struct tttdlctx *ctx, tttdl_announcement_cb announcement_cb) {
    ctx->announcement_cb = announcement_cb;
}

void
tttdlctx_set_announcement_callback_cookie(struct tttdlctx *ctx, void *cookie) {
    ctx->announcement_cb_cookie = cookie;
}

void
tttdlctx_set_verbose(struct tttdlctx *ctx, int value) {
    ctx->verbose = value;
}

void
tttdlctx_set_address_families(struct tttdlctx *ctx, int address_families) {
    ctx->address_families = address_families;
}

int
tttdlctx_listen(struct tttdlctx *ctx,
        struct sockaddr_storage *peer_addr_r, int *peer_addr_length_r,
        PORT *invitation_port_r) {
    int rc;
    int listener4 = -1, listener6 = -1;
    int discovered = 0;
    int sockets[2];

    if (ctx->address_families & TTT_IPV4) {
        listener4 = make_multicast_receiver(AF_INET, ctx->multicast_rendezvous_addr4, ctx->listen_port);
        if (listener4 < 0) {
            goto fail;
        }
    }

    if (ctx->address_families & TTT_IPV6) {
        listener6 = make_multicast_receiver(AF_INET6, ctx->multicast_rendezvous_addr6, ctx->listen_port);
        if (listener6 < 0) {
            goto fail;
        }
    }

    if (ctx->listening_cb) {
        /* Call the callback to say that we set everything up correctly and
         * we're now listening for announcements via UDP */
        ctx->listening_cb(ctx->listening_cb_cookie);
    }

    sockets[0] = listener4;
    sockets[1] = listener6;

    do {
        int maxfd = -1;
        fd_set readfds;

        /* Wait for messages on both the IPv4 and IPv6 socket */
        FD_ZERO(&readfds);
        for (int i = 0; i < 2; i++) {
            if (sockets[i] >= 0) {
                FD_SET(sockets[i], &readfds);
                if (sockets[i] > maxfd)
                    maxfd = sockets[i];
            }
        }
        rc = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (rc < 0) {
            ttt_socket_error(0, "discover_listen: select");
            break;
        }

        /* Something happened, check on each socket */
        for (int i = 0; !discovered && i < 2; i++) {
            char datagram[512];
            struct sockaddr_storage peer_addr;
            socklen_t addr_len = sizeof(peer_addr);
            int listener = sockets[i];

            if (listener < 0 || !FD_ISSET(listener, &readfds)) {
                continue;
            }

            rc = recvfrom(listener, datagram, sizeof(datagram), 0, (struct sockaddr *) &peer_addr, &addr_len);
            if (rc < 0) {
                ttt_socket_error(0, "discover_listen: recvfrom");
            }
            else {
                struct ttt_discover_result result;
                //ttt_dump_hex(datagram, rc, "received datagram");
                if (validate_datagram(datagram, rc, ctx->secret, ctx->secret_length,
                            ctx->allow_unencrypted, ctx->verbose, &result) == 0) {
                    *invitation_port_r = result.invitation_port;
                    memcpy(peer_addr_r, &peer_addr, addr_len);
                    *peer_addr_length_r = addr_len;
                    discovered = 1;
                }
                if (ctx->announcement_cb != NULL) {
                    /* Inform our caller that we got a valid or invalid
                     * announcement... */
                    ctx->announcement_cb(ctx->announcement_cb_cookie,
                            (const struct sockaddr *) &peer_addr,
                            addr_len, discovered,
                            discovered ? result.invitation_port : 0);
                }
            }
        }
    } while (!discovered);

    if (discovered)
        rc = 0;
    else
        rc = -1;

end:
    if (listener4 >= 0) {
        multicast_interfaces_unsubscribe(listener4, ctx->multicast_rendezvous_addr4);
        closesocket(listener4);
    }
    if (listener6 >= 0) {
        multicast_interfaces_unsubscribe(listener6, ctx->multicast_rendezvous_addr6);
        closesocket(listener6);
    }
    return rc;

fail:
    rc = -1;
    goto end;
}

static int
make_dgram_addr_info(const char *multicast_rendezvous_addr, PORT announce_port, struct addrinfo **res) {
    struct addrinfo hints;
    char port_str[20];
    int rc;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(port_str, sizeof(port_str), "%hu", announce_port);
    rc = getaddrinfo(multicast_rendezvous_addr, port_str, &hints, res);
    if (rc != 0) {
        ttt_error(0, 0, "discover_announce: getaddrinfo multicast: %s", gai_strerror(rc));
        return -1;
    }
    return 0;
}

int
tttdactx_init(struct tttdactx *ctx, int address_families, int address_types,
        const char *secret, size_t secret_length) {
    int rc;
    int num_valid_sockets = 0;
#ifdef WINDOWS
    const BOOL one = 1;
#else
    const int one = 1;
#endif

    memset(ctx, 0, sizeof(*ctx));

    ctx->multicast_rendezvous_addr4 = strdup(TTT_MULTICAST_RENDEZVOUS_ADDR);
    ctx->multicast_rendezvous_addr6 = strdup(TTT_MULTICAST_RENDEZVOUS_ADDR_IPv6);
    ctx->announce_port = TTT_DEFAULT_DISCOVER_PORT;
    ctx->address_families = address_families;
    ctx->address_types = address_types;

    if (secret_length > 0) {
        ctx->secret = malloc(secret_length);
        if (ctx->secret == NULL)
            goto fail;
        ctx->secret_length = secret_length;
        memcpy(ctx->secret, secret, secret_length);
    }

    /* To maximise the chance of our announcement reaching our peer, we want
     * to try a broadcast packet on every interface on which we can broadcast,
     * and a multicast packet on every interface that supports multicast and
     * has a non-public IP address. The flags in address_types can inhibit
     * either of these. */

    if (address_types & TTT_ANNOUNCE_BROADCAST) {
        errno = 0;
        ctx->broadcast_ifs = ttt_get_broadcast_ifs(address_families);
        if (ctx->broadcast_ifs == NULL && errno != 0) {
            ttt_error(0, errno, "failed to get list of broadcast-enabled interfaces");
        }
    }

    if (address_types & TTT_ANNOUNCE_MULTICAST) {
        errno = 0;
        ctx->multicast_ifs = ttt_get_multicast_ifs(address_families);
        if (ctx->multicast_ifs == NULL && errno != 0) {
            ttt_error(0, errno, "failed to get list of multicast-enabled interfaces");
        }
    }

    /* If we have no suitable interfaces, bail out early rather than failing
     * to announce loads of times... */
    if (ctx->multicast_ifs == NULL && ctx->broadcast_ifs == NULL) {
        ttt_error(0, 0, "no suitable network interfaces found for announcement");
        goto fail;
    }

    /* Initialise sockets to send broadcast packets on... */
    for (struct ttt_netif *iface = ctx->broadcast_ifs; iface; iface = iface->next) {
        if (iface->bc_valid) {
            iface->sock = socket(iface->family, SOCK_DGRAM, 0);
            if (iface->sock < 0) {
                ttt_socket_error(0, "socket");
                goto fail;
            }
            rc = setsockopt(iface->sock, SOL_SOCKET, SO_BROADCAST, (const char *) &one, sizeof(one));
            if (rc < 0) {
                ttt_socket_error(0, "discover_announce: setsockopt SO_BROADCAST");
                goto fail;
            }
            sockaddr_set_port((struct sockaddr *) &iface->bc_addr, ctx->announce_port);
        }
        if (iface->sock >= 0) {
            num_valid_sockets++;
        }
    }

    /* ... and initialise sockets to send multicast packets on. */
    for (struct ttt_netif *iface = ctx->multicast_ifs; iface; iface = iface->next) {
        iface->sock = socket(iface->family, SOCK_DGRAM, 0);
        if (iface->sock < 0) {
            ttt_socket_error(0, "socket");
            goto fail;
        }

        if (iface->family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&iface->if_addr;
            rc = setsockopt(iface->sock, IPPROTO_IP, IP_MULTICAST_IF, (const char *) &sin->sin_addr, sizeof(sin->sin_addr));
            if (rc != 0) {
                /* Failed to enable this socket for multicast traffic,
                 * perhaps because it's a localhost or link-local address.
                 * This isn't a fatal error unless there are no more
                 * sockets. */
                closesocket(iface->sock);
                iface->sock = -1;
            }
        }
        else if (iface->family == AF_INET6) {
            rc = setsockopt(iface->sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char *) &iface->if_index_ipv6, sizeof(iface->if_index_ipv6));
            if (rc != 0) {
                //ttt_socket_error(0, "failed to enable IPv6 socket for multicast traffic");
                closesocket(iface->sock);
                iface->sock = -1;
            }
        }
        if (iface->sock >= 0) {
            num_valid_sockets++;
        }
    }

    if (num_valid_sockets == 0) {
        ttt_socket_error(0, "no suitable network interfaces found for announcement. Last socket error was");
    }

    /* Get an addrinfo for our multicast rendezvous address, which we will be
     * announcing to as well as to any broadcast addresses we find. */
    if (make_dgram_addr_info(ctx->multicast_rendezvous_addr4, ctx->announce_port, &ctx->multicast_rendezvous_addrinfo4) != 0)
        goto fail;
    if (make_dgram_addr_info(ctx->multicast_rendezvous_addr6, ctx->announce_port, &ctx->multicast_rendezvous_addrinfo6) != 0)
        goto fail;

    return 0;

fail:
    tttdactx_destroy(ctx);
    return -1;
}

void
tttdactx_set_port(struct tttdactx *ctx, PORT port) {
    struct addrinfo *addrinfo;

    ctx->announce_port = port;

    /* Change the port number in the broadcast address structs... */
    for (struct ttt_netif *iface = ctx->broadcast_ifs; iface; iface = iface->next) {
        sockaddr_set_port((struct sockaddr *) &iface->bc_addr, ctx->announce_port);
    }

    /* Change the port number in the multicast destination address... */
    if (make_dgram_addr_info(ctx->multicast_rendezvous_addr4, ctx->announce_port, &addrinfo) == 0) {
        freeaddrinfo(ctx->multicast_rendezvous_addrinfo4);
        ctx->multicast_rendezvous_addrinfo4 = addrinfo;
    }
    if (make_dgram_addr_info(ctx->multicast_rendezvous_addr6, ctx->announce_port, &addrinfo) == 0) {
        freeaddrinfo(ctx->multicast_rendezvous_addrinfo6);
        ctx->multicast_rendezvous_addrinfo6 = addrinfo;
    }
}

int
tttdactx_set_multicast_addr(struct tttdactx *ctx, const char *addr, int ipv6) {
    char *new_addr = strdup(addr);
    if (new_addr == NULL)
        return -1;
    if (ipv6) {
        free(ctx->multicast_rendezvous_addr6);
        ctx->multicast_rendezvous_addr6 = new_addr;
    }
    else {
        free(ctx->multicast_rendezvous_addr4);
        ctx->multicast_rendezvous_addr4 = new_addr;
    }
    return 0;
}

void
tttdactx_set_multicast_ttl(struct tttdactx *ctx, int ttl) {
    for (struct ttt_netif *iface = ctx->multicast_ifs; iface; iface = iface->next) {
        if (iface->sock >= 0) {
            int rc = setsockopt(iface->sock,
                    iface->family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP,
                    iface->family == AF_INET6 ? IPV6_MULTICAST_HOPS : IP_MULTICAST_TTL,
                    (const char *) &ttl, sizeof(ttl));
            if (rc != 0) {
                ttt_socket_error(0, "discover_announce: setsockopt IP_MULTICAST_TTL");
            }
        }
    }
}

void
tttdactx_set_invitation_port(struct tttdactx *ctx, int sa_family, PORT port) {
    if (sa_family == AF_INET)
        ctx->invitation_port4 = port;
    else if (sa_family == AF_INET6)
        ctx->invitation_port6 = port;
}

void
tttdactx_destroy(struct tttdactx *ctx) {
    free(ctx->multicast_rendezvous_addr4);
    free(ctx->multicast_rendezvous_addr6);
    free(ctx->secret);
    if (ctx->multicast_rendezvous_addrinfo4 != NULL) {
        freeaddrinfo(ctx->multicast_rendezvous_addrinfo4);
    }
    if (ctx->multicast_rendezvous_addrinfo6 != NULL) {
        freeaddrinfo(ctx->multicast_rendezvous_addrinfo6);
    }
    ttt_netif_list_free(ctx->broadcast_ifs, 1);
    ttt_netif_list_free(ctx->multicast_ifs, 1);
}

int
tttdactx_announce(struct tttdactx *ctx) {
    int num_sockets_succeeded = 0;
    int addr_families[2] = { AF_INET, AF_INET6 };
    PORT invitation_ports[2] = { ctx->invitation_port4, ctx->invitation_port6 };

    for (int af = 0; af < 2; ++af) {
        int addr_family = addr_families[af];
        PORT invitation_port = invitation_ports[af];
        char datagram[262];
        int datagram_length;

        if (invitation_port == 0)
            continue;

        datagram_length = make_announce_datagram(datagram, sizeof(datagram),
                ctx->secret, ctx->secret_length, TTT_ENC_AES_256_CBC,
                invitation_port);
        if (datagram_length < 0) {
            ttt_error(0, errno, "discover_announce: failed to build datagram");
            return -1;
        }

        /* Go through the list of broadcast-enabled interfaces, and the list of
         * multicast-enabled interfaces, and send an announcement datagram on
         * the socket we've opened for each of them. */
        for (int type = 0; type < 2; ++type) {
            struct ttt_netif *list = (type == 0 ? ctx->broadcast_ifs : ctx->multicast_ifs);

            if (list == ctx->broadcast_ifs && (ctx->address_types & TTT_ANNOUNCE_BROADCAST) == 0)
                continue;
            if (list == ctx->multicast_ifs && (ctx->address_types & TTT_ANNOUNCE_MULTICAST) == 0)
                continue;

            for (struct ttt_netif *iface = list; iface; iface = iface->next) {
                ssize_t bytes_sent;
                struct sockaddr *sa;
                int sa_len;

                /* Skip sockets which failed setup in some way */
                if (iface->sock < 0) {
                    continue;
                }

                /* Make sure this socket corresponds with the address family
                 * we're using on this iteration of the outer loop */
                if (addr_family != iface->family) {
                    continue;
                }

                if (type == 0) {
                    /* Send to broadcast address */
                    sa = (struct sockaddr *) &iface->bc_addr;
                    sa_len = iface->bc_addr_len;
                }
                else {
                    /* Send to our IPv4 or IPv6 multicast rendezvous address */
                    if (iface->family == AF_INET) {
                        sa = ctx->multicast_rendezvous_addrinfo4->ai_addr;
                        sa_len = ctx->multicast_rendezvous_addrinfo4->ai_addrlen;
                    }
                    else if (iface->family == AF_INET6) {
                        sa = ctx->multicast_rendezvous_addrinfo6->ai_addr;
                        sa_len = ctx->multicast_rendezvous_addrinfo6->ai_addrlen;
                    }
                    else {
                        assert(0);
                    }
                }

                bytes_sent = sendto(iface->sock, datagram, datagram_length, 0, sa, sa_len);
                if (bytes_sent < 0) {
                    ttt_socket_error(0, "discover_announce: sendto");
                }
                else if (bytes_sent < datagram_length) {
                    ttt_error(0, 0, "discover_announce: expected to send %d bytes but only sent %d", datagram_length, (int) bytes_sent);
                }
                else {
                    num_sockets_succeeded++;
                }
            }
        }
    }

    /* Return -1 (failure) if every attempt to send failed. */
    return num_sockets_succeeded == 0 ? -1 : 0;
}

int
ttt_discover_and_connect(const char *multicast_address_ipv4,
        const char *multicast_address_ipv6, int address_families,
        int discover_port, const char *passphrase, size_t passphrase_length,
        int verbose,
        tttdl_listening_cb listening_cb, void *listening_callback_cookie,
        tttdl_announcement_cb announcement_cb, void *announcement_callback_cookie,
        struct ttt_session *new_sess) {
    struct tttdlctx ctx;
    int ctx_valid = 0;
    struct sockaddr_storage peer_addr;
    int peer_addr_len = sizeof(peer_addr);
    PORT peer_invitation_port;
    const int use_tls = 1;
    int handshake_completed = 0;
    int rc;

    /* Initialise a discovery listen context */
    memset(&ctx, 0, sizeof(ctx));
    if (tttdlctx_init(&ctx, passphrase, passphrase_length) != 0) {
        ttt_error(0, 0, "failed to initialise listen context");
        return -1;
    }
    ctx_valid = 1;

    /* Listen for UDP announcement datagrams on a well-known port */
    if (discover_port > 0) {
        tttdlctx_set_port(&ctx, discover_port);
    }

    /* If we're using any multicast addresses other than the defaults, set
     * them now. */
    if (multicast_address_ipv4) {
        tttdlctx_set_multicast_addr(&ctx, multicast_address_ipv4, 0);
    }
    if (multicast_address_ipv6) {
        tttdlctx_set_multicast_addr(&ctx, multicast_address_ipv6, 1);
    }

    /* Set up callbacks in the tttdlctx */
    tttdlctx_set_listening_callback(&ctx, listening_cb);
    tttdlctx_set_listening_callback_cookie(&ctx, listening_callback_cookie);
    tttdlctx_set_announcement_callback(&ctx, announcement_cb);
    tttdlctx_set_announcement_callback_cookie(&ctx, announcement_callback_cookie);
    tttdlctx_set_verbose(&ctx, verbose);
    tttdlctx_set_address_families(&ctx, address_families);

    do {
        /* Listen until we receive a valid UDP datagram which was encrypted
         * with our secret. This datagram, when decrypted, tells us which
         * port to make a TCP connection to. */
        rc = tttdlctx_listen(&ctx, &peer_addr, &peer_addr_len, &peer_invitation_port);
        if (rc != 0) {
            ttt_error(0, 0, "discover_listen failed.");
            goto fail;
        }

        /* Only call the listening callback once */
        tttdlctx_set_listening_callback(&ctx, NULL);

        /* Connect to the host that sent us the valid announcement on
         * the port it specified, and send a message. */
        ttt_session_set_key(passphrase, passphrase_length);
        ttt_sockaddr_set_port((struct sockaddr *) &peer_addr, peer_invitation_port);
        if (ttt_session_connect(new_sess, (struct sockaddr *) &peer_addr, peer_addr_len, use_tls) < 0) {
            ttt_error(0, 0, "failed to connect");
        }
        else if (ttt_session_handshake(new_sess) != 0) {
            /* This socket is blocking, so ttt_session_handshake will either
             * block and succeed, or fail permanently. It won't fail with
             * want_read or want_write. */
            ttt_error(0, 0, "handshake failed");
            ttt_session_destroy(new_sess);
        }
        else {
            handshake_completed = 1;
        }

        /* If we couldn't connect or couldn't handshake with the host who
         * announced to us, go round and listen for announcements again. */
    } while (!handshake_completed);

    tttdlctx_destroy(&ctx);
    ctx_valid = 0;

    /* If we get here, we have discovered our peer and successfully established
     * a TCP connection, encrypted and authenticated using the passphrase. */
    return 0;

fail:
    if (ctx_valid) {
        tttdlctx_destroy(&ctx);
    }
    return -1;
}

int
ttt_discover_and_accept(const char *multicast_address_ipv4,
        const char *multicast_address_ipv6, int address_families,
        int address_types, int discover_port, int max_announcements,
        int announcement_interval_ms, int multicast_ttl,
        const char *passphrase, size_t passphrase_length, int verbose,
        struct ttt_session *new_sess) {
    struct tttdactx dactx;
    int dactx_valid = 0;
    struct tttacctx acctx;
    int acctx_valid = 0;
    int announcement;
    char peer_addr_str[100];
    char peer_addr_port[30];
    const int use_tls = 1;
    PORT invitation_port4 = 0, invitation_port6 = 0;
    int new_sess_valid = 0;
    int rc;
    int num_failed_announcements = 0, max_failed_announcements = 10;

    /* Initialise a "discovery announce" context, where we will send
     * UDP datagrams, encrypted with the passphrase, which contain among
     * other things the port number we're inviting the other owner of
     * this passphrase to connect to. */
    memset(&dactx, 0, sizeof(dactx));
    memset(&acctx, 0, sizeof(acctx));
    if (tttdactx_init(&dactx, address_families, address_types, passphrase, passphrase_length) != 0) {
        ttt_error(0, 0, "failed to initialise announce context");
        goto fail;
    }
    dactx_valid = 1;

    /* Open our listening TCP socket on the invitation port. */
    if (tttacctx_init(&acctx, multicast_address_ipv4, multicast_address_ipv6, address_families, 0, use_tls) < 0) {
        ttt_error(0, 0, "failed to initialise connection accept context");
        goto fail;
    }
    acctx_valid = 1;

    invitation_port4 = tttacctx_get_listen_port(&acctx, AF_INET);
    invitation_port6 = tttacctx_get_listen_port(&acctx, AF_INET6);

    tttdactx_set_invitation_port(&dactx, AF_INET, invitation_port4);
    tttdactx_set_invitation_port(&dactx, AF_INET6, invitation_port6);

    /* Set TTL, if required. This affects our outgoing announcement
     * datagrams. */
    if (multicast_ttl != 0) {
        tttdactx_set_multicast_ttl(&dactx, multicast_ttl);
    }

    /* Set the multicast address and discovery port if required, but usually
     * these are expected to stay as their defaults. */
    if (multicast_address_ipv4) {
        tttdactx_set_multicast_addr(&dactx, multicast_address_ipv4, 0);
    }
    if (multicast_address_ipv6) {
        tttdactx_set_multicast_addr(&dactx, multicast_address_ipv6, 1);
    }

    if (discover_port > 0) {
        tttdactx_set_port(&dactx, discover_port);
    }

    /* Set the secret passphrase we're going to use for our session.
     * This will be used in the TLS handshake we do with any incoming
     * connection, and the other end of it should have the same passphrase.
     */
    ttt_session_set_key(passphrase, passphrase_length);

    /* Send a number of announcements, with a suitable time gap in between.
     * Each announcement is a UDP datagram sent to a broadcast and/or
     * multicast address, so anything on the same network which is looking
     * for it should see it.
     * We keep sending announcements until we reach the limit
     * (num_announcements) or until we receive a connection on our TCP
     * listening socket which successfully completes a handshake proving
     * it has the right passphrase.
     */
    for (announcement = 0; max_announcements == 0 || announcement < max_announcements; announcement++) {
        if (announcement > 0) {
            /* Listen for incoming connections on our TCP socket. If
             * announcement_gap_ms milliseconds go by with nobody connecting to
             * us and completing a handshake, time out and make another UDP
             * announcement. */
            rc = tttacctx_accept(&acctx, announcement_interval_ms, new_sess);
            if (rc < 0) {
                ttt_error(0, 0, "fatal error waiting for incoming connection");
                goto fail;
            }
            else if (rc == 0) {
                /* timeout */
            }
            else {
                /* Success! new_sess now contains a session which connected to
                 * the correct port and successfully handshook with us. */
                new_sess_valid = 1;
                if (verbose) {
                    if (ttt_session_get_peer_addr(new_sess, peer_addr_str, sizeof(peer_addr_str), peer_addr_port, sizeof(peer_addr_port)) == 0) {
                        fprintf(stderr, "Accepted connection from %s:%s\n", peer_addr_str, peer_addr_port);
                    }
                }
                break;
            }
        }

        /* No successful incoming connection yet, so send out another
         * broadcast/multicast announcement inviting anyone who decrypts
         * it to connect to us. */
        rc = tttdactx_announce(&dactx);
        if (rc != 0) {
            ttt_error(0, 0, "discover_announce failed.");
            num_failed_announcements++;
            if (num_failed_announcements > max_failed_announcements) {
                 break;
            }
        }
    }

end:
    if (dactx_valid)
        tttdactx_destroy(&dactx);
    if (acctx_valid)
        tttacctx_destroy(&acctx);

    if (new_sess_valid)
        return 0;
    else
        return -1;

fail:
    if (new_sess_valid) {
        ttt_session_destroy(new_sess);
        new_sess_valid = 0;
    }
    goto end;
}
