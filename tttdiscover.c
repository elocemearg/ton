#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "tttutils.h"
#include "tttnetif.h"
#include "tttcrypt.h"
#include "tttdiscover.h"
#include "tttsession.h"
#include "tttaccept.h"

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
            ttt_error(0, 0, "validate_datagram: ttt_aes_256_cbc_decrypt() failed");
            return -1;
        }
    }

    if (verbose) {
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

    ctx->multicast_rendezvous_addr = strdup(TTT_MULTICAST_RENDEZVOUS_ADDR);
    ctx->allow_unencrypted = 0;
    ctx->listen_port = TTT_DEFAULT_DISCOVER_PORT;
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
tttdlctx_set_multicast_addr(struct tttdlctx *ctx, const char *addr) {
    char *new_addr = strdup(addr);
    if (new_addr == NULL)
        return -1;
    free(ctx->multicast_rendezvous_addr);
    ctx->multicast_rendezvous_addr = new_addr;
    return 0;
}

void
tttdlctx_destroy(struct tttdlctx *ctx) {
    free(ctx->secret);
    free(ctx->multicast_rendezvous_addr);
}

int
tttdlctx_listen(struct tttdlctx *ctx,
        struct sockaddr_storage *peer_addr_r, int *peer_addr_length_r,
        PORT *invitation_port_r) {
    int rc;
    struct addrinfo hints;
    struct addrinfo *addrinfo = NULL;
    char port_str[20];
    int listener = -1;
    const int one = 1;
    int discovered = 0;
    struct sockaddr **multicast_if_addrs = NULL;
    int num_multicast_if_addrs = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%hu", ctx->listen_port);

    rc = getaddrinfo(NULL, port_str, &hints, &addrinfo);
    if (rc != 0) {
        ttt_error(0, errno, "discover_listen: getaddrinfo");
        goto fail;
    }

    listener = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (listener < 0) {
        ttt_error(0, errno, "discover_listen: socket");
        goto fail;
    }

    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        ttt_error(0, errno, "discover_listen: setsockopt");
        goto fail;
    }

    rc = bind(listener, addrinfo->ai_addr, addrinfo->ai_addrlen);
    if (rc != 0) {
        ttt_error(0, errno, "discover_listen: bind");
        goto fail;
    }

    multicast_if_addrs = ttt_get_multicast_if_addrs(&num_multicast_if_addrs);
    for (int i = 0; i < num_multicast_if_addrs; i++) {
        /* Your ideas are intriguing to me
         * and I wish to subscribe to your newsletter. */
        struct sockaddr *sa = multicast_if_addrs[i];
        if (sa->sa_family == AF_INET) {
            struct ip_mreq group;
            group.imr_multiaddr.s_addr = inet_addr(ctx->multicast_rendezvous_addr);
            group.imr_interface.s_addr = ((struct sockaddr_in *) sa)->sin_addr.s_addr;
            if (setsockopt(listener, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &group, sizeof(group)) != 0) {
                ttt_error(0, errno, "discover_listen: setsockopt IP_ADD_MEMBERSHIP");
                goto fail;
            }
        }
    }

    do {
        char datagram[512];
        struct sockaddr_storage peer_addr;
        socklen_t addr_len = sizeof(peer_addr);
        rc = recvfrom(listener, datagram, sizeof(datagram), 0, (struct sockaddr *) &peer_addr, &addr_len);
        if (rc < 0) {
            ttt_error(0, errno, "discover_listen: recvfrom");
        }
        else {
            struct ttt_discover_result result;
            ttt_dump_hex(datagram, rc, "received datagram");
            if (validate_datagram(datagram, rc, ctx->secret, ctx->secret_length,
                        ctx->allow_unencrypted, 1, &result) == 0) {
                *invitation_port_r = result.invitation_port;
                memcpy(peer_addr_r, &peer_addr, addr_len);
                *peer_addr_length_r = addr_len;
                discovered = 1;
            }
        }
    } while (!discovered);

    if (discovered)
        rc = 0;
    else
        rc = -1;
end:
    if (addrinfo)
        freeaddrinfo(addrinfo);
    if (listener >= 0)
        closesocket(listener);
    ttt_free_addrs(multicast_if_addrs, num_multicast_if_addrs);
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
        ttt_error(0, errno, "discover_announce: getaddrinfo multicast");
        return -1;
    }
    return 0;
}

int
tttdactx_init(struct tttdactx *ctx,
        const char *secret, size_t secret_length) {
    int rc;

    memset(ctx, 0, sizeof(*ctx));

    ctx->multicast_rendezvous_addr = strdup(TTT_MULTICAST_RENDEZVOUS_ADDR);
    ctx->announce_port = TTT_DEFAULT_DISCOVER_PORT;

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
     * has a non-public IP address. */
    ctx->broadcast_if_addrs = ttt_get_broadcast_if_addrs(&ctx->num_broadcast_if_addrs);
    ctx->multicast_if_addrs = ttt_get_multicast_if_addrs(&ctx->num_multicast_if_addrs);
    if (ctx->num_broadcast_if_addrs <= 0 && ctx->num_multicast_if_addrs <= 0) {
        ttt_error(0, 0, "no suitable network interfaces!");
        goto fail;
    }

    if (ctx->num_broadcast_if_addrs < 0)
        ctx->num_broadcast_if_addrs = 0;
    if (ctx->num_multicast_if_addrs < 0)
        ctx->num_multicast_if_addrs = 0;

    ctx->num_sockets = ctx->num_broadcast_if_addrs + ctx->num_multicast_if_addrs;
    ctx->sockets = malloc(sizeof(int) * ctx->num_sockets);
    if (ctx->sockets == NULL) {
        ttt_error(0, errno, "malloc");
        goto fail;
    }
    for (int i = 0; i < ctx->num_sockets; i++) {
        ctx->sockets[i] = -1;
    }

    /* sockets contains num_broadcast_if_addrs sockets to broadcast on,
     * followed by num_multicast_if_addrs sockets to multicast on. */

    for (int i = 0; i < ctx->num_sockets; i++) {
        const int one = 1;
        const int multicast_ttl = 1;
        struct sockaddr *sa = (i < ctx->num_broadcast_if_addrs) ? ctx->broadcast_if_addrs[i] : ctx->multicast_if_addrs[i - ctx->num_broadcast_if_addrs];
        ctx->sockets[i] = socket(sa->sa_family, SOCK_DGRAM, 0);
        if (ctx->sockets[i] < 0) {
            ttt_error(0, errno, "socket");
            goto fail;
        }
        if (i < ctx->num_broadcast_if_addrs) {
            /* Set up this socket for broadcast, and fill in the port number
             * of the struct sockaddr. */
            rc = setsockopt(ctx->sockets[i], SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
            if (rc < 0) {
                ttt_error(0, errno, "discover_announce: setsockopt SO_BROADCAST");
                goto fail;
            }

            if (sa->sa_family == AF_INET) {
                ((struct sockaddr_in *) sa)->sin_port = htons(ctx->announce_port);

            }
            else if (sa->sa_family == AF_INET6) {
                ((struct sockaddr_in6 *) sa)->sin6_port = htons(ctx->announce_port);
            }
        }
        else {
            /* Set up this socket for multicast. */
            /* setsockopt takes only IPv4 in_addr structs, so
             * ttt_get_multicast_if_addrs() only returns IPv4 interfaces */
            struct sockaddr_in *sin;
            assert(sa->sa_family == AF_INET);
            sin = (struct sockaddr_in *) sa;
            rc = setsockopt(ctx->sockets[i], IPPROTO_IP, IP_MULTICAST_IF, &sin->sin_addr, sizeof(sin->sin_addr));
            if (rc != 0) {
                ttt_error(0, errno, "discover_announce: setsockopt IP_MULTICAST_IF");
                goto fail;
            }

            rc = setsockopt(ctx->sockets[i], IPPROTO_IP, IP_MULTICAST_TTL, &multicast_ttl, sizeof(multicast_ttl));
            if (rc != 0) {
                ttt_error(0, errno, "discover_announce: setsockopt IP_MULTICAST_TTL");
                goto fail;
            }
        }
    }

    /* Get an addrinfo for our multicast rendezvous address, which we will be
     * announcing to as well as to any broadcast addresses we find. */
    if (make_dgram_addr_info(ctx->multicast_rendezvous_addr, ctx->announce_port,&ctx->multicast_rendezvous_addrinfo) != 0)
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
    for (int i = 0; i < ctx->num_broadcast_if_addrs; ++i) {
        struct sockaddr *sa = ctx->broadcast_if_addrs[i];
        if (sa->sa_family == AF_INET) {
            ((struct sockaddr_in *) sa)->sin_port = htons(ctx->announce_port);

        }
        else if (sa->sa_family == AF_INET6) {
            ((struct sockaddr_in6 *) sa)->sin6_port = htons(ctx->announce_port);
        }
    }

    /* Change the port number in the multicast destination address... */
    if (make_dgram_addr_info(ctx->multicast_rendezvous_addr, ctx->announce_port, &addrinfo) == 0) {
        freeaddrinfo(ctx->multicast_rendezvous_addrinfo);
        ctx->multicast_rendezvous_addrinfo = addrinfo;
    }
}

int
tttdactx_set_multicast_addr(struct tttdactx *ctx, const char *addr) {
    char *new_addr = strdup(addr);
    if (new_addr == NULL)
        return -1;
    free(ctx->multicast_rendezvous_addr);
    ctx->multicast_rendezvous_addr = new_addr;
    return 0;
}

void
tttdactx_set_multicast_ttl(struct tttdactx *ctx, int ttl) {
    for (int i = ctx->num_broadcast_if_addrs; i < ctx->num_sockets; i++) {
        int rc = setsockopt(ctx->sockets[i], IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        if (rc != 0) {
            ttt_error(0, errno, "discover_announce: setsockopt IP_MULTICAST_TTL");
        }
    }
}

void
tttdactx_destroy(struct tttdactx *ctx) {
    free(ctx->multicast_rendezvous_addr);
    free(ctx->secret);
    if (ctx->sockets) {
        for (int i = 0; i < ctx->num_sockets; i++) {
            if (ctx->sockets[i] >= 0)
                closesocket(ctx->sockets[i]);
        }
        free(ctx->sockets);
    }
    if (ctx->multicast_rendezvous_addrinfo != NULL) {
        freeaddrinfo(ctx->multicast_rendezvous_addrinfo);
    }
    ttt_free_addrs(ctx->broadcast_if_addrs, ctx->num_broadcast_if_addrs);
    ttt_free_addrs(ctx->multicast_if_addrs, ctx->num_multicast_if_addrs);
}

int
tttdactx_announce(struct tttdactx *ctx, PORT invitation_port) {
    int num_sockets_failed = 0;
    char datagram[262];
    int datagram_length;

    datagram_length = make_announce_datagram(datagram, sizeof(datagram),
            ctx->secret, ctx->secret_length, TTT_ENC_AES_256_CBC,
            invitation_port);
    if (datagram_length < 0) {
        ttt_error(0, errno, "discover_announce: failed to build datagram");
        goto fail;
    }

    for (int si = 0; si < ctx->num_sockets; si++) {
        ssize_t bytes_sent;
        struct sockaddr *sa;
        int sa_len;
        if (si < ctx->num_broadcast_if_addrs) {
            sa = ctx->broadcast_if_addrs[si];
            if (sa->sa_family == AF_INET)
                sa_len = sizeof(struct sockaddr_in);
            else if (sa->sa_family == AF_INET6)
                sa_len = sizeof(struct sockaddr_in6);
            else
                continue;
        }
        else {
            sa = ctx->multicast_rendezvous_addrinfo->ai_addr;
            sa_len = ctx->multicast_rendezvous_addrinfo->ai_addrlen;
        }

        bytes_sent = sendto(ctx->sockets[si], datagram, datagram_length, 0, sa, sa_len);
        if (bytes_sent < 0) {
            ttt_error(0, errno, "discover_announce: sendto");
            num_sockets_failed++;
        }
        else if (bytes_sent < datagram_length) {
            ttt_error(0, 0, "discover_announce: expected to send %d bytes but only sent %d", datagram_length, (int) bytes_sent);
            num_sockets_failed++;
        }
    }

    /* Return -1 (failure) if we failed to send on all sockets. */
    return -(num_sockets_failed == ctx->num_sockets);

fail:
    return -1;
}


int
ttt_discover_and_connect(const char *multicast_address, int discover_port,
        const char *passphrase, size_t passphrase_length, int verbose,
        struct ttt_session *new_sess) {
    struct tttdlctx ctx;
    int ctx_valid = 0;
    struct sockaddr_storage peer_addr;
    int peer_addr_len = sizeof(peer_addr);
    PORT peer_invitation_port;
    char peer_addr_str[100];
    char peer_port_str[30];
    const int use_tls = 1;
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

    if (multicast_address) {
        tttdlctx_set_multicast_addr(&ctx, multicast_address);
    }

    /* Listen until we receive a valid UDP datagram which was encrypted
     * with our secret. This datagram, when decrypted, tells us which
     * port to make a TCP connection to. */
    rc = tttdlctx_listen(&ctx, &peer_addr, &peer_addr_len, &peer_invitation_port);
    if (rc != 0) {
        ttt_error(0, 0, "discover_listen failed.");
        goto fail;
    }

    if (verbose) {
        /* Look up who sent us a valid announcement and report to the user. */
        rc = getnameinfo((struct sockaddr *) &peer_addr, sizeof(peer_addr),
                peer_addr_str, sizeof(peer_addr_str),
                peer_port_str, sizeof(peer_port_str),
                NI_NUMERICHOST | NI_NUMERICSERV);
        if (rc != 0) {
            ttt_error(0, 0, "getnameinfo: %s", gai_strerror(rc));
        }
        else {
            fprintf(stderr, "Discovered: %s port %s, invitation port %hu\n", peer_addr_str, peer_port_str, peer_invitation_port);
        }
    }
    tttdlctx_destroy(&ctx);
    ctx_valid = 0;

    /* Connect to the host that sent us the valid announcement on
     * the port it specified, and send a message. */
    ttt_session_set_key(passphrase, passphrase_length);
    ttt_sockaddr_set_port((struct sockaddr *) &peer_addr, peer_invitation_port);
    if (ttt_session_connect(new_sess, (struct sockaddr *) &peer_addr, peer_addr_len, use_tls) < 0) {
        ttt_error(0, 0, "failed to connect");
        goto fail;
    }
    else if (ttt_session_handshake(new_sess) != 0) {
        /* This socket is blocking, so ttt_session_handshake will either block
         * and succeed, or fail permanently. It won't fail with want_read or
         * want_write. */
        ttt_error(0, 0, "handshake failed");
        ttt_session_destroy(new_sess);
        goto fail;
    }

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
ttt_discover_and_accept(const char *multicast_address, int discover_port,
        int max_announcements, int announcement_interval_ms, int multicast_ttl,
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
    PORT invitation_port = 0;
    int new_sess_valid = 0;
    int rc;
    int num_failed_announcements = 0, max_failed_announcements = 10;

    /* Initialise a "discovery announce" context, where we will send
     * UDP datagrams, encrypted with the passphrase, which contain among
     * other things the port number we're inviting the other owner of
     * this passphrase to connect to. */
    memset(&dactx, 0, sizeof(dactx));
    memset(&acctx, 0, sizeof(acctx));
    if (tttdactx_init(&dactx, passphrase, passphrase_length) != 0) {
        ttt_error(0, 0, "failed to initialise announce context");
        goto fail;
    }
    dactx_valid = 1;

    /* Open our listening TCP socket on the invitation port. */
    if (tttacctx_init(&acctx, NULL, invitation_port, use_tls) < 0) {
        ttt_error(0, 0, "failed to initialise connection accept context");
        goto fail;
    }
    acctx_valid = 1;

    invitation_port = tttacctx_get_listen_port(&acctx);

    /* Set TTL, if required. This affects our outgoing announcement
     * datagrams. */
    if (multicast_ttl > 1) {
        tttdactx_set_multicast_ttl(&dactx, multicast_ttl);
    }

    /* Set the multicast address and discovery port if required, but usually
     * these are expected to stay as their defaults. */
    if (multicast_address) {
        tttdactx_set_multicast_addr(&dactx, multicast_address);
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
        rc = tttdactx_announce(&dactx, invitation_port);
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
