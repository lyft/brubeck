#ifndef __BRUBECK_STATSD_TCP_H__
#define __BRUBECK_STATSD_TCP_H__


#include <openssl/hmac.h>
#include "bloom.h"

#define MAX_LINE 16384
#define CONNECTION_BACKLOG 16
#define MIN_READ_WATERMARK 10
#define MAX_READ_WATERMARK  4096

/* Socket read and write timeouts, in seconds. */
#define SOCKET_READ_TIMEOUT_SECONDS 10
#define SOCKET_WRITE_TIMEOUT_SECONDS 10

#define SHA_SIZE 32
#define SHA_FUNCTION EVP_sha256

struct brubeck_statsd_tcp_msg {
    char *key;      /* The key of the message, NULL terminated */
    uint16_t key_len; /* length of the key */
    uint16_t type;  /* type of the t, as a brubeck_mt_t */
    value_t value;  /* integer value of the message */
    char *trail;    /* Any data following the 'key:value|type' construct, NULL terminated*/
    uint16_t trail_len; /* The length of the trailing string */
};

typedef struct brubeck_statsd_client_connection {
    int fd;
    struct event_base *evbase;
    struct bufferevent *buf_ev;
    struct evbuffer *input_buffer;
} brubeck_client_t;
 

struct brubeck_statsd_tcp {
    struct brubeck_sampler sampler;
    pthread_t *workers;

    unsigned int worker_count;
    unsigned int mmsg_count;

    /* The event_base for this client. */
    struct event_base *evbase;
    evutil_socket_t fd;
};

struct brubeck_statsd_secure_tcp {
    struct brubeck_sampler sampler;
    const char *hmac_key;

    /** tcp/udp mode of the server **/
    sampler_mode_t mode;

    struct multibloom *replays;
    time_t now;
    time_t drift;

    pthread_t thread;

    /* The event_base for this client. */
    struct event_base *evbase;
    evutil_socket_t fd;

    HMAC_CTX ctx;
};

typedef struct brubeck_statsd_client_connection brubeck_client_t;


int brubeck_statsd_tcp_msg_parse(struct brubeck_statsd_tcp_msg *msg, char *buffer, size_t length);

struct brubeck_sampler * brubeck_statsd_secure_tcp_new(struct brubeck_server *server, json_t *settings);
struct brubeck_sampler *brubeck_statsd_tcp_new(struct brubeck_server *server, json_t *settings);

#endif

