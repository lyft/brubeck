#ifndef __BRUBECK_STATSD_TCP_H__
#define __BRUBECK_STATSD_TCP_H__

#include "bloom.h"

struct brubeck_statsd_tcp_msg {
    char *key;      /* The key of the message, NULL terminated */
    uint16_t key_len; /* length of the key */
    uint16_t type;  /* type of the t, as a brubeck_mt_t */
    value_t value;  /* integer value of the message */
    char *trail;    /* Any data following the 'key:value|type' construct, NULL terminated*/
};

struct brubeck_statsd_tcp {
    struct brubeck_sampler sampler;
    pthread_t *workers;

    unsigned int worker_count;
    unsigned int mmsg_count;

    /* The event_base for this client. */
    struct event_base *evbase;
};

struct evbuffer_info {
    const char *name;
    size_t total_drained;
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
};

int brubeck_statsd_tcp_msg_parse(struct brubeck_statsd_tcp_msg *msg, char *buffer, size_t length);

struct brubeck_sampler * brubeck_statsd_secure_tcp_new(struct brubeck_server *server, json_t *settings);
struct brubeck_sampler *brubeck_statsd_tcp_new(struct brubeck_server *server, json_t *settings);

#endif

