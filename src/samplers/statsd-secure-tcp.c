#include <stddef.h>
#include <time.h>
#include "brubeck.h"

#define MAX_READ_WATERMARK  4096

#define error_out(...) {\
    log_splunk("%s:%d: %s():\t", __FILE__, __LINE__, __FUNCTION__);\
    log_splunk(__VA_ARGS__);\
}

static int
memcmpct(const void *_a, const void *_b, size_t len)
{
    const unsigned char *a = _a;
    const unsigned char *b = _b;
    size_t i;
    int cmp = 0;

    for (i = 0; i < len; ++i)
        cmp |= a[i] ^ b[i];

    return cmp;
}

static const char *
hmactos(const char *buffer)
{
    static const char hex_str[] = "0123456789abcdef";
    static __thread char hex_hmac[SHA_SIZE * 2 + 1];

    unsigned int i, j;

    for (i = 0, j = 0; i < SHA_SIZE; i++) {
        hex_hmac[j++] = hex_str[buffer[i] >> 4];
        hex_hmac[j++] = hex_str[buffer[i] & 0xF];
    }

    hex_hmac[j] = 0;

    return hex_hmac;
}

static int
verify_token(struct brubeck_server *server, struct brubeck_statsd_secure_tcp *statsd, const char *buffer)
{
    uint32_t ha, hb;
    uint64_t timestamp;
    struct timespec now;

    memcpy(&timestamp, buffer + SHA_SIZE, 8);
    clock_gettime(CLOCK_REALTIME, &now);

    if (now.tv_sec != statsd->now) {
        statsd->now = now.tv_sec;
        multibloom_reset(statsd->replays, statsd->now % statsd->drift);
    }

    /* token from the future? */
    if (statsd->now < timestamp) {
        log_splunk(
                "sampler=statsd-tcp-ecure event=fail_future now=%llu timestamp=%llu",
                (long long unsigned int)statsd->now,
                (long long unsigned int)timestamp
        );
        brubeck_atomic_inc(&server->stats.secure.from_future);
        return -1;
    }

    /* delayed */
    if (statsd->now - timestamp > statsd->drift) {
        log_splunk(
                "sampler=statsd-tcp-secure event=fail_delayed now=%llu timestamp=%llu drift=%d",
                (long long unsigned int)statsd->now,
                (long long unsigned int)timestamp,
                (int)(statsd->now - timestamp)
        );
        brubeck_atomic_inc(&server->stats.secure.delayed);
        return -1;
    }

    memcpy(&ha, buffer, sizeof(ha));
    memcpy(&hb, buffer + 4, sizeof(hb));

    if (multibloom_check(statsd->replays, timestamp % statsd->drift, ha, hb)) {
        log_splunk("sampler=statsd-tcp-secure event=fail_replayed hmac=%s", hmactos(buffer));
        brubeck_atomic_inc(&server->stats.secure.replayed);
        return -1;
    }

    return 0;
}

static void
read_cb(struct bufferevent *bev, void *ctx)
{
        int successfully_parsed = 0;
        char *buffer;
        struct brubeck_statsd_secure_tcp *statsd;
        struct brubeck_server *server;
        struct brubeck_metric *metric;
        unsigned char hmac_buffer[SHA_SIZE];
        unsigned int hmac_len;

        struct brubeck_statsd_tcp_msg msg;

        /* This callback is invoked when there is data to read on bev. */
        struct evbuffer *input = bufferevent_get_input(bev);
        
        statsd = ctx;
        server = statsd->sampler.server;

        buffer= (char *)evbuffer_pullup(input, -1);

        /**
          *  Parse the input bytes, drain the successfully parsed bytes
          *  return parsed bytes count.
          *  1. Pass the buffer to statsd and parse IOTA's 
          *  2. Return  the number of bytes "successfully" parsed
          *  3. Drain "successfully" parsed bytes
          *  4. Return.
          */          
        successfully_parsed = brubeck_statsd_tcp_msg_parse(&msg, buffer, strlen(buffer));
        if (successfully_parsed <= 0) {
            if (msg.key_len > 0)
                buffer[msg.key_len] = ':';

            log_splunk("sampler=statsd_secure_tcp event=bad_key key='%.*s'",
                (int)strlen(buffer), buffer);

            log_splunk_errno("sampler=statsd-secure event=failed_read from socket");
            brubeck_server_mark_dropped(server);
        } else {
            /**
              * Extract part of the buffer
              * parsed successfully.
              */
            char *parsed_str = (char *) malloc(sizeof(char) * (successfully_parsed + 1));
            strncpy(parsed_str, buffer, successfully_parsed);
            *(parsed_str + successfully_parsed) = '\0';

            puts(parsed_str);

            if (verify_token(server, statsd, parsed_str) < 0) {
                error_out("Bad token, skipping %s", parsed_str);
                evbuffer_drain(input, successfully_parsed + 1);
                return;
            }

            if (memcmpct(parsed_str, hmac_buffer, SHA_SIZE) != 0) {
                log_splunk("sampler=statsd-secure event=fail_auth hmac=%s", hmactos(parsed_str));
                brubeck_atomic_inc(&server->stats.secure.failed);
                evbuffer_drain(input, successfully_parsed + 1);
                return;
            }

            /**
              * Successfully parsed a single metric
              */
            brubeck_atomic_inc(&server->stats.metrics);
            brubeck_atomic_inc(&statsd->sampler.inflow);

            // Reject the newline charecter too
            evbuffer_drain(input, successfully_parsed + 1);

            HMAC_Init_ex(&statsd->ctx, NULL, 0, NULL, NULL);
            HMAC_Update(&statsd->ctx, (unsigned char *)parsed_str + SHA_SIZE, strlen(parsed_str) - SHA_SIZE);
            HMAC_Final(&statsd->ctx, hmac_buffer, &hmac_len);

            metric = brubeck_metric_find(server, msg.key, msg.key_len, msg.type);
            if (metric != NULL)
                brubeck_metric_record(metric, msg.value);
        }
}

static void
event_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct brubeck_statsd_secure_tcp *statsd = ctx;

    struct evbuffer *input = bufferevent_get_input(bev);
    int finished = 0;

    if (events & BEV_EVENT_CONNECTED) {
        log_splunk("Client connected...");
    }

    if (events & BEV_EVENT_EOF) {
        size_t len = evbuffer_get_length(input);
        error_out("Got a close from client.  We drained x bytes from it, "
            "and have %lu left.\n", (unsigned long)len);
        finished = 1;
    }
    
    if (events & BEV_EVENT_ERROR) {
        int err = bufferevent_socket_get_dns_error(bev);
        if (err)
            error_out("DNS error: %s\n", evutil_gai_strerror(err));
        
        error_out("Got an error from client: %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        finished = 1;
    }

    if (finished) {
        bufferevent_free(bev);
        brubeck_server_mark_dropped(statsd->sampler.server);
    }
}

static void
accept_secure_conn_cb(struct evconnlistener *listener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *ctx)
{
        struct brubeck_statsd_secure_tcp *statsd = (struct brubeck_statsd_secure_tcp *)ctx;
        log_splunk("Got a new connection for server");

        HMAC_CTX_init(&statsd->ctx);
        HMAC_Init_ex(&statsd->ctx, statsd->hmac_key, strlen(statsd->hmac_key), SHA_FUNCTION(), NULL);

        /* We got a new connection! Set up a bufferevent for it. */
        struct event_base *base = evconnlistener_get_base(listener);
        struct bufferevent *bev = bufferevent_socket_new(
                base, fd, BEV_OPT_CLOSE_ON_FREE);

        /**
          * Cache FD and Base pointers 
          * for future needs
          */
        if (statsd != NULL) {
            statsd->evbase = base;
            statsd->fd = fd;
        }

        log_splunk("sampler=statsd-tcp-secure event=worker_online");

        /* Trigger the read callback only whenever there is at least 10 bytes
        of data in the buffer. */
        bufferevent_setwatermark(bev, EV_READ, MIN_READ_WATERMARK, MAX_READ_WATERMARK);

        bufferevent_setcb(bev, read_cb, NULL, event_cb, statsd);
        bufferevent_settimeout(bev, SOCKET_READ_TIMEOUT_SECONDS, SOCKET_WRITE_TIMEOUT_SECONDS);

        bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void
accept_secure_error_cb(struct evconnlistener *listener, void *ctx)
{
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_splunk("Got an error %d (%s) on the listener. "
                "Shutting down.\n", err, evutil_socket_error_to_string(err));

        event_base_loopexit(base, NULL);
}

static void *statsd_secure__thread(void *_in)
{
    struct brubeck_statsd *statsd = _in;
    struct event_base *base;
    struct evconnlistener *listener;

    base = event_base_new();
    assert(base != NULL);

    listener = evconnlistener_new_bind(base, accept_secure_conn_cb, statsd,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
        (struct sockaddr*)&statsd->sampler.addr, sizeof(statsd->sampler.addr));

    if (!listener) {
        log_splunk("Unable to create listener");
        assert(listener);
    }
    evconnlistener_set_error_cb(listener, accept_secure_error_cb);

    event_base_dispatch(base);
    return NULL;
}

static void shutdown_sampler(struct brubeck_sampler *sampler)
{
    struct brubeck_statsd_secure_tcp *statsd = (struct brubeck_statsd_secure_tcp *)sampler;
    pthread_cancel(statsd->thread);
}

struct brubeck_sampler *
brubeck_statsd_secure_tcp_new(struct brubeck_server *server, json_t *settings)
{    
    struct brubeck_statsd_secure_tcp *std = xmalloc(sizeof(struct brubeck_statsd_secure_tcp));
    char *address;
    struct sockaddr_in addr;
    int port, replay_len;

    std->sampler.shutdown = &shutdown_sampler;
    std->sampler.type = BRUBECK_SAMPLER_STATSD_SECURE;
    std->sampler.mode = TCP;
    std->now = 0;

    json_unpack_or_die(settings,
        "{s:s, s:i, s:s, s:i, s:i}",
        "address", &address,
        "port", &port,
        "hmac_key", &std->hmac_key,
        "max_drift", &std->drift,
        "replay_len", &replay_len);

    std->replays = multibloom_new(std->drift, replay_len, 0.001);
    std->sampler.in_sock = -1;

    /**
      * Set the server 
      */
    std->sampler.server = server;

    addr.sin_family = AF_INET;
    /* Listen on 0.0.0.0 */
    addr.sin_addr.s_addr = 0;
    addr.sin_port = htons(port);

    std->sampler.addr = addr;

    log_splunk("sampler=%s event=load_secure_%s addr=0.0.0.0:%d",
        brubeck_sampler_name(&(std->sampler)), brubeck_sampler_mode(&(std->sampler)), port);

    if (pthread_create(&std->thread, NULL, &statsd_secure__thread, std) != 0)
        die("failed to start sampler thread");

    return (struct brubeck_sampler *)std;
}
