#include <stddef.h>
#define _GNU_SOURCE
#include <sys/uio.h>
#include <sys/socket.h>
#include "brubeck.h"

#ifdef __GLIBC__
#   if ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
#       define HAVE_RECVMMSG 1
#   endif
#endif

#define MAX_PACKET_SIZE 512

#define MAX_LINE 16384
#define CONNECTION_BACKLOG 16
#define MIN_READ_WATERMARK 10
/* Socket read and write timeouts, in seconds. */
#define SOCKET_READ_TIMEOUT_SECONDS 10
#define SOCKET_WRITE_TIMEOUT_SECONDS 10

#define errorOut(...) {\
    log_splunk("%s:%d: %s():\t", __FILE__, __LINE__, __FUNCTION__);\
    log_splunk(__VA_ARGS__);\
}

#ifdef HAVE_RECVMMSG
static void statsd_run_recvmmsg(struct brubeck_statsd *statsd, int sock)
{
    /**
      * TODO: Implement Me!!
      */
}
#endif

static void
statsd_tcp_run_recvmsg(struct brubeck_statsd *statsd, int sock)
{
    /**
      * TODO: Implement me!
      */
}

int
brubeck_statsd_tcp_msg_parse(struct brubeck_statsd_tcp_msg *msg, char *buffer, size_t length)
{
    /**
      * TODO: Implement me!
      */
}

static void
*statsd__thread(void *_in)
{
    /**
      * TODO: Implement me!
      */
      return NULL;
}

static void
run_worker_threads(struct brubeck_statsd *statsd)
{
    /**
      * TODO: Implement me!
      */
}

static void
shutdown_sampler(struct brubeck_sampler *sampler)
{
    /**
      * TODO: Implement me!
      */
    log_splunk("shutdown_sampler")
    struct brubeck_statsd_tcp *stats_tcp = (struct brubeck_statsd_tcp *)sampler;
    event_base_loopexit(stats_tcp->evbase, NULL);
}


static void
read_cb(struct bufferevent *bev, void *ctx)
{
        struct evbuffer_info *info = ctx;
        log_splunk("data is ready");
        /* This callback is invoked when there is data to read on bev. */
        struct evbuffer *input = bufferevent_get_input(bev);
        struct evbuffer *output = bufferevent_get_output(bev);

        size_t len = evbuffer_get_length(input);
        log_splunk("Number of bytes available %zd\n", len);
        if (len) {
            info->total_drained += len;
            evbuffer_drain(input, len);
            log_splunk("Drained %lu bytes from %s\n", (unsigned long) len, info->name);
        }        

        /* Copy all the data from the input buffer to the output buffer. */
        evbuffer_add_buffer(output, input);
}

static void
event_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct evbuffer_info *info = ctx;
    struct evbuffer *input = bufferevent_get_input(bev);
    int finished = 0;

    if (events & BEV_EVENT_CONNECTED) {
        log_splunk("Client connected...");
    }

    if (events & BEV_EVENT_EOF) {
        size_t len = evbuffer_get_length(input);
        log_splunk("Got a close from %s.  We drained %lu bytes from it, "
            "and have %lu left.\n", info->name,
            (unsigned long)info->total_drained, (unsigned long)len);
        finished = 1;
    }
    
    if (events & BEV_EVENT_ERROR) {
        int err = bufferevent_socket_get_dns_error(bev);
        if (err)
            log_splunk("DNS error: %s\n", evutil_gai_strerror(err));        
        
        log_splunk("Got an error from %s: %s\n",
            info->name, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        finished = 1;
    }

    if (finished) {
        free(ctx);
        bufferevent_free(bev);
    }
}

static void
accept_conn_cb(struct evconnlistener *listener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *ctx)
{
        log_splunk("Got a new connection ")
        /* We got a new connection! Set up a bufferevent for it. */
        struct event_base *base = evconnlistener_get_base(listener);
        struct bufferevent *bev = bufferevent_socket_new(
                base, fd, BEV_OPT_CLOSE_ON_FREE);

        struct evbuffer_info *info = malloc(sizeof(struct evbuffer_info));
        info->name = "read buffer";
        info->total_drained = 0;

        /* Trigger the read callback only whenever there is at least 10 bytes
        of data in the buffer. */
        bufferevent_setwatermark(bev, EV_READ, MIN_READ_WATERMARK, 0);

        bufferevent_setcb(bev, read_cb, NULL, event_cb, info);
        bufferevent_settimeout(bev, SOCKET_READ_TIMEOUT_SECONDS, SOCKET_WRITE_TIMEOUT_SECONDS);

        bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void
accept_error_cb(struct evconnlistener *listener, void *ctx)
{
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_splunk("Got an error %d (%s) on the listener. "
                "Shutting down.\n", err, evutil_socket_error_to_string(err));

        event_base_loopexit(base, NULL);
}

struct brubeck_sampler *
brubeck_statsd_tcp_new(struct brubeck_server *server, json_t *settings)
{
    struct brubeck_statsd_tcp *std = xmalloc(sizeof(struct brubeck_statsd_tcp));

    char *address;
    int port;
    int multisock = 0;

    struct event_base *base;
    struct evconnlistener *listener;

    std->sampler.type = BRUBECK_SAMPLER_STATSD;
    std->sampler.mode = TCP;
    std->sampler.shutdown = &shutdown_sampler;
    std->sampler.in_sock = -1;
    std->worker_count = 4;
    std->mmsg_count = 1;

    json_unpack_or_die(settings,
        "{s:s, s:i, s?:i, s?:i, s?:b}",
        "address", &address,
        "port", &port,
        "workers", &std->worker_count,
        "multimsg", &std->mmsg_count,
        "multisock", &multisock);

    base = event_base_new();
    assert(base != NULL);

    brubeck_sampler_init_inet(&std->sampler, server, NULL, port);

    listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
        (struct sockaddr*)&std->sampler.addr, sizeof(std->sampler.addr));

    if (!listener) {
        log_splunk("Unable to create listener");
        assert(listener);
    }
    evconnlistener_set_error_cb(listener, accept_error_cb);

    event_base_dispatch(base);

    std->evbase = base;

    //run_worker_threads(std);
    return &std->sampler;
}




