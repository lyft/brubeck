#include <stddef.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include "brubeck.h"

#ifdef __GLIBC__
#   if ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
#       define HAVE_RECVMMSG 1
#   endif
#endif

#define MAX_LINE 16384
#define CONNECTION_BACKLOG 16
#define MIN_READ_WATERMARK 10
#define MAX_READ_WATERMARK  4096
#define SOCKET_READ_TIMEOUT_SECONDS 10
#define SOCKET_WRITE_TIMEOUT_SECONDS 10


#define error_out(...) {\
    log_splunk("%s:%d: %s():\t", __FILE__, __LINE__, __FUNCTION__);\
    log_splunk(__VA_ARGS__);\
}

int
brubeck_statsd_tcp_msg_parse(struct brubeck_statsd_tcp_msg *msg, char *buffer, size_t length)
{
    char *end = buffer + length;
    int total = 1;

    char *start;
    *end = '\0';

    /**
     * Message key: all the string until the first ':'
     *
     *      gaugor:333|g
     *      ^^^^^^
     */

    {
        msg->key = buffer;
        msg->key_len = 0;
        while (*buffer != ':' && *buffer != '\0') {
            /* Invalid metric, can't have a space */
            if (*buffer == ' ')
                return -1;
            
            ++buffer;
            ++total;
        }
        if (*buffer == '\0')
            return -1;

        msg->key_len = buffer - msg->key;
        *buffer++ = '\0';
        total++;

        /* Corrupted metric. Graphite won't swallow this */
        if (msg->key[msg->key_len - 1] == '.')
            return -1;
    }

    /**
     * Message value: the numeric value between ':' and '|'.
     * This is already converted to an integer.
     *
     *      gaugor:333|g
     *             ^^^
     */
    {
        int negative = 0;
        start = buffer;

        msg->value = 0.0;

        if (*buffer == '-') {
            ++total;
            ++buffer;
            negative = 1;
        }

        while (*buffer >= '0' && *buffer <= '9') {
            msg->value = (msg->value * 10.0) + (*buffer - '0');
            if (msg->value != 0.0) {
                ++total;
            }
            ++buffer;
        }


        if (*buffer == '.') {
            double f = 0.0, n = 0.0;
            ++buffer;
            ++total;

            while (*buffer >= '0' && *buffer <= '9') {
                f = (f * 10.0) + (*buffer - '0');
                ++buffer;
                ++total;
                n += 1.0;
            }

            msg->value += f / pow(10.0, n);
        }

        if (negative)
            msg->value = -msg->value;

        if (unlikely(*buffer == 'e')) {
            msg->value = strtod(start, &buffer);
        }

        if (*buffer != '|')
            return -1;

        buffer++;
        total++;
    }

    /**
     * Message type: one or two char identifier with the
     * message type. Valid values: g, c, C, h, ms
     *
     *      gaugor:333|g
     *                 ^
     */
    {
        switch (*buffer) {
            case 'g': msg->type = BRUBECK_MT_GAUGE; break;
            case 'c': msg->type = BRUBECK_MT_METER; break;
            case 'C': msg->type = BRUBECK_MT_COUNTER; break;
            case 'h': msg->type = BRUBECK_MT_HISTO; break;
            case 'm':
                      ++buffer;
                      ++total;
                      if (*buffer == 's') {
                          msg->type = BRUBECK_MT_TIMER;
                          break;
                      }

            default:
                      return -1;
        }
    }

    /**
     * Trailing bytes: data appended at the end of the message.
     * This is stored verbatim and will be parsed when processing
     * the specific message type. This is optional.
     *
     *      gorets:1|c|@0.1
     *                 ^^^^----
     */
    {
        buffer++;

        if (buffer[0] == '\n') {
            total++;
            msg->trail = NULL;
            return total;
        }
            
        if (*buffer == '@' || *buffer == '|') {
            msg->trail = buffer;

            char *ptr = buffer;
            while (*ptr++) {
                total++;
                if (*ptr == '\n') {
                    msg->trail_len = strlen(msg->trail) - 1;
                    msg->trail = (char *)malloc(sizeof(char) * msg->trail_len);
                    strncpy(msg->trail, (char *)buffer, msg->trail_len);
                    msg->trail[msg->trail_len] = '\0';
                    return ++total;
                }
            }
            /**
              * Incomplete message
              * wait for the next batch
              */
            return 0;
        }
        return -1;
    }
}

static void
read_cb(struct bufferevent *bev, void *ctx)
{
        int successfully_parsed = 0;
        char *buffer;
        struct brubeck_statsd_tcp *statsd;
        struct brubeck_server *server;

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

            log_splunk("sampler=statsd_tcp event=bad_key key='%.*s'",
                (int)strlen(buffer), buffer);

            brubeck_server_mark_dropped(server);
        } else {
            /**
              * Successfully parsed a single metric
              */
            brubeck_atomic_inc(&server->stats.metrics);
            brubeck_atomic_inc(&statsd->sampler.inflow);

            // Drain the successfully parsed
            if (evbuffer_drain(input, successfully_parsed) < 0) {
                error_out("Couldn't drain the buffer successfully :(");
                die("Stopping the thread.");
            }

            log_splunk("sampler=statsd_tcp event=parsed key=%s key len bytes=%d", msg.key, msg.key_len);
            log_splunk("sampler=statsd_tcp msg=Drained %d bytes from it, "
                "and have %zd left.\n", successfully_parsed, evbuffer_get_length(input));
        }
}

static void
event_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct brubeck_statsd_tcp *statsd = ctx;

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
accept_conn_cb(struct evconnlistener *listener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *ctx)
{
        struct brubeck_statsd_tcp *statsd = (struct brubeck_statsd_tcp *)ctx;
        log_splunk("Got a new connection for server");

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

        /* Trigger the read callback only whenever there is at least 10 bytes
        of data in the buffer. */
        bufferevent_setwatermark(bev, EV_READ, 0, MAX_READ_WATERMARK);

        bufferevent_setcb(bev, read_cb, NULL, event_cb, statsd);
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

static void
*statsd__thread(void *_in)
{
    struct brubeck_statsd_tcp *statsd = _in;
    struct event_base *base;
    struct evconnlistener *listener;

    base = event_base_new();
    assert(base != NULL);

    listener = evconnlistener_new_bind(base, accept_conn_cb, statsd,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 16,
        (struct sockaddr*)&statsd->sampler.addr, sizeof(statsd->sampler.addr));

    if (!listener) {
        die("Unable to create listener");
    }
    evconnlistener_set_error_cb(listener, accept_error_cb);

    event_base_dispatch(base);
    return NULL;
}

static void
run_worker_threads(struct brubeck_statsd_tcp *statsd)
{
    unsigned int i;
    statsd->workers = xmalloc(statsd->worker_count * sizeof(pthread_t));
    for (i = 0; i < statsd->worker_count; ++i) {
        if (pthread_create(&statsd->workers[i], NULL, &statsd__thread, statsd) != 0)
            die("failed to start sampler thread");
    }
}

static void
shutdown_sampler(struct brubeck_sampler *sampler)
{
    struct brubeck_statsd_tcp *statsd = (struct brubeck_statsd_tcp *)sampler;
    size_t i;

    for (i = 0; i < statsd->worker_count; ++i) {
        pthread_cancel(statsd->workers[i]);
    }
}

struct brubeck_sampler *
brubeck_statsd_tcp_new(struct brubeck_server *server, json_t *settings)
{
    struct brubeck_statsd_tcp *std = malloc(sizeof(struct brubeck_statsd_tcp));
    char *address = NULL;
    int port;

    /** Initialize **/
    event_init();

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
        "multimsg", &std->mmsg_count);

    /**
      * Set the server 
      */

    brubeck_sampler_init_inet(&std->sampler, server, address, port);

    std->sampler.server = server;

    run_worker_threads(std);
    return &std->sampler;
}
