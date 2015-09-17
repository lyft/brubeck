#include <string.h>

#include "sput.h"
#include "brubeck.h"

static void try_parse(struct brubeck_statsd_tcp_msg *msg, const char *msg_text, double expected, int expected_len)
{
    char buffer[64];
    size_t len = strlen(msg_text);
    memcpy(buffer, msg_text, len);
    sput_fail_unless(brubeck_statsd_tcp_msg_parse(msg, buffer, len) == expected_len, msg_text);
    sput_fail_unless(expected == msg->value, "msg.value == expected");
}

static void try_parse_and_fail(struct brubeck_statsd_tcp_msg *msg, const char *msg_text, double expected)
{
    char buffer[64];
    size_t len = strlen(msg_text);
    memcpy(buffer, msg_text, len);
    sput_fail_if(brubeck_statsd_tcp_msg_parse(msg, buffer, len) == 0, msg_text);
    sput_fail_unless(expected != msg->value, "msg.value != expected");
}

void test_statsd_tcp_msg__parse_strings(void)
{
    struct brubeck_statsd_tcp_msg msg;

    try_parse(&msg, "github.auth.fingerprint.sha1:1|c\n", 1, 33);
    try_parse(&msg, "github.auth.fingerprint.sha1:1|c|@args\n", 1, 39);
    try_parse(&msg, "github.auth.fingerprint.sha1:1|g\ngithub.auth.fingerprint.sha2", 1, 33);
    try_parse(&msg, "lol:1|ms\n", 1, 9);
    try_parse(&msg, "this.is.sparta:199812|C\n", 199812, 24);
    try_parse(&msg, "this.is.sparta:23.23|g\n", 23.23, 23);
    try_parse(&msg, "this.is.sparta:0012|h\n", 12, 20);    
    try_parse(&msg, "this.is.sparta:0.232030|g\n", 0.23203, 25);
    try_parse_and_fail(&msg, "this.are.some. floats:1234567.89|g", 1234567.89);
    try_parse_and_fail(&msg, "this.are.some", 1234567.89);
}
