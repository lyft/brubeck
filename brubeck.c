#include "brubeck.h"
#include "getopt.h"

int main(int argc, char *argv[])
{
	static struct option longopts[] = {
		{ "log", required_argument, NULL, 'l' },
		{ "config", required_argument, NULL, 'c' },
		{ "tcp_mode", no_argument, NULL, 't' },
		{ "version", no_argument, NULL,	'v' },
		{ NULL,  0,  NULL, 0 }
	};

	struct brubeck_server _server;
	const char *config_file = "config.default.json";
	const char *log_file = NULL;

	server_mode_t mode = UDP_MODE;

	int opt;

	while ((opt = getopt_long(argc, argv, ":t:l:c:v", longopts, NULL)) != -1) {
		switch (opt) {
		case 'l': log_file = optarg; break;
		case 'c': config_file = optarg; break;
		case 't': mode = TCP_MODE; break;
		case 'v':
			puts("brubeck " GIT_SHA);
			return 0;

		default:
			printf("Usage: %s [--log LOG_FILE] [--config CONFIG_FILE] [--tcp_mode][--version]", argv[0]);
			return 1;
		}
	}

	initproctitle(argc, argv);
	gh_log_open(log_file);
	brubeck_server_init(&_server, config_file, mode);
	return brubeck_server_run(&_server);
}
