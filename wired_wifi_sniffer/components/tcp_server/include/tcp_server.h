#ifndef D7F56C5F_80CF_4C45_ABEB_1E7C086E397D
#define D7F56C5F_80CF_4C45_ABEB_1E7C086E397D
#include "lwip/sockets.h"
#include <stdint.h>

bool onSend(const int sock, void *buffer, size_t len);
typedef void (*on_socket_accept_t)(const int sock, struct sockaddr_in *so_in);

typedef struct
{
	uint16_t port;
	uint16_t keepIdle;
	uint16_t keepInterval;
	uint16_t keepCount;
	on_socket_accept_t on_socket_accept;
} tcp_server_config_t;

void disconnect_socket(int sock);
void start_tcp_server(tcp_server_config_t *tcp_server_config);

#endif /* D7F56C5F_80CF_4C45_ABEB_1E7C086E397D */
