#ifndef MAIN_CONFIG_HTTP_SERVER_H_
#define MAIN_CONFIG_HTTP_SERVER_H_

typedef struct config_http_server_prm{
	char rootdir[30];
} config_http_server_prm_t;

void init_config_http_server(config_http_server_prm_t config_http_server_prm);

#endif /* MAIN_CONFIG_HTTP_SERVER_H_ */
