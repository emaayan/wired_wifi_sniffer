
#pragma once
#include <stdio.h>
#include "lwip/esp_netif_net_stack.h"


#define DEF_IP "192.168.5.1"
typedef void (*wired_send_failure_cb)();
void save_ip(const char* ip,const char* def_ip );
esp_netif_t * get_if();
esp_err_t init_wired_netif(wired_send_failure_cb wired_send_failure);
esp_err_t get_ip(char *ip, size_t sz);
void register_iface_cmd(void);