#ifndef WIFI_LIB_H
#define WIFI_LIB_H

#include "esp_err.h"
#include "esp_event.h"

typedef void (*wifi_lib_event_handler_t)(int32_t event_id, void *event_data);

typedef struct wifi_lib_cfg {
	wifi_lib_event_handler_t event_handler;
} wifi_lib_cfg_t;

esp_err_t init_wifi(wifi_lib_cfg_t wifi_lib_cfg);
ESP_EVENT_DECLARE_BASE(WIFI_LIB_EVENT);

typedef enum {
	WIFI_LIB_GOT_IP,
	WIFI_LIB_JOINED_SSID,
	WIFI_LIB_LEFT_SSID,
	WIFI_LIB_HAS_SSID
} wifi_lib_event_types_t;

#endif