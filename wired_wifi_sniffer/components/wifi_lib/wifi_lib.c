#include "wifi_lib.h"

#include <stdio.h>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "utils_lib.h"


static const char *TAG = "wifi_lib";

static wifi_lib_cfg_t _wifi_lib_cfg = {0};

static esp_event_loop_handle_t wifi_lib_event_loop_handle = NULL;
ESP_EVENT_DEFINE_BASE(WIFI_LIB_EVENT);

static void wifi_lib_post_event(wifi_lib_event_types_t wifi_lib_event_types) {
	if (wifi_lib_event_loop_handle) {
		esp_err_t err = esp_event_post_to(wifi_lib_event_loop_handle, WIFI_LIB_EVENT, wifi_lib_event_types, NULL, 0, pdMS_TO_TICKS(10));
		switch (err) {
			case ESP_ERR_TIMEOUT:
				ESP_LOGE(TAG, "timeout on event loop");
				break;
			default:
				ESP_ERROR_CHECK_WITHOUT_ABORT(err);
				break;
		}
	}
}

#define WIFI_LIB_EVENT_QUEUE_SIZE 20

static esp_err_t wifi_lib_start_event_loop() {
	static esp_event_loop_args_t wifi_lib_event_loop_task_config = {
		.queue_size = WIFI_LIB_EVENT_QUEUE_SIZE,
		.task_name = "wifi_lib_events_task",
		.task_priority = configMAX_PRIORITIES - 5,
		.task_stack_size = configMINIMAL_STACK_SIZE * 5,
		.task_core_id = tskNO_AFFINITY};

	return esp_event_loop_create(&wifi_lib_event_loop_task_config, &wifi_lib_event_loop_handle);
}

static void wifi_lib_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data) {
	wifi_lib_event_handler_t event_handler = handler_args;
	event_handler(id, event_data);
}

static esp_err_t wifi_lib_register_event_handler(wifi_lib_event_handler_t event_handler) {
	if (wifi_lib_event_loop_handle) {
		return esp_event_handler_instance_register_with(wifi_lib_event_loop_handle, WIFI_LIB_EVENT, ESP_EVENT_ANY_ID, wifi_lib_event_handler, event_handler, NULL);
	} else {
		return ESP_ERR_INVALID_ARG;
	}
}

#define WIFI_EVENT_AP_START_BIT BIT0
#define WIFI_EVENT_STA_CONNECTED_BIT BIT1
#define WIFI_EVENT_STA_DISCONNECTED_BIT BIT2
#define WIFI_EVENT_STA_START_BIT BIT3
#define WIFI_EVENT_AP_STOP_BIT BIT4
#define WIFI_EVENT_STA_STOP_BIT BIT5
#define WIFI_EVENT_IS_READY BIT10

static EventGroupHandle_t s_wifi_event_group;
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {

	switch (event_id) {
		case WIFI_EVENT_WIFI_READY: {
			ESP_LOGI(TAG, "Wi-fi Ready");
			xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_IS_READY);
			break;
		}
		case WIFI_EVENT_STA_START: {
			ESP_LOGI(TAG, "STA Started");
			xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_START_BIT);
			break;
		}
		case WIFI_EVENT_STA_STOP: {
			ESP_LOGI(TAG, "STA Stopped");
			xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_STOP_BIT);
			break;
		}
		case WIFI_EVENT_AP_START: {
			ESP_LOGI(TAG, "Started soft AP");
			xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_AP_START_BIT);
			break;
		}
		case WIFI_EVENT_AP_STOP: {
			ESP_LOGI(TAG, "Stopped Soft AP");
			xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_AP_STOP_BIT);
			break;
		}
		case WIFI_EVENT_AP_STACONNECTED: {
			wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
			ESP_LOGI(TAG, "station " MACSTR " join, AID=%d", MAC2STR(event->mac), event->aid);
			break;
		}
		case WIFI_EVENT_AP_STADISCONNECTED: {
			wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
			ESP_LOGI(TAG, "station " MACSTR " leave, AID=%d", MAC2STR(event->mac), event->aid);
			break;
		}
		case WIFI_EVENT_STA_CONNECTED: {
			wifi_event_sta_connected_t *wifi_event_sta_connected = (wifi_event_sta_connected_t *)event_data;
			ESP_LOGI(TAG, "Connected STA to %s on channel %d", wifi_event_sta_connected->ssid, wifi_event_sta_connected->channel);
			xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_CONNECTED_BIT);
			break;
		}
		case WIFI_EVENT_STA_DISCONNECTED: {
			wifi_event_sta_disconnected_t *wifi_event_sta_disconnected = (wifi_event_sta_disconnected_t *)event_data;
			ESP_LOGI(TAG, "Disconnected From %s with rssi %d ,due to: %d", wifi_event_sta_disconnected->ssid, wifi_event_sta_disconnected->rssi, wifi_event_sta_disconnected->reason);
			// esp_wifi_connect();
			// s_retry_num++;
			xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_DISCONNECTED_BIT);
			break;
		}
		case WIFI_EVENT_STA_BEACON_TIMEOUT: {
			ESP_LOGW(TAG, "STA Beacon timeout");
			break;
		}
		case WIFI_EVENT_HOME_CHANNEL_CHANGE: {
			ESP_LOGI(TAG, "Channel changed");
			break;
		}
		default:
			ESP_LOGI(TAG, "STA Event %" PRIu32, event_id);
			break;
	}
}

#define IP_EVENT_STA_GOT_IP_BIT BIT0
#define IP_EVENT_AP_STAIPASSIGNED_BIT BIT1
#define IP_EVENT_STA_LOST_IP_BIT BIT2
static EventGroupHandle_t s_ip_event_group;
static void ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	int8_t power = 0;
	switch (event_id) {

		case IP_EVENT_STA_GOT_IP: {
			// s_retry_num = 0;
			ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
			wifi_lib_post_event(WIFI_LIB_GOT_IP);
			ESP_LOGI(TAG, "IP:" IPSTR, IP2STR(&event->ip_info.ip));
			ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_get_max_tx_power(&power));
			ESP_LOGI(TAG, "Max TX Power: %d", power);
			xEventGroupSetBits(s_ip_event_group, IP_EVENT_STA_GOT_IP_BIT);
			break;
		}
		case IP_EVENT_AP_STAIPASSIGNED: {
			ip_event_ap_staipassigned_t *event = (ip_event_ap_staipassigned_t *)event_data;
			wifi_lib_post_event(WIFI_LIB_GOT_IP);

			//	led_blink_slow();
			//	led_blink_slow();

			ESP_LOGI(TAG, "IP assigned :" IPSTR, IP2STR(&event->ip));
			ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_get_max_tx_power(&power));
			ESP_LOGI(TAG, "Max TX Power: %d", power);
			xEventGroupSetBits(s_ip_event_group, IP_EVENT_AP_STAIPASSIGNED_BIT);
			break;
		}
		case IP_EVENT_STA_LOST_IP: {
			ESP_LOGW(TAG, "station lost IP and the IP is reset to 0");
			xEventGroupSetBits(s_ip_event_group, IP_EVENT_STA_LOST_IP_BIT);
			break;
		}
		default:
			ESP_LOGI(TAG, "IP Event %" PRIu32, event_id);
			break;
	}
}

esp_err_t init_wifi(wifi_lib_cfg_t wifi_lib_cfg) {
	_wifi_lib_cfg = wifi_lib_cfg;
	ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_loop_create_default());

	s_wifi_event_group = xEventGroupCreate();
	esp_event_handler_instance_t instance_any_id;
	ESP_ERROR_RETURN(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id), TAG, "");

	s_ip_event_group = xEventGroupCreate();
	esp_event_handler_instance_t instance_got_ip;
	ESP_ERROR_RETURN(esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &ip_event_handler, NULL, &instance_got_ip), TAG, "");

	ESP_ERROR_RETURN(wifi_lib_start_event_loop(),TAG,"");
	ESP_ERROR_RETURN(wifi_lib_register_event_handler(_wifi_lib_cfg.event_handler), TAG, "");

	
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_RETURN(esp_wifi_init(&cfg), TAG, "");

	ESP_ERROR_RETURN(esp_wifi_set_storage(WIFI_STORAGE_RAM), TAG, "");
	ESP_ERROR_RETURN(esp_wifi_set_mode(WIFI_MODE_NULL), TAG, "");
	ESP_ERROR_RETURN(esp_wifi_set_ps(WIFI_PS_NONE), TAG, ""); // for timestamp setting
	ESP_ERROR_RETURN(esp_netif_init(), TAG, "");

	ESP_ERROR_RETURN(esp_wifi_start(), TAG, "");
	ESP_LOGI(TAG, "Waiting for IP, the card must be connected to the other USB port, for the CLI to work");
	EventBits_t bits = xEventGroupWaitBits(s_ip_event_group, IP_EVENT_AP_STAIPASSIGNED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
	if (bits & IP_EVENT_AP_STAIPASSIGNED_BIT) {
		ESP_LOGD(TAG, "Got IP");
	}
	return ESP_OK;
}