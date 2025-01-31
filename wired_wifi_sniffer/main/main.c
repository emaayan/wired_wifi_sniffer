
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"

#include "esp_check.h"
#include "esp_console.h"
#include "linenoise/linenoise.h"


#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "esp_mac.h"

#include "config_http_server.h"
#include "utils_lib.h"
#include "led_common.h"
#include "nvs_lib.h"
#include "sniffer.h"
#include "tcp_server.h"
#include "wifi_lib.h"
#include "usb_ncm_iface.h"


#include "sdkconfig.h"
static const char *TAG = "main";


#define MOUNT_POINT "/data"
#define HISTORY_FILE_PATH MOUNT_POINT "/history.txt"

static int _sock = 0;
static void on_socket_accept_handler(const int sock, struct sockaddr_in *so_in) {
	_sock = sock;
	sniffer_start();
}

static bool on_sniffer_write(void *buffer, size_t len) {
	if (_sock) {
		if (onSend(_sock, buffer, len)) {
			return true;
		} else {
			sniffer_stop();
			disconnect_socket(_sock);
			_sock = 0;			
			return false;
		}
	} else {
		sniffer_stop();			
		return false;
	}
}

#define PORT 19000 // wireshark default port for pipes
#define KEEPALIVE_IDLE 5	 // CONFIG_TCP_SERVER_KEEPALIVE_IDLE
#define KEEPALIVE_INTERVAL 5 // CONFIG_TCP_SERVER_KEEPALIVE_INTERVAL
#define KEEPALIVE_COUNT 3	 // CONFIG_TCP_SERVER_KEEPALIVE_COUNT
static void init_tcp_server() {
	static tcp_server_config_t tcp_server_config = {
		.port = PORT,
		.keepIdle = KEEPALIVE_IDLE,
		.keepInterval = KEEPALIVE_INTERVAL,
		.keepCount = KEEPALIVE_COUNT,
		.on_socket_accept = on_socket_accept_handler, 
	};
	start_tcp_server(&tcp_server_config);
}

static void init_filesystem(void) {
	static wl_handle_t wl_handle;
	const esp_vfs_fat_mount_config_t mount_config = {
		.max_files = 4,
		.format_if_mount_failed = true,
	};
	esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_POINT, "storage", &mount_config, &wl_handle);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
		return;
	}
}

static void init_nvs(void) {
	nvs_init_flash();
}

void init_console() {
	esp_console_repl_t *repl = NULL;
	esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
	repl_config.history_save_path = HISTORY_FILE_PATH;
	repl_config.prompt = "sniffer>";

	// install console REPL environment
#if CONFIG_ESP_CONSOLE_UART
	esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &repl));
#elif CONFIG_ESP_CONSOLE_USB_CDC
	esp_console_dev_usb_cdc_config_t cdc_config = ESP_CONSOLE_DEV_CDC_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_console_new_repl_usb_cdc(&cdc_config, &repl_config, &repl));
#elif CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
	esp_console_dev_usb_serial_jtag_config_t usbjtag_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&usbjtag_config, &repl_config, &repl));
#endif
	register_iface_cmd();
	register_sniffer_cmd();
	char ip[20] = "";
	get_ip(ip, sizeof(ip));

	printf("\n =========================================================\n");
	printf(" |         Steps to sniff network packets                  |\n");
	printf(" |                                                         |\n");
	printf(" |  1. Enter 'help' to check all command's usage           |\n");
	printf(" |  2. use wireshark -i TCP@%s -k to start capture packet |\n", ip);
	printf(" |  3. use http://%s for browser UI           |\n", ip);
	printf(" |                                                         |\n");
	printf(" =========================================================\n\n");

	// start console REPL
	ESP_ERROR_CHECK(esp_console_start_repl(repl));
}

#include "mdns.h"

static char *generate_hostname(void) {
	uint8_t mac[6];
	char *hostname;
	ESP_ERROR_CHECK_WITHOUT_ABORT(esp_read_mac(mac, ESP_MAC_WIFI_STA));
	if (-1 == asprintf(&hostname, "%s-%02X%02X%02X", "sniffer", mac[3], mac[4], mac[5])) {
		abort();
	}
	return hostname;
}

static esp_err_t init_mdns(esp_netif_t *netif) {
	char *hostname = generate_hostname();

	// initialize mDNS
	ESP_ERROR_RETURN(mdns_init(), TAG, "");
	// set mDNS hostname (required if you want to advertise services)
	ESP_ERROR_RETURN(mdns_hostname_set(hostname), TAG, "");
	ESP_LOGI(TAG, "mdns hostname set to: [%s]", hostname);
	// set default mDNS instance name
	ESP_ERROR_RETURN(mdns_instance_name_set("ESP32 with mDNS"), TAG, "");

	// initialize service
	ESP_ERROR_RETURN(mdns_service_add("ESP32-WebServer", "_http", "_tcp", 80, NULL, 0), TAG, "");
	ESP_ERROR_RETURN(mdns_service_subtype_add_for_host("ESP32-WebServer", "_http", "_tcp", NULL, "_server"), TAG, "");

	ESP_ERROR_RETURN(mdns_register_netif(netif), TAG, "");
	/* It is not enough to just register the interface, we have to enable is manually.
	 * This is typically performed in "GOT_IP" event handler, but we call it here directly
	 * since the `EXAMPLE_INTERFACE` netif is connected already, to keep the example simple.
	 */
	ESP_ERROR_RETURN(mdns_netif_action(netif, MDNS_EVENT_ENABLE_IP4), TAG, "");
	ESP_ERROR_RETURN(mdns_netif_action(netif, MDNS_EVENT_ANNOUNCE_IP4), TAG, "");

	free(hostname); // PROBLEM in event error return
	return ESP_OK;
}

static void wired_send_failure() {
	led_blink_fast();
}

void on_wifi_lib_event(int32_t event_id, void *event_data) {
	switch (event_id) {
		case WIFI_LIB_GOT_IP:
			led_blink_slow();
			led_blink_slow();
			break;
	}
}

static config_http_server_prm_t config_http_server_prm = {0};
static wifi_lib_cfg_t wifi_lib_cfg = {.event_handler = on_wifi_lib_event};

void app_main(void) {
	const esp_app_desc_t *esp_app_desc = esp_app_get_description();

	ESP_LOGI(TAG, "[++++++] Starting Sniffer Version: %s [++++++]", esp_app_desc->project_name);

	init_nvs();
	init_filesystem();

	init_console();

	led_init_default();

	init_wired_netif(wired_send_failure);
	ESP_RETURN_VOID_ON_ERROR(init_wifi(wifi_lib_cfg), TAG, "Error init WI-Fi");

	esp_netif_t *netif = get_if();
	ESP_RETURN_VOID_ON_ERROR(init_mdns(netif), TAG, "Error init mdns");

	init_tcp_server();

	init_sniffer(on_sniffer_write);

	snprintf(config_http_server_prm.rootdir, sizeof(config_http_server_prm.rootdir), "%s/", MOUNT_POINT);
	init_config_http_server(config_http_server_prm);
}
