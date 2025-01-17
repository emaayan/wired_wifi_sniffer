
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "esp_app_desc.h"

#include "lwip/ip4_addr.h"

#include "sdkconfig.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"

#include "esp_console.h"
#include "esp_event.h"
#include "esp_vfs_fat.h"
#include "esp_wifi_types_generic.h"
#include "esp_wifi.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "usb_ncm_iface.h"
#include "sniffer.h"
#include "esp_mac.h"
#include "tcp_server.h"
#include "nvs_lib.h"
#include "config_http_server.h"
#include "xtensa/config/specreg.h"
#include "led_common.h"

#define MOUNT_POINT "/data"
#define HISTORY_FILE_PATH MOUNT_POINT "/history.txt" 

static const char *TAG = "main";


#define WIFI_EVENT_AP_START_BIT BIT0
#define WIFI_EVENT_STA_CONNECTED_BIT BIT1
#define WIFI_EVENT_STA_DISCONNECTED_BIT BIT2
#define WIFI_EVENT_STA_START_BIT BIT3
#define WIFI_EVENT_AP_STOP_BIT BIT4
#define WIFI_EVENT_STA_STOP_BIT BIT5
#define WIFI_EVENT_IS_READY BIT10
static EventGroupHandle_t s_wifi_event_group;
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data){
 	switch (event_id)
    {
	case WIFI_EVENT_WIFI_READY:
	{
		ESP_LOGI(TAG, "Wifi Ready");
		xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_IS_READY);
		break; 
	}	
    case WIFI_EVENT_STA_START:
    {
        ESP_LOGI(TAG, "STA Started");
        xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_START_BIT);
        break;
    }
    case WIFI_EVENT_STA_STOP:
    {
        ESP_LOGI(TAG, "STA Stopped");
        xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_STOP_BIT);
        break;
    }
    case WIFI_EVENT_AP_START:
    {
        ESP_LOGI(TAG, "Started soft AP");
        xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_AP_START_BIT);
        break;
    }
    case WIFI_EVENT_AP_STOP:
    {
        ESP_LOGI(TAG, "Stopped Soft AP");
        xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_AP_STOP_BIT);
        break;
    }
    case WIFI_EVENT_AP_STACONNECTED:
    {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(TAG, "station " MACSTR " join, AID=%d", MAC2STR(event->mac), event->aid);
        break;
    }
    case WIFI_EVENT_AP_STADISCONNECTED:
    {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGI(TAG, "station " MACSTR " leave, AID=%d", MAC2STR(event->mac), event->aid);
        break;
    }
    case WIFI_EVENT_STA_CONNECTED:
    {
        wifi_event_sta_connected_t *wifi_event_sta_connected = (wifi_event_sta_connected_t *)event_data;
        ESP_LOGI(TAG, "Connected STA to %s on channel %d", wifi_event_sta_connected->ssid, wifi_event_sta_connected->channel);
        xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_CONNECTED_BIT);        
        break;
    }
    case WIFI_EVENT_STA_DISCONNECTED:
    {
        wifi_event_sta_disconnected_t *wifi_event_sta_disconnected = (wifi_event_sta_disconnected_t *)event_data;
        ESP_LOGI(TAG, "Disconnected From %s with rssi %d ,due to: %d", wifi_event_sta_disconnected->ssid, wifi_event_sta_disconnected->rssi, wifi_event_sta_disconnected->reason);
        // esp_wifi_connect();
        // s_retry_num++;
        xEventGroupSetBits(s_wifi_event_group, WIFI_EVENT_STA_DISCONNECTED_BIT);        
        break;
    }
    case WIFI_EVENT_STA_BEACON_TIMEOUT:
    {
        ESP_LOGW(TAG, "STA Beacon timeout");
        break;
    }
	case WIFI_EVENT_HOME_CHANNEL_CHANGE :
	{
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
static void ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{ 
	 int8_t power = 0;
    switch (event_id)
    {

    case IP_EVENT_STA_GOT_IP:
    {
       // s_retry_num = 0;
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        //wifi_lib_post_event(WIFI_LIB_GOT_IP);
        ESP_LOGI(TAG, "IP:" IPSTR, IP2STR(&event->ip_info.ip));
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_get_max_tx_power(&power));
    	ESP_LOGI(TAG, "Max TX Power: %d", power);
    	xEventGroupSetBits(s_ip_event_group, IP_EVENT_STA_GOT_IP_BIT);
        break;
    }
    case IP_EVENT_AP_STAIPASSIGNED:
    {
        ip_event_ap_staipassigned_t *event = (ip_event_ap_staipassigned_t *)event_data;
        led_blink_slow();
        led_blink_slow();
        ESP_LOGI(TAG, "IP assigned :" IPSTR, IP2STR(&event->ip));
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_get_max_tx_power(&power));
    	ESP_LOGI(TAG, "Max TX Power: %d", power);
    	xEventGroupSetBits(s_ip_event_group, IP_EVENT_AP_STAIPASSIGNED_BIT);
        break;
    }
    case IP_EVENT_STA_LOST_IP:
    {
        ESP_LOGW(TAG, "station lost IP and the IP is reset to 0");
        xEventGroupSetBits(s_ip_event_group, IP_EVENT_STA_LOST_IP_BIT);
        break;
    }
    default:
        ESP_LOGI(TAG, "IP Event %" PRIu32, event_id);
        break;
    }
}

static void init_wifi(void)
{
	ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_loop_create_default());
	
	s_wifi_event_group = xEventGroupCreate();
	esp_event_handler_instance_t instance_any_id;
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    
	s_ip_event_group= xEventGroupCreate();
	esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &ip_event_handler, NULL, &instance_got_ip));
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_init(&cfg));         
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_storage(WIFI_STORAGE_RAM));           
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_ps(WIFI_PS_NONE));//for timestamp setting
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_init());
        
    esp_wifi_start();
    ESP_LOGI(TAG,"Waiting for IP, the card must be connected to the other USB port, for the CLI to work");
    EventBits_t bits = xEventGroupWaitBits(s_ip_event_group, IP_EVENT_AP_STAIPASSIGNED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & IP_EVENT_AP_STAIPASSIGNED_BIT){
		ESP_LOGD(TAG,"Got IP");		
	}      
}

/*
typedef struct
{
	int sock;
} sender_config_t ;

static void sender(void *pvParameters)
{
	sender_config_t *st=pvParameters;
	int sock=st->sock; 
	ESP_LOGI(TAG,"Starting to send");	
	bool b=true;
	
 	while(b){
					 
		 char buffer[1400]="";
		 int max=sizeof(buffer)-1 ;
		 int min=20;
		 int rd_num = rand() % (max - min + 1) + min;
		 size_t sz=rd_num;//sizeof(buffer);
	//	 sz=512; 
	//	 ESP_LOGI(TAG,"Size: %d",rd_num);
		 b=onSend(sock, &sz, sizeof(sz));
		 if (b)     {
		 	memset(buffer, 't', sz);
		 	b=onSend(sock, buffer, sz);
		 }
		 vTaskDelay(pdMS_TO_TICKS(30));
	}
	ESP_LOGI(TAG,"Stopped");
	vTaskDelete(NULL);
}
 */
//static sender_config_t st={.sock=0};
static void on_socket_accept_handler(const int sock, struct sockaddr_in *so_in) 
{		       
	//st.sock=sock;
	//xTaskCreate(sender, "sender", configMINIMAL_STACK_SIZE *6, &st, configMAX_PRIORITIES - 4, NULL);
    sniffer_start(sock); 	
}


#define PORT 19000
#define KEEPALIVE_IDLE 5 // CONFIG_TCP_SERVER_KEEPALIVE_IDLE
#define KEEPALIVE_INTERVAL 5 //CONFIG_TCP_SERVER_KEEPALIVE_INTERVAL
#define KEEPALIVE_COUNT 3 //CONFIG_TCP_SERVER_KEEPALIVE_COUNT
static void init_tcp_server()
{
    static tcp_server_config_t tcp_server_config = {.port = PORT, .keepIdle = KEEPALIVE_IDLE, .keepInterval = KEEPALIVE_INTERVAL, .keepCount = KEEPALIVE_COUNT, .on_socket_accept = on_socket_accept_handler};
    start_tcp_server(&tcp_server_config);
}

static void init_filesystem(void)
{
    static wl_handle_t wl_handle;
    const esp_vfs_fat_mount_config_t mount_config = {	
        .max_files = 4,
        .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_POINT, "storage", &mount_config, &wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return;
    }
}


static void init_nvs(void)
{    
    nvs_init_flash();    
}


void init_console(){
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
    char ip[20]="";
	get_ip(ip,sizeof(ip));
	
    printf("\n =========================================================\n");
    printf(" |         Steps to sniff network packets                  |\n");
    printf(" |                                                         |\n");
    printf(" |  1. Enter 'help' to check all command's usage           |\n");    
    printf(" |  2. use wireshark -i TCP@%s -k to start capture packet |\n",ip);
    printf(" |  3. use http://%s for browser UI           |\n",ip);
    printf(" |                                                         |\n");
    printf(" =========================================================\n\n");

    // start console REPL
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}



#include "mdns.h"

static char *generate_hostname(void)
{
    uint8_t mac[6];
    char   *hostname;
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    if (-1 == asprintf(&hostname, "%s-%02X%02X%02X", "sniffer", mac[3], mac[4], mac[5])) {
        abort();
    }
    return hostname;

}

static void init_mdns(esp_netif_t * netif)
{
    char *hostname = generate_hostname();

    //initialize mDNS
    ESP_ERROR_CHECK( mdns_init() );
    //set mDNS hostname (required if you want to advertise services)
    ESP_ERROR_CHECK( mdns_hostname_set(hostname) );
    ESP_LOGI(TAG, "mdns hostname set to: [%s]", hostname);
    //set default mDNS instance name
    ESP_ERROR_CHECK( mdns_instance_name_set("ESP32 with mDNS") );
   
    //initialize service
    ESP_ERROR_CHECK( mdns_service_add("ESP32-WebServer", "_http", "_tcp", 80, NULL, 0) );
    ESP_ERROR_CHECK( mdns_service_subtype_add_for_host("ESP32-WebServer", "_http", "_tcp", NULL, "_server") );
    
	
 	ESP_ERROR_CHECK(mdns_register_netif(netif));
    /* It is not enough to just register the interface, we have to enable is manually.
     * This is typically performed in "GOT_IP" event handler, but we call it here directly
     * since the `EXAMPLE_INTERFACE` netif is connected already, to keep the example simple.
     */
    ESP_ERROR_CHECK(mdns_netif_action(netif, MDNS_EVENT_ENABLE_IP4));
    ESP_ERROR_CHECK(mdns_netif_action(netif, MDNS_EVENT_ANNOUNCE_IP4 ));

    free(hostname);
}

static void wired_send_failure(){
	led_blink_fast();
}

#include <sys/time.h>
void app_main(void)
{
	const esp_app_desc_t * esp_app_desc =esp_app_get_description();	
    ESP_LOGI(TAG, "[++++++] Starting Sniffer Version: %s",esp_app_desc->version);
 	
	
    init_nvs();        	
	init_filesystem();
	led_init_default();
			
    init_wired_netif(wired_send_failure);
    init_wifi();
    
	esp_netif_t * netif=get_if();	
	init_mdns(netif);
	
	init_tcp_server();
	
	init_sniffer();
	
	init_http_server();
	
	init_console();
	
	//set_time(1736795134237);
	
	
	
}

