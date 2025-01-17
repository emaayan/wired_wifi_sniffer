#include "tcp_server.h"

#include "esp_log.h"
#include "lwip/tcp.h"
#include "sys/errno.h" //contains the actuall description of errorcodes
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"

#include "../../build/config/sdkconfig.h"

#define RX_BUFFER_SIZE 256

static const char *TAG = "TcpServer";
// https://docs.espressif.com/projects/esp-idf/en/v5.0.1/esp32/api-guides/lwip.html?highlight=shutdown#socket-error-handling
// https://esp32developer.com/programming-in-c-c/tcp-ip/tcp-server

#define SD_BOTH 2
void disconnect_socket(int sock)
{
    if (sock)
    {
        int ret_shut = shutdown(sock, SD_BOTH);
        ESP_LOGD(TAG, "code during shutdown : %d ", ret_shut);//TODO: we get -1 find out why
        int ret_close = close(sock);
        ESP_LOGD(TAG, "code during close : %d ", ret_close);
    }
}

void onSocketAccept(const int sock, struct sockaddr_in *so_in, on_socket_accept_t on_socket_accept)
{
    char addr_str[128];
    inet_ntoa_r(so_in->sin_addr, addr_str, sizeof(addr_str) - 1);
    ESP_LOGI(TAG, "Socket accepted ip address: %s:%d ", addr_str, so_in->sin_port);
    if (on_socket_accept)
    {		
        on_socket_accept(sock, so_in);
    }
}

void onReceive(const int sock, char rx_buffer[], int len)
{
    //   ESP_LOGI(TAG, "Received %d bytes: %s", len, rx_buffer);
}

// send() can return less bytes than supplied length.
// Walk-around for robust implementation.
// https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/wifi.html#wifi-buffer-usage
// https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/lwip.html
// https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/kconfig.html#config-lwip-check-thread-safety
// https://pubs.opengroup.org/onlinepubs/007908799/xns/send.html
bool onSend(const int sock, void *buffer, size_t len)
{	
	if(sock){
	//	ESP_LOGE(TAG, "Sending %d", len);	    
	//	ESP_LOG_BUFFER_HEX(TAG, buffer, len); 
	    int e = write(sock, buffer, len);
	    
	    if (e < 0)
	    {
	        ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
	        disconnect_socket(sock);
	        return false;
	    }
	    else
	    {
	        return true;
	    }   
    }else{
		return false;
	}
}

static void tcp_server_task(void *pvParameters)
{

    tcp_server_config_t *tcp_server_config = pvParameters;
    uint16_t port = tcp_server_config->port;
    int keepAlive = 1;
    int keepIdle = tcp_server_config->keepIdle;
    int keepInterval = tcp_server_config->keepInterval;
    int keepCount = tcp_server_config->keepCount;
    on_socket_accept_t on_socket_accept = tcp_server_config->on_socket_accept;

    int addr_family = AF_INET;
    int listen_sock = socket(addr_family, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int reuse_addr = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

    ESP_LOGD(TAG, "Socket created");
    struct sockaddr_storage dest_addr;
    struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *)&dest_addr;
    dest_addr_ip4->sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr_ip4->sin_family = AF_INET;
    dest_addr_ip4->sin_port = htons(port);

    int bind_status = bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bind_status != 0)
    {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d,IPPROTO: %d", errno, addr_family);
    }
    else
    {
        ESP_LOGI(TAG, "Socket bound, port %d", port);

        int listen_status = listen(listen_sock, 1);
        if (listen_status != 0)
        {
            ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
        }
        else
        {

            while (1)
            {

                ESP_LOGD(TAG, "Waiting for Client Socket Connections");

                struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
                socklen_t addr_len = sizeof(source_addr);
                int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
                if (sock < 0)
                {
                    ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
                }
                else
                {
                    // Set tcp keepalive option
                    int opt_ret = 0;
                    opt_ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(int));
                    if (opt_ret < 0)
                    {
                        ESP_LOGE(TAG, "problem setting SO_KEEPALIVE: errno %d", sock);
                    }
                    opt_ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepIdle, sizeof(int));
                    if (opt_ret < 0)
                    {
                        ESP_LOGE(TAG, "problem setting TCP_KEEPIDLE: errno %d", sock);
                    }
                    opt_ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepInterval, sizeof(int));
                    if (opt_ret < 0)
                    {
                        ESP_LOGE(TAG, "problem setting TCP_KEEPINTVL: errno %d", sock);
                    }
                    opt_ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepCount, sizeof(int));
                    if (opt_ret < 0)
                    {
                        ESP_LOGE(TAG, "problem setting TCP_KEEPCNT: errno %d", sock);
                    }
                    // Convert ip address to string
                    if (source_addr.ss_family == PF_INET)
                    {
                        struct sockaddr_in *so_in = ((struct sockaddr_in *)&source_addr);
                        onSocketAccept(sock, so_in, on_socket_accept);
                        // do_retransmit(sock);
                    }

                    // disconnect_socket(sock);
                }
            }
        }
    }

    close(listen_sock);
    vTaskDelete(NULL);
}

#define TCP_SERVER_TASK_PRIORITY 10
void start_tcp_server(tcp_server_config_t *tcp_server_config)
{
    ESP_LOGI(TAG, "Starting TCP Server");
    xTaskCreate(tcp_server_task, "tcp_server", configMINIMAL_STACK_SIZE *6, tcp_server_config, configMAX_PRIORITIES - TCP_SERVER_TASK_PRIORITY, NULL);
}
