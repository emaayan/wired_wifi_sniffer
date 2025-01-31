#include "usb_ncm_iface.h"

#include <stdint.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_check.h"

#include "tinyusb.h"
#include "tinyusb_net.h"

#include "dhcpserver/dhcpserver.h"
#include "dhcpserver/dhcpserver_options.h"

#include "nvs_lib.h"

#include "esp_console.h"
#include "argtable3/argtable3.h"

#include "utils_lib.h"

static const char *TAG = "usb_ncm_iface";
#ifdef CONFIG_TINYUSB_NET_MODE_RNDIS
DRAM_ATTR uint8_t tud_network_mac_address[6] = {0x02, 0x02, 0x84, 0x6A, 0x96, 0x00}; // for RNDIS
#endif

// #define LOG_PAYLOAD

static esp_netif_t *g_s_netif = NULL;

static void tinyusb_netif_free_buffer_cb(void *buffer, void *ctx) {
	free(buffer);
}

// static uint8_t buf_copy[600]={};

static wired_send_failure_cb _wired_send_failure_cb = NULL;

static esp_err_t tinyusb_netif_recv_cb(void *buffer, uint16_t len, void *ctx) {
	esp_netif_t *s_netif = ctx; // g_s_netif;
	if (s_netif) {
#ifdef LOG_PAYLOAD
		ESP_LOG_BUFFER_HEX("USB->Ethernet", buffer, len);
#endif
		void *buf_copy = malloc(len);
		if (!buf_copy) {
			ESP_LOGE(TAG, "No Memory for size: %d", len);
			return ESP_ERR_NO_MEM;
		} else {
			ESP_LOGD(TAG, "received bytes from ethernet %d ", len);
		}

		//	len=sizeof(buf_copy);
		memcpy(buf_copy, buffer, len);
		return esp_netif_receive(s_netif, buf_copy, len, NULL);
	} else {
		// ESP_LOGE(TAG,"No Interface");
	}
	return ESP_OK;
}

static esp_err_t create_usb_eth_if(esp_netif_t *s_netif, tusb_net_rx_cb_t tusb_net_rx_cb, tusb_net_free_tx_cb_t tusb_net_free_tx_cb) {
	const tinyusb_config_t tusb_cfg = {
		.external_phy = false,
	};

	ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));
	
	tinyusb_net_config_t net_config = {
		// locally administrated address for the ncm device as it's going to be used internally
		.mac_addr = {0},
		.on_recv_callback = tusb_net_rx_cb,	   // tinyusb_netif_recv_cb,
		.free_tx_buffer = tusb_net_free_tx_cb, // wifi_netif_free_buffer_cb, // tinyusb_netif_free_buffer_cb,
		.user_context = s_netif,
	};
	// uint8_t e_mac[6]={0};
	ESP_ERROR_CHECK(esp_read_mac(net_config.mac_addr, ESP_MAC_ETH));

	ESP_ERROR_CHECK(tinyusb_net_init(TINYUSB_USBDEV_0, &net_config));

	return ESP_OK;
}

////////////////////////////////////////////////////////////////////////////////

static void netif_l2_free_cb(void *h, void *buffer) {
	free(buffer);
}

#define TUSB_SEND_TO 50
static esp_err_t ether2usb_transmit_cb(void *h, void *buffer, size_t len) {

#ifdef LOG_PAYLOAD
	ESP_LOG_BUFFER_HEX("Ethernet->USB", buffer, len);
#endif
	esp_err_t esp_err = tinyusb_net_send_sync(buffer, len, NULL, pdMS_TO_TICKS(TUSB_SEND_TO));
	if (esp_err != ESP_OK) {
		switch (esp_err) {
			case ESP_FAIL:
				// esp_err_t esp_err=tinyusb_net_send_async (buffer, len,NULL);
				// esp_err_t esp_err=tinyusb_net_send(buffer,len,NULL);

				ESP_LOGE("Ethernet->USB", "Failed to send");
				if (_wired_send_failure_cb) {
					_wired_send_failure_cb();
				}
				ESP_LOG_BUFFER_HEX("Ethernet->USB", buffer, len);
				//	ESP_LOGI("Ethernet->USB", "retrying in %d",TUSB_SEND_TO);
				/*
				esp_err=tinyusb_net_send_sync(buffer, len, NULL, pdMS_TO_TICKS(TUSB_SEND_TO));
				  if (esp_err!= ESP_OK) {
					ESP_LOGE("Ethernet->USB", "Failed to send buffer to USB! %d" ,esp_err);
				 }
				 */
				break;
			case ESP_ERR_INVALID_STATE:
				ESP_LOGE("Ethernet->USB", "Tiny USB was not ready error %d", esp_err);
				break;
			default:
				ESP_LOGE("Ethernet->USB", "Error sending, Error %d", esp_err);
				break;
		}
	} else {
		ESP_LOGD("Ethernet->USB", "Sent to USB %d ", len);
	}
	return esp_err; // ESP_OK; //TODO: need to see if it does a retry by itself or do i need do here;
}

static esp_netif_recv_ret_t ethernetif_receieve_cb(void *h, void *buffer, size_t len, void *l2_buff) {
#ifdef LOG_PAYLOAD
	ESP_LOG_BUFFER_HEX("Ethernet->ESP", buffer, len);
#endif
	return ethernetif_input(h, buffer, len, l2_buff);
}
// with OUI range MAC to create a virtual netif running http server
// this needs to be different to usb_interface_mac (==client)

static bool is_valid_ip(int32_t addr) {
	return addr != IPADDR_NONE;
}

void save_ip(const char *ip, const char *def_ip) {

	int32_t ip_addr = ipaddr_addr(ip);
	int32_t def_ip_addr = ipaddr_addr(def_ip);

	if (is_valid_ip(ip_addr)) {
		nvs_set_num32i(NS, "IP", ip_addr);
	} else {
		nvs_set_num32i(NS, "IP", def_ip_addr);
		ESP_LOGE(TAG, "Invalid IP %s, using default %s ", ip, def_ip);
	}
}

static u_int32_t load_ip(const char *def_ip) {
	int32_t def_ip_addr = ipaddr_addr(def_ip);
	int32_t ip_addr = 0;
	nvs_get_num32i(NS, "IP", &ip_addr, def_ip_addr);
	if (is_valid_ip(ip_addr)) {
		return ip_addr;
	} else {
		ESP_LOGE(TAG, "Invalid IP was loaded, usign default");
		return def_ip_addr;
	}
}

esp_err_t get_ip(char *ip, size_t sz) {

	if (g_s_netif) {
		esp_netif_ip_info_t esp_netif_ip_info = {0};
		esp_err_t esp_err = esp_netif_get_ip_info(g_s_netif, &esp_netif_ip_info);
		if (esp_err == ESP_OK) {
			snprintf(ip, sz, IPSTR, IP2STR(&esp_netif_ip_info.ip));
		} else {
			ESP_LOGE(TAG, "Error getting ip%s", esp_err_to_name(esp_err));
		}
		return esp_err;
	} else {
		return ESP_ERR_INVALID_STATE;
	}
}

static esp_err_t create_virtual_net_if(esp_netif_t **res_s_netif) {

	int32_t ip = load_ip(DEF_IP);

	const esp_netif_ip_info_t esp_netif_soft_ap_ip = {
		.ip = {.addr = ip},
		.gw = {.addr = ip},
		.netmask = {.addr = ipaddr_addr("255.255.255.0")},
	};

	ESP_LOGI(TAG, "*********IP for wireshark is: " IPSTR, IP2STR(&esp_netif_soft_ap_ip.ip));

	// 1) Derive the base config (very similar to IDF's default WiFi AP with DHCP server)
	esp_netif_inherent_config_t base_cfg = {
		.flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP,
		.ip_info = &esp_netif_soft_ap_ip,
		.if_key = "wired",
		.if_desc = "USB NCM sniffer device",
		.route_prio = 10,
	};

	// 2) Use static config for driver's config pointing only to static transmit and free functions
	esp_netif_driver_ifconfig_t driver_cfg = {
		.handle = (void *)1,					  // not using an instance, USB-NCM is a static singleton (must be != NULL)
		.transmit = ether2usb_transmit_cb,		  // point to static Tx function
		.driver_free_rx_buffer = netif_l2_free_cb // point to Free Rx buffer function
	};

	// 3) USB-NCM is an Ethernet netif from lwip perspective, we already have IO definitions for that:
	struct esp_netif_netstack_config lwip_netif_config = {
		.lwip = {
			.init_fn = ethernetif_init,
			.input_fn = ethernetif_receieve_cb,
		}};

	esp_netif_config_t cfg = {
		// Config the esp-netif with:
		.base = &base_cfg,			//   1) inherent config (behavioural settings of an interface)
		.driver = &driver_cfg,		//   2) driver's config (connection to IO functions -- usb)
		.stack = &lwip_netif_config //   3) stack config (using lwip IO functions -- derive from eth)
	};
	esp_netif_t *s_netif = esp_netif_new(&cfg);
	if (s_netif == NULL) {
		ESP_LOGE(TAG, "Cannot initialize if interface Net device");
		return ESP_FAIL;
	}

	uint8_t lwip_addr[6] = {0};
	ESP_ERROR_RETURN(esp_base_mac_addr_get(lwip_addr),TAG,"");
	ESP_ERROR_RETURN(esp_netif_set_mac(s_netif, lwip_addr),TAG,"");

	uint32_t lease_opt = 10000; // set the minimum lease time
	ESP_ERROR_RETURN(esp_netif_dhcps_option(s_netif, ESP_NETIF_OP_SET, IP_ADDRESS_LEASE_TIME, &lease_opt, sizeof(lease_opt)),TAG,"");
	// start the interface manually (as the driver has been started already)
	esp_netif_action_start(s_netif, 0, 0, 0); 
	*res_s_netif = s_netif;

	return ESP_OK;
}

/**
 *  In this scenario of configuring WiFi, we setup USB-Ethernet to create a virtual network and run DHCP server,
 *  so it could assign an IP address to the PC
 *
 *           ESP32               PC
 *      |    lwip MAC=...01   |                        eth NIC MAC=...02
 *      | <DHCP server>   usb | <->  [ USB-NCM device acting as eth-NIC ]
 *      | <HTTP server>       |
 *
 *  From the PC's NIC perspective the board acts as a separate network with it's own IP and MAC address,
 *  but the virtual ethernet NIC has also it's own IP and MAC address (configured via tinyusb_net_init()).
 *  That's why we need to create the virtual network with *different* MAC address.
 *  Here, we use two different OUI range MAC addresses.
 */

esp_netif_t *get_if() {
	return g_s_netif;
}

esp_err_t init_wired_netif(wired_send_failure_cb wired_send_failure) {

	_wired_send_failure_cb = wired_send_failure;
	ESP_RETURN_ON_ERROR(create_virtual_net_if(&g_s_netif),TAG,"Problem creating virutal if");
	ESP_RETURN_ON_ERROR(create_usb_eth_if(g_s_netif, tinyusb_netif_recv_cb, tinyusb_netif_free_buffer_cb),TAG,"Problem creating virutal if");
	return ESP_OK;
}

static struct {
	struct arg_str *ip;
	struct arg_end *end;
} iface_args;

static int do_iface_cmd(int argc, char **argv) {
	int nerrors = arg_parse(argc, argv, (void **)&iface_args);

	if (nerrors != 0) {
		arg_print_errors(stderr, iface_args.end, argv[0]);
		return 0;
	}
	if (iface_args.ip->count > 0) {
		const char *key = iface_args.ip->sval[0];
		// unsigned int sz=strlen(key);
		save_ip(key, DEF_IP);
		esp_restart();
	}
	return 0;
}

esp_err_t register_iface_cmd(void) {
	iface_args.ip = arg_str0("i", "ip", "<ip_address>", "ip of internal iface (to set wireshark to listen to, will cause restart)");
	iface_args.end = arg_end(1);
	const esp_console_cmd_t iface_cmd = {
		.command = "iface",
		.help = "configure iface parameters",
		.hint = NULL,
		.func = &do_iface_cmd,
		.argtable = &iface_args,
	};
	return  esp_console_cmd_register(&iface_cmd);
}
