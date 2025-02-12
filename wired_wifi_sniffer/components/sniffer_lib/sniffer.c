#include "sniffer.h"

#include "esp_console.h"
#include "argtable3/argtable3.h"

#include "esp_check.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "capture_lib.h"
#include "nvs_lib.h"
#include "utils_lib.h"

#include "sdkconfig.h"
static const char *TAG = "sniffer";

#define SNIFFER_DEFAULT_MAC ""
#define SNIFFER_DEFAULT_CHANNEL (1)
#define SNIFFER_DEFAULT_RSSI (-70)
#define SNIFFER_DEFAULT_FRAME_TYPE_FILTER WIFI_PROMIS_FILTER_MASK_ALL

typedef struct {
	char *filter_name;
	uint32_t filter_val;
} wlan_filter_table_t;

typedef struct {
	bool run;
	sniffer_write_cb_t sniffer_write_cb;
	addrFilter_t addr2_filter;
	int rssi_th;
} sniffer_runtime_t;

static sniffer_runtime_t snf_rt = {0};

static wlan_filter_table_t wifi_filter_hash_table[SNIFFER_WLAN_FILTER_MAX] = {0};

static void create_wifi_filter_hashtable(void) {
	char *wifi_filter_keys[SNIFFER_WLAN_FILTER_MAX] = {"mgmt", "data", "ctrl", "misc", "mpdu", "ampdu", "fcsfail", "all"};
	uint32_t wifi_filter_values[SNIFFER_WLAN_FILTER_MAX] = {
		WIFI_PROMIS_FILTER_MASK_MGMT, WIFI_PROMIS_FILTER_MASK_DATA, WIFI_PROMIS_FILTER_MASK_CTRL, WIFI_PROMIS_FILTER_MASK_MISC, WIFI_PROMIS_FILTER_MASK_DATA_MPDU, WIFI_PROMIS_FILTER_MASK_DATA_AMPDU, WIFI_PROMIS_FILTER_MASK_FCSFAIL, 1 << 7 // WIFI_PROMIS_FILTER_MASK_ALL
	};
	for (int i = 0; i < SNIFFER_WLAN_FILTER_MAX; i++) {
		wifi_filter_hash_table[i].filter_name = wifi_filter_keys[i];
		wifi_filter_hash_table[i].filter_val = wifi_filter_values[i];
	}
}

uint32_t search_wifi_filter_hashtable(const char *key) {
	uint32_t len = strlen(key);
	for (int i = 0; i < SNIFFER_WLAN_FILTER_MAX; i++) {
		if (!strncmp(wifi_filter_hash_table[i].filter_name, key, len)) {
			return wifi_filter_hash_table[i].filter_val;
		}
	}
	return 0;
}

static bool sniffer_write(void *buffer, size_t len) {
	return snf_rt.sniffer_write_cb(buffer, len); // onSend(sock, buffer, len);
}

static bool isAddrEquel(const uint8_t addr[], const addrFilter_t filter) {
	bool f = filter.size == 0 || !memcmp(addr, filter.addr, filter.size);
	return f;
}

static bool packet_mac_filter(wifi_promiscuous_pkt_type_t type, addrFilter_t addr2_filter, void *buf) {

	// ESP_LOGI(CMD_PCAP_TAG,"%d ",sz);
	// ESP_LOG_BUFFER_HEX(CMD_PCAP_TAG, pcap_rec->buf,sz);
	bool macFilter = false;
	const uint16_t fc = *(uint16_t *)buf;
	const uint8_t subtype = FC_SUBTYPE(fc);
	const bool to_ds = FC_TO_DS(fc);
	const bool from_ds = FC_FROM_DS(fc);
	switch (type) {
		case WIFI_PKT_MGMT: {
			wifi_managment_hdr_t *wifi_managment_hdr = (wifi_managment_hdr_t *)buf;
			macFilter = isAddrEquel(wifi_managment_hdr->sa, addr2_filter) || isAddrEquel(wifi_managment_hdr->da, addr2_filter);
		} break;
		case WIFI_PKT_DATA: {
			if (!from_ds && !to_ds) {
				wifi_data_ibss_hdr_t *wifi_data_ibss_hdr = (wifi_data_ibss_hdr_t *)buf;
				macFilter = isAddrEquel(wifi_data_ibss_hdr->sa, addr2_filter); // || isAddrEquel(wifi_data_ibss_hdr->da, addr2_filter);
			} else if (from_ds && !to_ds) {
				wifi_data_from_ap_hdr_t *wifi_data_from_ap_hdr = (wifi_data_from_ap_hdr_t *)buf;
				macFilter = isAddrEquel(wifi_data_from_ap_hdr->sa, addr2_filter); // || isAddrEquel(wifi_data_from_ap_hdr->da, addr2_filter);
			} else if (!from_ds && to_ds) {
				wifi_data_to_ap_hdr_t *wifi_data_to_ap_hdr = (wifi_data_to_ap_hdr_t *)buf;
				macFilter = isAddrEquel(wifi_data_to_ap_hdr->sa, addr2_filter); // || isAddrEquel(wifi_data_to_ap_hdr->da, addr2_filter);
			} else {
				wifi_data_wds_hdr_t *wifi_data_wds_hdr = (wifi_data_wds_hdr_t *)buf;
				macFilter = isAddrEquel(wifi_data_wds_hdr->ta, addr2_filter); // || isAddrEquel(wifi_data_wds_hdr->da, addr2_filter);
			}
		} break;
		case WIFI_PKT_CTRL: {
			switch (subtype) {
				case WIFI_PKT_CTRL_SUBTYPE_BAR: {
					wifi_ctrl_ba_hdr_t *wifi_ctrl_ba_hdr = (wifi_ctrl_ba_hdr_t *)buf;
					macFilter = isAddrEquel(wifi_ctrl_ba_hdr->ta, addr2_filter); // || isAddrEquel(wifi_ctrl_ba_hdr->ra, addr2_filter);
				} break;
				case WIFI_PKT_CTRL_SUBTYPE_BA: {
					wifi_ctrl_ba_hdr_t *wifi_ctrl_ba_hdr = (wifi_ctrl_ba_hdr_t *)buf;
					macFilter = isAddrEquel(wifi_ctrl_ba_hdr->ta, addr2_filter); // || isAddrEquel(wifi_ctrl_ba_hdr->ta, addr2_filter);
				} break;
				case WIFI_PKT_CTRL_SUBTYPE_PS_POLL: {
					wifi_ctrl_ps_poll_hdr_t *wifi_ctrl_ps_poll_hdr = (wifi_ctrl_ps_poll_hdr_t *)buf;
					macFilter = isAddrEquel(wifi_ctrl_ps_poll_hdr->ta, addr2_filter);
				} break;
				case WIFI_PKT_CTRL_SUBTYPE_RTS: {
					wifi_ctrl_rts_hdr_t *wifi_ctrl_rts_hdr = (wifi_ctrl_rts_hdr_t *)buf;
					macFilter = isAddrEquel(wifi_ctrl_rts_hdr->ta, addr2_filter); //|| isAddrEquel(wifi_ctrl_rts_hdr->ra, addr2_filter);
				} break;
				case WIFI_PKT_CTRL_SUBTYPE_CTS: {
					wifi_ctrl_cts_hdr_t *wifi_ctrl_cts_hdr = (wifi_ctrl_cts_hdr_t *)buf;
					macFilter = isAddrEquel(wifi_ctrl_cts_hdr->ra, addr2_filter);
				} break;
				case WIFI_PKT_CTRL_SUBTYPE_ACK: {
					wifi_ctrl_ack_hdr_t *wifi_ctrl_ack_hdr = (wifi_ctrl_ack_hdr_t *)buf;
					macFilter = isAddrEquel(wifi_ctrl_ack_hdr->ra, addr2_filter);
				} break;
				default:
					break;
			}
		} break;
		default:
			break;
	}
	return macFilter;
}

static esp_err_t sniff_packet_start(pcap_hdr_t header) {
	esp_err_t ret = ESP_OK;
	size_t real_write = sniffer_write(&header, sizeof(header));
	if (!real_write) {
		sniffer_stop();
		ret = ESP_ERR_INVALID_STATE;
	}
	return ret;
}

static esp_err_t sniffer_packet_capture(wifi_promiscuous_pkt_type_t type, pcap_rec_t *pcap_rec) {
	esp_err_t esp_err = ESP_OK;
	size_t real_write = 0;
	real_write = sniffer_write(pcap_rec, sizeof(pcap_rec_t) - sizeof(pcap_rec->buf));
	if (!real_write) {
		esp_err = ESP_ERR_INVALID_STATE;
	} else {
		size_t sz = pcap_rec->pcap_rec_hdr.incl_len - pcap_rec->ieee80211_radiotap_header.it_len;
		real_write = sniffer_write(pcap_rec->buf, sz);
		if (!real_write) {
			esp_err = ESP_ERR_INVALID_STATE;
		} else {
			esp_err = ESP_OK;
		}
	}
	if (esp_err != ESP_OK) {
		sniffer_stop();
	}
	return esp_err;
}

static struct timeval current_time = {
	.tv_sec = 0,
	0,
};
static uint64_t timer = 0;
uint64_t sniffer_get_time() {
	return (uint64_t)current_time.tv_sec * 1000 + (uint64_t)current_time.tv_usec / 1000;
}

struct timeval to_timeval(int64_t epoch) {
	struct timeval tv = {};
	tv.tv_sec = epoch / 1000;
	tv.tv_usec = ((epoch % 1000) * 1000);
	return tv;
}

void sniffer_set_time(uint64_t t) {
	current_time = to_timeval(t);
	timer = esp_timer_get_time();
}

static void wifi_sniffer_cb(void *recv_buf, wifi_promiscuous_pkt_type_t type) {
	wifi_promiscuous_pkt_t *sniffer = (wifi_promiscuous_pkt_t *)recv_buf;

	if (type != WIFI_PKT_MISC && !sniffer->rx_ctrl.rx_state && sniffer->rx_ctrl.rssi >= snf_rt.rssi_th) {
		bool b = packet_mac_filter(type, snf_rt.addr2_filter, sniffer->payload);
		if (b) {
			pcap_rec_t pcap_rec = capture_create_pcap_record(sniffer);
			// int64_t ts_micro=sniffer->rx_ctrl.timestamp;//this is tied to when esp_wifi_start is called
			struct timeval tt = to_timeval((esp_timer_get_time() - timer) / 1000);
			pcap_rec.pcap_rec_hdr.ts_sec = current_time.tv_sec + tt.tv_sec;
			pcap_rec.pcap_rec_hdr.ts_usec = current_time.tv_usec + tt.tv_usec;
			sniffer_packet_capture(type, &pcap_rec);
		}
	}
}

esp_err_t sniffer_stop() {
	snf_rt.run = false;
	ESP_ERROR_RETURN(esp_wifi_set_promiscuous(snf_rt.run), TAG, "");
	ESP_LOGD(TAG, "stop promiscuous ok");
	return ESP_OK;
}

////////RSSI
#define RSSI_FILTER_KEY "rssi"
esp_err_t sniffer_load_rssi_filter(int32_t *rssi) {
	esp_err_t esp_err = nvs_get_num32i(NS, RSSI_FILTER_KEY, rssi, SNIFFER_DEFAULT_RSSI);
	return esp_err;
}

esp_err_t sniffer_save_rssi_filter(int value) {
	int32_t prev_value = 0;
	if (sniffer_load_rssi_filter(&prev_value) == ESP_OK) {
		if (prev_value != value) {
			ESP_LOGI(TAG, "Saving %s %d", RSSI_FILTER_KEY, value);
			return nvs_set_num32i(NS, RSSI_FILTER_KEY, value);
		} else {
			return ESP_OK;
		}
	} else {
		ESP_LOGW(TAG, "Failed to load previous %s,saving", RSSI_FILTER_KEY);
		return nvs_set_num32i(NS, RSSI_FILTER_KEY, value);
	}
}

void sniffer_rssi_filter(int rssi) {
	snf_rt.rssi_th = rssi;
	sniffer_save_rssi_filter(rssi);
}

int32_t sniffer_rssi() {
	int32_t value = 0;
	if (sniffer_load_rssi_filter(&value) == ESP_OK) {
		return value;
	} else {
		ESP_LOGE(TAG, "Problem getting rssi");
		return 0;
	}
}

////////FRAME_TYPE
#define FRAME_TYPE_FILTER_KEY "frame_type"
static esp_err_t sniffer_load_frame_type_filter(int32_t *channel) {
	esp_err_t esp_err = nvs_get_num32i(NS, FRAME_TYPE_FILTER_KEY, channel, WIFI_PROMIS_FILTER_MASK_ALL);
	return esp_err;
}

static esp_err_t sniffer_save_frame_type_filter(const uint32_t value) {
	int32_t prev_value = 0;
	if (sniffer_load_frame_type_filter(&prev_value) == ESP_OK) {
		if (prev_value != value) {
			ESP_LOGI(TAG, "Saving %s %" PRIu32, FRAME_TYPE_FILTER_KEY, value);
			return nvs_set_num32i(NS, FRAME_TYPE_FILTER_KEY, value);
		} else {
			return ESP_OK;
		}
	} else {
		ESP_LOGW(TAG, "Failed to load previous %s,saving", FRAME_TYPE_FILTER_KEY);
		return nvs_set_num32i(NS, FRAME_TYPE_FILTER_KEY, value);
	}
}

esp_err_t sniffer_frame_type_filter(uint32_t filter) {

	wifi_promiscuous_filter_t wifi_filter = {.filter_mask = filter};
	ESP_ERROR_RETURN(esp_wifi_set_promiscuous_filter(&wifi_filter), TAG, "");
	ESP_LOGI(TAG, "Frame Filter %" PRIu32, wifi_filter.filter_mask);

	wifi_promiscuous_filter_t wifi_promiscuous_ctrl_filter = {.filter_mask = (filter & WIFI_PROMIS_FILTER_MASK_CTRL) ? WIFI_PROMIS_CTRL_FILTER_MASK_ALL : 0};
	ESP_ERROR_RETURN(esp_wifi_set_promiscuous_ctrl_filter(&wifi_promiscuous_ctrl_filter), TAG, "");
	ESP_LOGI(TAG, "Frame Control Filter %" PRIu32, wifi_promiscuous_ctrl_filter.filter_mask);

	sniffer_save_frame_type_filter(filter);
	return ESP_OK;
}

esp_err_t sniffer_frame_type(char result[]) {
	wifi_promiscuous_filter_t filter = {0};
	esp_err_t esp_err = esp_wifi_get_promiscuous_filter(&filter);
	if (esp_err == ESP_OK) {
		for (int i = 0; i < SNIFFER_WLAN_FILTER_MAX; i++) {
			if (filter.filter_mask & wifi_filter_hash_table[i].filter_val) {
				size_t max = MAX_RESULT_FRAME_LEN - strlen(result) - 1;
				if (strlen(result) > 0) {
					strncat(result, ",", max);
				}
				strncat(result, wifi_filter_hash_table[i].filter_name, max);
			}
		}
	}
	return esp_err;
}

////////CHANNEL
#define CHANNEL_FILTER_KEY "channel"
static esp_err_t sniffer_load_channel_filter(int32_t *channel) {
	esp_err_t esp_err = nvs_get_num32i(NS, CHANNEL_FILTER_KEY, channel, SNIFFER_DEFAULT_CHANNEL);
	return esp_err;
}

static esp_err_t sniffer_save_channel_filter(const uint32_t value) {
	int32_t prev_value = 0;
	if (sniffer_load_channel_filter(&prev_value) == ESP_OK) {
		if (prev_value != value) {
			ESP_LOGI(TAG, "Saving %s %" PRIu32, CHANNEL_FILTER_KEY, value);
			return nvs_set_num32i(NS, CHANNEL_FILTER_KEY, value);
		} else {
			return ESP_OK;
		}
	} else {
		ESP_LOGW(TAG, "Failed to load previous %s,saving", CHANNEL_FILTER_KEY);
		return nvs_set_num32i(NS, CHANNEL_FILTER_KEY, value);
	}
}

esp_err_t sniffer_channel_filter(uint32_t channel) {
	ESP_ERROR_RETURN(esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE), TAG, "");
	sniffer_save_channel_filter(channel);
	return ESP_OK;
}

uint32_t sniffer_channel() {
	int32_t value = 0;
	if (sniffer_load_channel_filter(&value) == ESP_OK) {
		return value;
	} else {
		ESP_LOGE(TAG, "Problem getting channel");
		return 0;
	}
}

///////////MAC
#define MAC_FILTER_KEY "mac"
static esp_err_t sniffer_load_mac_filter(char *mac, size_t *sz) {
	esp_err_t esp_err = nvs_get_string(NS, MAC_FILTER_KEY, mac, sz, SNIFFER_DEFAULT_MAC, sizeof(SNIFFER_DEFAULT_MAC));
	if (esp_err == ESP_OK) {
		if (*sz > 0) {
			*sz = *sz - 1;
		}
	}
	return esp_err;
}

void tohex(addrFilter_t addrFilter, char *stringbuf, size_t sz) {
	char *buf2 = stringbuf;
	char *endofbuf = stringbuf + sz;
	for (int i = 0; i < addrFilter.size; i++) {
		/* i use 5 here since we are going to add at most
		   3 chars, need a space for the end '\n' and need
		   a null terminator */
		if (buf2 + 5 < endofbuf) {
			buf2 += sprintf(buf2, "%02X", addrFilter.addr[i]);
		}
	}
	buf2 += sprintf(buf2, "%s", "");
}

static int hex_to_decimal(char hexChar) {
	if (hexChar >= '0' && hexChar <= '9')
		return hexChar - '0';
	else if (hexChar >= 'a' && hexChar <= 'f')
		return hexChar - 'a' + 10;
	else if (hexChar >= 'A' && hexChar <= 'F')
		return hexChar - 'A' + 10;
	else
		return -1; // Invalid character
}

static int hex_to_byte_array(const char *hexArray, size_t hexLength, uint8_t byteArray[]) {
	size_t i;
	for (i = 0; i < hexLength / 2; i++) {
		int highNibble = hex_to_decimal(hexArray[i * 2]);
		int lowNibble = hex_to_decimal(hexArray[i * 2 + 1]);

		if (highNibble == -1 || lowNibble == -1) {
			ESP_LOGE(TAG, "Invalid hexadecimal character");
			return -1;
		} else {
			byteArray[i] = (unsigned char)((highNibble << 4) | lowNibble);
		}
	}
	return i;
}

static esp_err_t sniffer_save_mac_filter(const char *value) {
	char *prev_value = "";
	size_t sz = 0;
	if (sniffer_load_mac_filter(prev_value, &sz) == ESP_OK) {
		size_t cur_sz = strlen(value);
		int diff = strncmp(prev_value, value, sz);
		ESP_LOGI(TAG, " curr: %d,  prev: %d , diff: %d", cur_sz, sz, diff);
		if (cur_sz != sz || diff != 0) {
			ESP_LOGI(TAG, "Saving %s %s", MAC_FILTER_KEY, value);
			return nvs_set_string(NS, MAC_FILTER_KEY, value);
		} else {
			return ESP_OK;
		}
	} else {
		ESP_LOGW(TAG, "Failed to load previous %s,saving", MAC_FILTER_KEY);
		return nvs_set_string(NS, MAC_FILTER_KEY, value);
	}
}

sniffer_mac_filter_ret_t sniffer_filter_mac(const char *mac, const size_t readBytes) {
	addrFilter_t *addrFilter = &snf_rt.addr2_filter;
	if (readBytes > 0) {
		if (readBytes % 2 == 0) {
			int t = hex_to_byte_array(mac, readBytes, snf_rt.addr2_filter.addr);
			if (t >= 0) {
				addrFilter->size = t;
				ESP_LOGI(TAG, "using mac filter %s", mac);
				sniffer_save_mac_filter(mac);
				return MAC_OK;
			} else {
				return MAC_FAIL;
			}

		} else if (readBytes > 12) {
			return MAC_TOO_LONG;
		} else {
			return MAC_NOT_EVEN;
		}
	} else {

		int t = hex_to_byte_array(mac, readBytes, snf_rt.addr2_filter.addr);
		if (t >= 0) {
			addrFilter->size = t;
			ESP_LOGI(TAG, "using mac filter %s", mac);
			sniffer_save_mac_filter(mac);
			return MAC_OK;
		} else {
			return MAC_FAIL;
		}
	}
}

addrFilter_t sniffer_mac() {
	return snf_rt.addr2_filter;
}

static void sniffer_set_channel_filter() {
	int32_t value = SNIFFER_DEFAULT_CHANNEL;
	sniffer_load_channel_filter(&value);
	sniffer_channel_filter(value);
}

static void sniffer_set_rssi_filter() {
	int32_t value = SNIFFER_DEFAULT_RSSI;
	sniffer_load_rssi_filter(&value);
	sniffer_rssi_filter(value);
}

static void sniffer_set_frame_type_filter() {
	int32_t value = SNIFFER_DEFAULT_FRAME_TYPE_FILTER;
	sniffer_load_frame_type_filter(&value);
	sniffer_frame_type_filter(value);
}

static void sniffer_set_mac_filter() {
	char *value = SNIFFER_DEFAULT_MAC;
	size_t sz = 0;
	sniffer_load_mac_filter(value, &sz);
	ESP_LOGI(TAG, "filter len %d ", sz);
	sniffer_filter_mac(value, sz);
}

static void sniffer_set_filters() {
	sniffer_set_rssi_filter();
	sniffer_set_frame_type_filter();
	sniffer_set_mac_filter();
	sniffer_set_channel_filter();
}

esp_err_t sniffer_start() {
	snf_rt.run = true;
	pcap_hdr_t header = capture_create_header();
	ESP_ERROR_RETURN(sniff_packet_start(header), TAG, "");

	sniffer_set_filters();

	ESP_ERROR_RETURN(esp_wifi_set_promiscuous(snf_rt.run), TAG, "");
	ESP_LOGD(TAG, "start WiFi promiscuous ok");
	return ESP_OK;
}

void init_sniffer(sniffer_write_cb_t sniffer_write_cb) {
	snf_rt.sniffer_write_cb = sniffer_write_cb;

	ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));

	sniffer_set_filters();
}

static void printfln(const char *fmt, ...) {
	char buffer[200] = "";
	va_list argptr;
	va_start(argptr, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, argptr);
	va_end(argptr);

	printf("%s\n", buffer);
}

static struct {
	struct arg_str *mac;
	struct arg_str *filter;
	struct arg_int *channel;
	struct arg_int *rssi;
	struct arg_str *time;
	struct arg_end *end;
} sniffer_args;

static int do_sniffer_cmd(int argc, char **argv) {
	int nerrors = arg_parse(argc, argv, (void **)&sniffer_args);

	if (nerrors != 0) {
		arg_print_errors(stderr, sniffer_args.end, argv[0]);
		return 0;
	}
	if (sniffer_args.channel->count > 0) {
		int *ch = sniffer_args.channel->ival;
		sniffer_channel_filter(*ch);
	}
	if (sniffer_args.rssi->count > 0) {
		int *rssi = sniffer_args.rssi->ival;
		sniffer_rssi_filter(*rssi);
	}

	if (sniffer_args.mac->count > 0) {
		const char *key = sniffer_args.mac->sval[0];
		unsigned int sz = strlen(key);
		sniffer_mac_filter_ret_t ret = sniffer_filter_mac(key, sz);
		switch (ret) {
			case MAC_OK:
				printfln("Filtering  %s ", key);
				break;
			case MAC_TOO_LONG:
				printfln("Argument exceeds 12 bytes %s ", key);
				break;
			case MAC_NOT_EVEN:
				printfln("Argument must be even in length %s ", key);
				break;
			case MAC_FAIL:
				printfln("Bad MAC ");
				break;
			default:
				//		printfln("Clearing filter ");
				break;
		}
	}

	if (sniffer_args.filter->count) {
		uint32_t filter = 0;
		for (int i = 0; i < sniffer_args.filter->count; i++) {
			filter += search_wifi_filter_hashtable(sniffer_args.filter->sval[i]);
		}
		/* When filter conditions are all wrong */
		if (filter == 0) {
			filter = WIFI_PROMIS_FILTER_MASK_ALL;
		}
		sniffer_frame_type_filter(filter);
	}

	if (sniffer_args.time->count) {
		const char *key = sniffer_args.time->sval[0];
		// uint32_t len = strlen(key);
		int64_t t = atoll(key);
		sniffer_set_time(t);
	}
	return 0;
}

void register_sniffer_cmd(void) {
	sniffer_args.mac = arg_strn("s", "mac", "<string>", 0, 1, "filter mac");
	sniffer_args.filter = arg_strn("F", "filter", "<mgmt|data|ctrl|misc|mpdu|ampdu|fcsfail>", 0, 7, "filter parameters");
	sniffer_args.channel = arg_int0("c", "channel", "<channel>", "communication channel to use");
	sniffer_args.rssi = arg_int0("r", "rssi", "<rssi>", "rssi threshold");
	sniffer_args.time = arg_str0("t", "time", "time", "set the timestamp to be sent to wireshark");
	sniffer_args.end = arg_end(1);
	const esp_console_cmd_t sniffer_cmd = {
		.command = "sniffer",
		.help = "Capture specific packet and store in pcap format",
		.hint = NULL,
		.func = &do_sniffer_cmd,
		.argtable = &sniffer_args};
	ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_cmd));

	create_wifi_filter_hashtable();
}
