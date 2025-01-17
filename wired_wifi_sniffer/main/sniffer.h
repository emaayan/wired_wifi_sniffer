/* cmd_sniffer example — declarations of command registration functions.

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#include "esp_eth_driver.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FC_SUBTYPE(fc)      (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc)        (((fc) >> 8) & 0x1)
#define FC_FROM_DS(fc)      (((fc) >> 9) & 0x1)

// Management Subtypes
#define WIFI_PKT_MGMT_SUBTYPE_ASSOC_REQ      0x0 // 0000
#define WIFI_PKT_MGMT_SUBTYPE_ASSOC_RESP     0x1 // 0001
#define WIFI_PKT_MGMT_SUBTYPE_REASSOC_REQ    0x2 // 0010
#define WIFI_PKT_MGMT_SUBTYPE_REASSOC_RESP   0x3 // 0011
#define WIFI_PKT_MGMT_SUBTYPE_PROBE_REQ      0x4 // 0100
#define WIFI_PKT_MGMT_SUBTYPE_PROBE_RESP     0x5 // 0101
#define WIFI_PKT_MGMT_SUBTYPE_TIMING_ADV     0x6 // 0110
#define WIFI_PKT_MGMT_SUBTYPE_BEACON         0x8 // 1000
#define WIFI_PKT_MGMT_SUBTYPE_ATIM           0x9 // 1001
#define WIFI_PKT_MGMT_SUBTYPE_DISASSOC       0xA // 1010
#define WIFI_PKT_MGMT_SUBTYPE_AUTH           0xB // 1011
#define WIFI_PKT_MGMT_SUBTYPE_DEAUTH         0xC // 1100
#define WIFI_PKT_MGMT_SUBTYPE_ACTION         0xD // 1101
#define WIFI_PKT_MGMT_SUBTYPE_ACTION_NOACK   0xE // 1110

// Control Subtypes
#define WIFI_PKT_CTRL_SUBTYPE_TRIGGER        0x2
#define WIFI_PKT_CTRL_SUBTYPE_WRAPPER        0x7
#define WIFI_PKT_CTRL_SUBTYPE_BAR            0x8
#define WIFI_PKT_CTRL_SUBTYPE_BA             0x9
#define WIFI_PKT_CTRL_SUBTYPE_PS_POLL        0xA
#define WIFI_PKT_CTRL_SUBTYPE_RTS            0xB
#define WIFI_PKT_CTRL_SUBTYPE_CTS            0xC
#define WIFI_PKT_CTRL_SUBTYPE_ACK            0xD
#define WIFI_PKT_CTRL_SUBTYPE_CF_END         0xE
#define WIFI_PKT_CTRL_SUBTYPE_CF_END_ACK     0xF

// Data Subtypes
#define WIFI_PKT_DATA_SUBTYPE_DATA           0x0
#define WIFI_PKT_DATA_SUBTYPE_DATA_CF_ACK    0x1
#define WIFI_PKT_DATA_SUBTYPE_DATA_CF_POLL   0x2
#define WIFI_PKT_DATA_SUBTYPE_DATA_CF_ACK_POLL 0x3
#define WIFI_PKT_DATA_SUBTYPE_NULL           0x4
#define WIFI_PKT_DATA_SUBTYPE_CF_ACK         0x5
#define WIFI_PKT_DATA_SUBTYPE_CF_POLL        0x6
#define WIFI_PKT_DATA_SUBTYPE_CF_ACK_POLL    0x7
#define WIFI_PKT_DATA_SUBTYPE_QOS_DATA       0x8
#define WIFI_PKT_DATA_SUBTYPE_QOS_DATA_CF_ACK 0x9
#define WIFI_PKT_DATA_SUBTYPE_QOS_DATA_CF_POLL 0xA
#define WIFI_PKT_DATA_SUBTYPE_QOS_DATA_CF_ACK_POLL 0xB
#define WIFI_PKT_DATA_SUBTYPE_QOS_NULL       0xC
#define WIFI_PKT_DATA_SUBTYPE_QOS_CF_POLL    0xE
#define WIFI_PKT_DATA_SUBTYPE_QOS_CF_ACK_POLL 0xF

//https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html

typedef struct
{
	int16_t fctl;     // frame control
    int16_t duration; // duration id	
} __attribute__((packed)) wifi_base_hdr_t;

/////Managment
typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t da[6];  
    uint8_t sa[6];  
    uint8_t bssid[6];    
    int16_t seqctl;   
    uint8_t *payload; 
} __attribute__((packed)) wifi_managment_hdr_t;


/////Data
typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t da[6];    
    uint8_t sa[6];    
    uint8_t bssid[6];   
    int16_t seqctl;  
    uint8_t *payload; 
} __attribute__((packed)) wifi_data_ibss_hdr_t;

typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t da[6]; //RA
    uint8_t ta[6]; //BSSID    
    uint8_t sa[6];   
    int16_t seqctl;  
    uint8_t *payload; 
} __attribute__((packed)) wifi_data_from_ap_hdr_t;

typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t ra[6]; //BSSID
    uint8_t sa[6]; //TA    
    uint8_t da[6];   
    int16_t seqctl;  
    uint8_t *payload; 
} __attribute__((packed)) wifi_data_to_ap_hdr_t;

typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t ra[6]; 
    uint8_t ta[6];     
    uint8_t da[6];   
    int16_t seqctl;
    uint8_t sa[6];  
    uint8_t *payload; 
} __attribute__((packed)) wifi_data_wds_hdr_t;


/////Ctrl
typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t ra[6]; 
    uint8_t ta[6];         
} __attribute__((packed)) wifi_ctrl_rts_hdr_t;

typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t ra[6];             
} __attribute__((packed)) wifi_ctrl_cts_hdr_t;


typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t ra[6];             
} __attribute__((packed)) wifi_ctrl_ack_hdr_t;

typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t bssid[6];             
    uint8_t ta[6];
} __attribute__((packed)) wifi_ctrl_ps_poll_hdr_t;

typedef struct
{
    wifi_base_hdr_t wifi_base_hdr;    
    uint8_t ra[6];             
    uint8_t ta[6];
} __attribute__((packed)) wifi_ctrl_ba_hdr_t;//bar



/**
 * @brief WLAN Sniffer Filter
 *
 */
typedef enum {
    SNIFFER_WLAN_FILTER_MGMT = 0, /*!< MGMT */
    SNIFFER_WLAN_FILTER_CTRL,     /*!< CTRL */
    SNIFFER_WLAN_FILTER_DATA,     /*!< DATA */
    SNIFFER_WLAN_FILTER_MISC,     /*!< MISC */
    SNIFFER_WLAN_FILTER_MPDU,     /*!< MPDU */
    SNIFFER_WLAN_FILTER_AMPDU,    /*!< AMPDU */
    SNIFFER_WLAN_FILTER_FCSFAIL,  /*!< When this bit is set, the hardware will receive packets for which frame check sequence failed */
    SNIFFER_WLAN_FILTER_ALL,    
    SNIFFER_WLAN_FILTER_MAX
} sniffer_wlan_filter_t;

void init_sniffer(); 
void register_sniffer_cmd(void);
esp_err_t sniffer_start(int sock);
esp_err_t sniffer_stop(int sock);


esp_err_t  sniffer_channel_filter(uint32_t channel);
uint32_t  sniffer_channel();

typedef enum sniffer_mac_filter_ret{
	MAC_OK,MAC_TOO_LONG,MAC_NOT_EVEN,MAC_FAIL
} sniffer_mac_filter_ret_t;


typedef struct
{
    uint8_t addr[6];
    size_t size;
} addrFilter_t;

sniffer_mac_filter_ret_t sniffer_filter_mac(const char* mac, const size_t readBytes);
uint32_t search_wifi_filter_hashtable(const char *key);
esp_err_t sniffer_frame_type_filter(uint32_t filter);

#define MAX_RESULT_FRAME_LEN 256
esp_err_t sniffer_frame_type(char result[]);

void sniffer_rssi_filter(int rssi);
int32_t sniffer_rssi();

addrFilter_t sniffer_mac();
void sniffer_set_time(uint64_t t);
uint64_t sniffer_get_time(); 
#ifdef __cplusplus
}
#endif
