#ifndef E6048912_5A40_4391_8553_587FB73E6A4C
#define E6048912_5A40_4391_8553_587FB73E6A4C

//#include "sdkconfig.h"
#include <esp_wifi_types.h>
#include <inttypes.h>
#include <stdio.h>


typedef struct pcap_capture_header {
	const uint32_t magic_number;
	const uint16_t version_major;
	const uint16_t version_minor;
	const uint32_t thiszone;					 /* GMT to local correction */
	const uint32_t sigfigs;						 /* accuracy of timestamps */
	const uint32_t snaplen;						 /* max length of captured packets, in octets */
	const uint32_t network; /* data link type */ // https://www.tcpdump.org/linktypes.html
} pcap_hdr_t;

typedef struct pcap_rec_header {
	uint32_t ts_sec;   /* timestamp seconds */
	uint32_t ts_usec;  /* timestamp microseconds */
	uint32_t incl_len; /* number of octets of packet saved in file */
	uint32_t orig_len; /* actual length of packet */
} pcap_rec_hdr_t;



typedef struct { // https://www.radiotap.org/
	uint8_t it_version; /* set to 0 */
	uint8_t it_pad;
	uint16_t it_len;	 /* entire length */
	uint32_t it_present; /* fields present */
} __attribute__((__packed__)) ieee80211_radiotap_header_t;


typedef struct {// https://www.radiotap.org/fields/XChannel
	uint32_t flags;
	uint16_t freq;
	uint8_t channel;
	uint8_t maxPower;
} __attribute__((packed)) r_tapdata_channel_t;

#define IT_PRESENT 0b00000000000001000000100001100000

typedef struct { // https://www.radiotap.org/fields/
	int8_t signal;	 // 5 https://www.radiotap.org/fields/Antenna%20signal.html
	int8_t noise;	 //  6 https://www.radiotap.org/fields/Antenna%20noise.html
	uint8_t antenna; // 11 https://www.radiotap.org/fields/Antenna.html
	uint8_t pad_for_channel;
	r_tapdata_channel_t r_tapdata_channel; // 18 https://www.radiotap.org/fields/XChannel
										   // EVERY CHANGE IN THIS STRUCUCTURE MUST BE REFLECTED IN IT_PRESET BIT FIELD
} __attribute__((packed)) r_tapdata_t;



typedef struct pcap_rec {
	pcap_rec_hdr_t pcap_rec_hdr;
	ieee80211_radiotap_header_t ieee80211_radiotap_header;
	r_tapdata_t r_tapdata;
	void *buf; //[MAX_LENGTH];
			   // uint8_t buf[MAX_LENGTH];
} __attribute__((packed)) pcap_rec_t;

typedef int (*on_start_capture_cb)(pcap_hdr_t pcap_hdr);
typedef int (*on_capture_cb)(pcap_rec_t pcaprec, size_t total_size);
void capture_set_cb(on_start_capture_cb on_start_capture_cb, on_capture_cb on_capture_cb);
void capture_start();
pcap_hdr_t capture_create_header();
int capture_on_send(pcap_rec_t pcap_rec);
pcap_rec_t capture_create_pcap_record(wifi_promiscuous_pkt_t *pkt);

#endif /* E6048912_5A40_4391_8553_587FB73E6A4C */
