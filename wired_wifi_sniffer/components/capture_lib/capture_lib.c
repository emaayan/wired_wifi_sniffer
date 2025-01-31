#include <capture_lib.h>

// https://wiki.wireshark.org/Development/LibpcapFileFormat

static const char *TAG = "CaptureLib";
#define MAX_LENGTH 1350																																				   // CONFIG_SNIFFER_SNAP_LEN // 2500
static pcap_hdr_t pcap_hdr = {.magic_number = 0xa1b2c3d4, .version_major = 2, .version_minor = 4, .thiszone = 0, .sigfigs = 0, .snaplen = MAX_LENGTH, .network = 127}; // LINKTYPE_IEEE802_11_RADIOTAP
static ieee80211_radiotap_header_t ieee80211_radiotap_header = {.it_version = 0, .it_len = sizeof(ieee80211_radiotap_header_t) + sizeof(r_tapdata_t), .it_present = IT_PRESENT};

pcap_hdr_t capture_create_header() {
	return pcap_hdr;
}

pcap_rec_t capture_create_pcap_record(wifi_promiscuous_pkt_t *pkt) {
	wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
	uint8_t *payload = pkt->payload;

	uint32_t sig_packetLength = ctrl.sig_len - 4; // MINUS FCS LENGTH
	uint32_t pack_len = sig_packetLength + ieee80211_radiotap_header.it_len;

	pcap_rec_t pcap_rec = {
		.pcap_rec_hdr = {
			.ts_sec = ctrl.timestamp / 1000000U,
			.ts_usec = ctrl.timestamp % 1000000U,
			.incl_len = pack_len > pcap_hdr.snaplen ? pcap_hdr.snaplen : pack_len,
			.orig_len = pack_len,
		},
		.ieee80211_radiotap_header = ieee80211_radiotap_header,
		.r_tapdata = {
			.noise = ctrl.noise_floor,
			.signal = ctrl.rssi,
			.antenna = ctrl.ant,
			.r_tapdata_channel.channel = ctrl.channel,
		},
		.buf = payload};
	return pcap_rec;
}
