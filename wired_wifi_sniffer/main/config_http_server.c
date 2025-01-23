#include "esp_check.h"
#include "esp_err.h"
#include <complex.h>
#include <esp_http_server.h>
#include <stdint.h>
#include <stdlib.h>

#define CONFIG_HTTP_QUERY_KEY_MAX_LEN (64)
#include "esp_vfs.h"
#include <fcntl.h>
static const char *TAG = "config_http_server";
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + 128)
#define SCRATCH_BUFSIZE (256)
#include "sniffer.h"
//TODO: unified this macroc of MOUNT_POINT IN main
#define ROOT "/data/" 
static esp_err_t index_get_handler(httpd_req_t *req) {

	/* Get header value string length and allocate memory for length + 1,
	 * extra byte for null termination */
	size_t buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
	if (buf_len > 1) {
		char *buf = malloc(buf_len);
		ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
		if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
			ESP_LOGD(TAG, "Found header => Host: %s", buf);
		}
		free(buf);
	}

	char filepath[FILE_PATH_MAX] = ROOT "index.html";
	int fd = open(filepath, O_RDONLY, 0);
	if (fd == -1) {
		ESP_LOGE(TAG, "Failed to open file : %s", filepath);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
		return ESP_FAIL;
	}
	char chunk[SCRATCH_BUFSIZE] = {}; ////( char*) req->user_ctx;
	ssize_t read_bytes;
	esp_err_t ret = ESP_OK;
	do {
		/* Read file in chunks into the scratch buffer */
		read_bytes = read(fd, chunk, SCRATCH_BUFSIZE);
		if (read_bytes == -1) {
			ESP_LOGE(TAG, "Failed to read file : %s", filepath);
			ret = ESP_FAIL;
		} else if (read_bytes > 0) {
			/* Send the buffer contents as HTTP response chunk */
			ret = httpd_resp_send_chunk(req, chunk, read_bytes);
			if (ret != ESP_OK) {
				ESP_LOGE(TAG, "File sending failed!");
				break;
			}
		}
	} while (read_bytes > 0);

	close(fd);
	if (ret != ESP_OK) {
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
	}
	httpd_resp_sendstr_chunk(req, NULL);

	/* After sending the HTTP response the old HTTP request
	 * headers are lost. Check if HTTP request headers can be read now. */
	if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
		ESP_LOGD(TAG, "Request headers lost");
	}
	return ESP_OK;
}

static const httpd_uri_t index_page = {
	.uri = "/",
	.method = HTTP_GET,
	.handler = index_get_handler,
	.user_ctx = "",
};

int parseInt(const char *s, int *i) {
	char *ep;
	long l;

	l = strtol(s, &ep, 0);

	if (*ep != 0){
		return 0;
	}

	*i = (int)l;
	return 1;
}

static esp_err_t channel_get_handler(httpd_req_t *req) {
	int32_t ch = sniffer_channel();
	ESP_LOGI(TAG, "Getting channel %" PRIu32, ch);
	char ch_str[3];
	itoa(ch, ch_str, 10);
	esp_err_t ret = httpd_resp_send(req, ch_str, HTTPD_RESP_USE_STRLEN);
	;
	httpd_resp_send_chunk(req, NULL, 0);
	return ret;
}

static const httpd_uri_t channel = {
	.uri = "/api/channel",
	.method = HTTP_GET,
	.handler = channel_get_handler,
	.user_ctx = NULL,
};

static void tohex(addrFilter_t addrFilter, char *stringbuf, size_t sz) {
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
	buf2 += sprintf(buf2, "\n");
}

static esp_err_t mac_get_handler(httpd_req_t *req) {
	addrFilter_t ad = sniffer_mac();
	char mac[13] = {};
	tohex(ad, mac, sizeof(mac));
	ESP_LOGI(TAG, "Getting mac %s", mac);
	esp_err_t ret = httpd_resp_send(req, mac, HTTPD_RESP_USE_STRLEN);
	httpd_resp_send_chunk(req, NULL, 0);
	return ret;
}

static const httpd_uri_t mac = {
	.uri = "/api/macFilterAddress",
	.method = HTTP_GET,
	.handler = mac_get_handler,
	.user_ctx = NULL,
};

static esp_err_t frame_type_get_handler(httpd_req_t *req) {
	char res[MAX_RESULT_FRAME_LEN] = {""};
	esp_err_t erp_err = sniffer_frame_type(res);
	ESP_LOGI(TAG, "Getting frame type %s", res);
	ESP_ERROR_CHECK_WITHOUT_ABORT(erp_err);
	esp_err_t ret = httpd_resp_send(req, res, HTTPD_RESP_USE_STRLEN);
	httpd_resp_send_chunk(req, NULL, 0);
	return ret;
}

static const httpd_uri_t frameType = {
	.uri = "/api/frameType",
	.method = HTTP_GET,
	.handler = frame_type_get_handler,
	.user_ctx = NULL,
};

static esp_err_t rssi_get_handler(httpd_req_t *req) {
	int32_t rssi = sniffer_rssi();
	ESP_LOGI(TAG, "Getting RSSI %" PRIi32, rssi);
	char rssi_str[3];
	itoa(rssi, rssi_str, 10);
	esp_err_t ret = httpd_resp_send(req, rssi_str, HTTPD_RESP_USE_STRLEN);
	;
	httpd_resp_send_chunk(req, NULL, 0);
	return ret;
}

static const httpd_uri_t rssi = {
	.uri = "/api/rssi",
	.method = HTTP_GET,
	.handler = rssi_get_handler,
	.user_ctx = NULL,
};

static esp_err_t timer_get_handler(httpd_req_t *req) {

	size_t buf_len = httpd_req_get_url_query_len(req) + 1;
	esp_err_t ret = ESP_OK;
	if (buf_len > 1) {
		char *buf = malloc(buf_len);
		esp_err_t e = httpd_req_get_url_query_str(req, buf, buf_len);
		if (e == ESP_OK) {
			char param[CONFIG_HTTP_QUERY_KEY_MAX_LEN] = {0};
			if (httpd_query_key_value(buf, "value", param, sizeof(param)) == ESP_OK) {
				uint64_t t = atoll(param);
				sniffer_set_time(t);
				ESP_LOGI(TAG, "Time %" PRIu64, t);
				// ret= httpd_resp_send(req, NULL, HTTPD_RESP_USE_STRLEN);
			}
		}
		free(buf);
	} else {
		char buffer[32] = "";
		uint64_t current_time = sniffer_get_time();

		int r = snprintf(buffer, sizeof(buffer), "%lld", current_time);
		ESP_LOGI(TAG, "return %" PRIu64, current_time);
		ret = httpd_resp_send(req, buffer, r);
	}

	httpd_resp_send_chunk(req, NULL, 0);
	return ret;
}

static const httpd_uri_t timerset = {
	.uri = "/api/time",
	.method = HTTP_GET,
	.handler = timer_get_handler,
	.user_ctx = NULL,
};

static esp_err_t favicon_get_handler(httpd_req_t *req) {
	char filepath[FILE_PATH_MAX] = ROOT "favicon.ico";
	int fd = open(filepath, O_RDONLY, 0);
	if (fd == -1) {
		ESP_LOGE(TAG, "Failed to open file : %s", filepath);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
		return ESP_FAIL;
	}
	char chunk[SCRATCH_BUFSIZE] = {}; ////( char*) req->user_ctx;
	ssize_t read_bytes;
	esp_err_t ret = ESP_OK;
	do {
		/* Read file in chunks into the scratch buffer */
		read_bytes = read(fd, chunk, SCRATCH_BUFSIZE);
		if (read_bytes == -1) {
			ESP_LOGE(TAG, "Failed to read file : %s", filepath);
			ret = ESP_FAIL;
		} else if (read_bytes > 0) {
			/* Send the buffer contents as HTTP response chunk */
			ret = httpd_resp_send_chunk(req, chunk, read_bytes);
			if (ret != ESP_OK) {
				ESP_LOGE(TAG, "File sending failed!");
				break;
			}
		}
	} while (read_bytes > 0);

	close(fd);
	if (ret != ESP_OK) {
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
	}
	httpd_resp_sendstr_chunk(req, NULL);

	return ret;
}

static const httpd_uri_t favicon = {
	.uri = "/favicon.ico",
	.method = HTTP_GET,
	.handler = favicon_get_handler,
	.user_ctx = NULL,
};

static esp_err_t filter_get_handler(httpd_req_t *req) {
	char *buf;
	size_t buf_len;

	/* Get header value string length and allocate memory for length + 1,
	 * extra byte for null termination */
	buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
	if (buf_len > 1) {
		buf = malloc(buf_len);
		ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
		/* Copy null terminated value string into buffer */
		if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
			ESP_LOGD(TAG, "Found header => Host: %s", buf);
		}
		free(buf);
	}

	/* Read URL query string length and allocate memory for length + 1,
	 * extra byte for null termination */
	buf_len = httpd_req_get_url_query_len(req) + 1;
	if (buf_len > 1) {
		buf = malloc(buf_len);
		ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
		if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
			ESP_LOGD(TAG, "Found URL query %s", buf);
			char param[CONFIG_HTTP_QUERY_KEY_MAX_LEN] = {0};
			// char dec_param[CONFIG_HTTP_QUERY_KEY_MAX_LEN] = {0};

			if (httpd_query_key_value(buf, "frame", param, sizeof(param)) == ESP_OK) {
				ESP_LOGD(TAG, "Found URL query parameter: frame=%s", param);
				char *end, *r, *tok;

				r = end = strdup(param);
				assert(end != NULL);

				uint32_t filter = 0; // TODO:when  frame is all just filter for everyting
				while ((tok = strsep(&end, ",")) != NULL) {
					uint32_t f = search_wifi_filter_hashtable(tok);
					if (f) {
						filter |= f;
						ESP_LOGI(TAG, "Frame %s %" PRIu32, tok, f);
					}
				}
				if (filter != 0) {
					sniffer_frame_type_filter(filter);
				}
				free(r);
			}
			if (httpd_query_key_value(buf, "channel", param, sizeof(param)) == ESP_OK) {
				ESP_LOGD(TAG, "Found URL query parameter: channel=%s", param);
				int ch = 0;
				if (parseInt(param, &ch)) {
					sniffer_channel_filter(ch);
				} else {
					ESP_LOGE(TAG, "Failed to parse channel=%s", param);
				}
			}

			if (httpd_query_key_value(buf, "rssi", param, sizeof(param)) == ESP_OK) {
				ESP_LOGD(TAG, "Found URL query parameter: rssi=%s", param);
				int rssi = 0;
				if (parseInt(param, &rssi)) {
					sniffer_rssi_filter(rssi);
				} else {
					ESP_LOGE(TAG, "Failed to parse rssi=%s", param);
				}
			}
			if (httpd_query_key_value(buf, "macFilterAddress", param, sizeof(param)) == ESP_OK) {
				size_t sz = strlen(param);
				ESP_LOGI(TAG, "Found URL query parameter: mac=%s,  %d", param, sz);
				if (sniffer_filter_mac(param, sz) != MAC_OK) {
					ESP_LOGE(TAG, "Failed to filter mac=%s", param);
					httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Invalid MAC filter");
				}
			}
		}
		free(buf);
	}

	httpd_resp_send_chunk(req, NULL, 0);

	/* After sending the HTTP response the old HTTP request
	 * headers are lost. Check if HTTP request headers can be read now. */
	if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
		// ESP_LOGI(TAG, "Request headers lost");
	}
	return ESP_OK;
}

static const httpd_uri_t filter = {
	.uri = "/api/filter",
	.method = HTTP_GET,
	.handler = filter_get_handler,
	.user_ctx = NULL,
};

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err) {
	httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "NOT FOUND");
	return ESP_FAIL;
}

static httpd_handle_t start_webserver(void) {
	httpd_handle_t server = NULL;
	httpd_config_t config = HTTPD_DEFAULT_CONFIG();

	config.lru_purge_enable = true;

	ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
	if (httpd_start(&server, &config) == ESP_OK) {
		// Set URI handlers
		ESP_LOGI(TAG, "Registering URI handlers");
		httpd_register_uri_handler(server, &index_page);
		httpd_register_uri_handler(server, &favicon);
		httpd_register_uri_handler(server, &filter);
		httpd_register_uri_handler(server, &timerset);

		httpd_register_uri_handler(server, &frameType);
		httpd_register_uri_handler(server, &channel);
		httpd_register_uri_handler(server, &mac);
		httpd_register_uri_handler(server, &rssi);

		return server;
	}

	ESP_LOGI(TAG, "Error starting server!");
	return NULL;
}

/*
static esp_err_t stop_webserver(httpd_handle_t server) {
	// Stop the httpd server
	return httpd_stop(server);
}*/

static httpd_handle_t server;
void init_http_server(void) {
	server = start_webserver();
}
