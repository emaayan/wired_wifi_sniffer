#include <config_http_server.h>

#include "esp_vfs.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_app_desc.h"

#include <complex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "sniffer.h"
#include "cJSON.h"

static const char *TAG = "config_http_server";
#define CONFIG_HTTP_QUERY_KEY_MAX_LEN (64)
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + 128)
#define SCRATCH_BUFSIZE (256)


static config_http_server_prm_t _config_http_server_prm;
static httpd_handle_t server;
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

	char filepath[FILE_PATH_MAX] ="";
	snprintf(filepath,sizeof(filepath),"%s%s", _config_http_server_prm.rootdir, "index.html");
	 
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

	if (*ep != 0) {
		return 0;
	}

	*i = (int)l;
	return 1;
}




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


#define FAVICON_FILE "favicon.ico"
static esp_err_t favicon_get_handler(httpd_req_t *req) {
	char filepath[FILE_PATH_MAX] = "";	
	snprintf(filepath,sizeof(filepath),"%s%s", _config_http_server_prm.rootdir, FAVICON_FILE);
	
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
	.uri = "/"FAVICON_FILE,
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
	}else{
		
		
		 httpd_resp_set_type(req, "application/json");
		 cJSON *root = cJSON_CreateObject();
		 
		 const esp_app_desc_t *esp_app_desc = esp_app_get_description();	
		 char buffer[64] = "";
		 snprintf(buffer,sizeof(buffer),"%s",esp_app_desc->project_name);
		 cJSON_AddStringToObject(root, "version", buffer);		 
		 
		 char res[MAX_RESULT_FRAME_LEN] = {""};
	  	 sniffer_frame_type(res);
		 cJSON_AddStringToObject(root, "frameType", res);
		
		 addrFilter_t ad = sniffer_mac();
		 char mac[13] = "";
		 tohex(ad, mac, sizeof(mac));
	     cJSON_AddStringToObject(root, "mac" , mac);
	     
		 int32_t rssi = sniffer_rssi();					 	
    	 cJSON_AddNumberToObject(root, "rssi", rssi);
    	     	 
		 int32_t chanel = sniffer_channel();					 	
    	 cJSON_AddNumberToObject(root, "channel", chanel);    	 
    	 
    	 const char *resp = cJSON_Print(root);
	     httpd_resp_sendstr(req, resp);
	     free((void *)resp);
	     cJSON_Delete(root);
	     

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

void init_config_http_server(config_http_server_prm_t config_http_server_prm) {
	_config_http_server_prm = config_http_server_prm;
	server = start_webserver();
}
