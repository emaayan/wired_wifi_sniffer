#ifndef UTILS_LIB
#define UTILS_LIB

#include "esp_check.h"

#define ESP_ERROR_RETURN(x, log_tag, format, ...)                                                                                                           \
	do {                                                                                                                                                    \
		esp_err_t err_rc_ = (x);                                                                                                                            \
		if (unlikely(err_rc_ != ESP_OK)) {                                                                                                                  \
			ESP_LOGE(log_tag, "%s:%d , %s:%s - %s(%#x) : " format, __FILE__, __LINE__, __FUNCTION__, #x, esp_err_to_name(err_rc_), err_rc_, ##__VA_ARGS__); \
			return err_rc_;                                                                                                                                 \
		}                                                                                                                                                   \
	} while (0)
#endif
