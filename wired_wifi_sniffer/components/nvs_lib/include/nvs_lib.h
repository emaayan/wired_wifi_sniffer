#ifndef A62773E8_A184_46FE_BA12_A9DF240BEDCF
#define A62773E8_A184_46FE_BA12_A9DF240BEDCF

#include "nvs.h"
#define NS "SNIFFER"
esp_err_t nvs_set_num_from_string(const char *namespace, const char *key, nvs_type_t type, const char *str_value);
esp_err_t nvs_set_num32i(const char *namespace, const char *key, const int32_t value);
esp_err_t nvs_get_num32i(const char *namespace, const char *key, int32_t *value, const int32_t def_value);
esp_err_t nvs_get_num(const char *namespace, const char *key, nvs_type_t type, void *out_value, const void *def_value);
esp_err_t nvs_set_string(const char *namespace, const char *key, const char *str_value);
esp_err_t nvs_get_string(const char *namespace, const char *key, char *out_value,size_t * len, const char *def_value, size_t def_value_sz);
esp_err_t nvs_erase_value(const char *namespace, const char *key);
esp_err_t nvs_get_array(const char *namespace, const char *key, uint8_t  *value, size_t *sz, uint8_t  *def_value, size_t def_sz);
esp_err_t nvs_set_array(const char *namespace, const char *key, const uint8_t  *value, size_t sz);
void nvs_init_flash();
void nvs_bytes_to_hex(const uint8_t buf[], const size_t buf_sz, const char *delimiter, const size_t delimiter_sz, char *stringbuf, size_t sz);
#endif /* A62773E8_A184_46FE_BA12_A9DF240BEDCF */
