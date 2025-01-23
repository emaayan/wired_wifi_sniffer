#include "ESP_LOG.h"
#include "led_lib.h"
const char *TAG = "LedMock";
void led_init(int pin) {
	ESP_LOGW(TAG, "init led Mock!");
}

void led_set(bool s_led_state) {
	ESP_LOGI(TAG, "Got led state %d ", s_led_state);
}