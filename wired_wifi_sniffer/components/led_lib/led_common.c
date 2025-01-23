
#include "led_common.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
static const char *TAG = "LedCommon";

void led_init_default() {
	ESP_LOGI(TAG, "Init led %d", LED_PIN);
	led_init(LED_PIN);
}

void led_blink(uint16_t delay) {
	led_set(false);
	led_set(true);
	vTaskDelay(pdMS_TO_TICKS(delay));
	led_set(false);
}

void led_blink_fast() {
	led_blink(10);
}

void led_blink_slow() {
	led_blink(200);
}