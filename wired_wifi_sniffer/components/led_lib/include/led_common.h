#ifndef B0899C67_02BD_45F8_B9F6_7BBE5A3EA606
#define B0899C67_02BD_45F8_B9F6_7BBE5A3EA606

#include "../../build/config/sdkconfig.h"

//#if CONFIG_IDF_TARGET_ESP32C2 || CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32S3
#ifdef CONFIG_BLINK_LED_RMT
#define LED_PIN CONFIG_BLINK_GPIO
#include "led_rmt.h"
#endif
#ifdef CONFIG_BLINK_LED_GPIO
#define LED_PIN CONFIG_BLINK_GPIO
#include <led_gpio.h>
#endif
#ifdef CONFIG_BLINK_LED_MOCK
#define LED_PIN 0
#include <led_mock.h>
#endif



void led_init_default();
void led_blink(uint16_t delay);
void led_blink_fast();
void led_blink_slow();

#endif /* B0899C67_02BD_45F8_B9F6_7BBE5A3EA606 */
