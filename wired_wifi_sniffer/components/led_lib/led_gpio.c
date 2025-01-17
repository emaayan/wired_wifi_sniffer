#include <led_gpio.h>
#include "esp_log.h"
#include "driver/gpio.h"

static const char *TAG = "GPIOLed";
static int _led_pin = 0;
void led_init(int pin)
{
	ESP_LOGI(TAG, "Init gpio...%d ",pin);
	_led_pin=pin;
    ESP_ERROR_CHECK(gpio_set_direction(pin, GPIO_MODE_OUTPUT));
}

void led_set(bool on)
{	
    ESP_ERROR_CHECK(gpio_set_level(_led_pin, on ? 1 : 0));
}


