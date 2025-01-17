#include "led_rmt.h"
#include "esp_err.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "led_strip.h"
static const char *TAG = "LedStrip";
static led_strip_handle_t led_strip;

//static bool _init=false;
void led_init(int pin)
{
	ESP_LOGI(TAG, "Init led strip...%d ",pin);
    /* LED strip initialization with the GPIO and pixels number*/
    led_strip_config_t strip_config = {
        .strip_gpio_num = pin,
        .max_leds = 1, // at least one LED on board
    };
    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000, // 10MHz
    };
    ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
    /* Set all LED off to clear all pixels */
    ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_clear(led_strip));
//    _init=true;
}


#define R 16
#define G 16
#define B 16
void led_set(bool s_led_state)
{
	if (led_strip){
	    /* If the addressable LED is enabled */
	    if (s_led_state)
	    {
	        /* Set the LED pixel using RGB from 0 (0%) to 255 (100%) for each color */
	        ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_set_pixel(led_strip, 0, R, G, B));
	        /* Refresh the strip to send data */
	        ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_refresh(led_strip));
	    }
	    else
	    {
	        /* Set all LED off to clear all pixels */
	        ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_clear(led_strip));
	    }
    }else{
		ESP_LOGW(TAG,"led not init");
	}
}
