#idf_component_register(SRCS "led_lib.c" "led_rmt.c" "led_gpio.c" "led_common.c" "led_mock.c"
#                    REQUIRES driver
#                    INCLUDE_DIRS "include")

set(srcs "led_common.c" "led_lib.c")
                   
     
if(CONFIG_IDF_TARGET STREQUAL "esp32" OR  CONFIG_IDF_TARGET STREQUAL "esp32c2")
       list(APPEND srcs "led_gpio.c")
else()
	   list(APPEND srcs "led_rmt.c")
endif()    

idf_component_register(SRCS ${srcs} 
REQUIRES driver
INCLUDE_DIRS "include")									                    