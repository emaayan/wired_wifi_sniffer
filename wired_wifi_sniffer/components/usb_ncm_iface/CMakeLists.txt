idf_component_register(SRCS "usb_ncm_iface.c"
                    INCLUDE_DIRS "include"
                    REQUIRES lwip console esp_event nvs_lib  utils_lib             
                    )