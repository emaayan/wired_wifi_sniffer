idf_component_register(SRCS "usb_ncm_iface.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_wifi esp_event nvs_lib              
                    )
#idf_build_set_property(COMPILE_DEFINITIONS CFG_TUD_NCM_IN_NTB_N=3 APPEND)