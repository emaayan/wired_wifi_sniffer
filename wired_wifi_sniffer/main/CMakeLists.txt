
idf_component_register(SRCS "main.c"
                            "sniffer.c"                                                        
                            "usb_ncm_iface.c"
                            "capture_lib.c"        
                            "config_http_server.c"                                             
                    INCLUDE_DIRS ".")


idf_build_set_property(COMPILE_DEFINITIONS CFG_TUD_NCM_IN_NTB_N=3 APPEND)


#list(APPEND EXCLUDE_COMPONENTS "esp_lcd")

#spiffs_create_partition_image(storage ../spiffs_image FLASH_IN_PROJECT)
fatfs_create_spiflash_image(storage ../files FLASH_IN_PROJECT)
