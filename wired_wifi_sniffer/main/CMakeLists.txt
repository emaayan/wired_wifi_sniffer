
idf_component_register(SRCS "main.c"
                            "sniffer.c"                                                                
                            "config_http_server.c"                                             
                    INCLUDE_DIRS ".")


#spiffs_create_partition_image(storage ../spiffs_image FLASH_IN_PROJECT)
fatfs_create_spiflash_image(storage ../files FLASH_IN_PROJECT)
