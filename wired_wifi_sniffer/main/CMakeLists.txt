
idf_component_register(SRCS "main.c" "config_http_server.c"                                                                       
                    INCLUDE_DIRS ".")

fatfs_create_spiflash_image(storage ../files FLASH_IN_PROJECT)
