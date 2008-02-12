all: iwtan_example test_data_driver test_analyze

iwtan_example: iwtan_data.c iwtan_analyze.c iwtan_example.c
	gcc iwtan_data.c iwtan_analyze.c iwtan_example.c -liw -lpcap -lpthread -o iwtan_example

test_data_driver: iwtan_data.c test_data_driver.c
	gcc iwtan_data.c test_data_driver.c -liw -lpcap -lpthread -o test_data_driver

test_analyze: iwtan_analyze.c iwtan_data.c test_analyze.c
	gcc iwtan_analyze.c iwtan_data.c test_analyze.c -liw -lpcap -lpthread -o test_analyze
