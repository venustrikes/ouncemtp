# Host-side protocol tests (Linux/macOS, no Switch needed):
#   make -C tests
# Builds the portable MTP responder against an emulated USB bulk pipe with
# ASan/UBSan, then runs the Python MTP initiator at USB 2 and USB 3 packet sizes.
CC      ?= cc
CFLAGS  := -std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter -fsanitize=address,undefined -I../source
SRCS    := ../source/mtp.c ../source/objdb.c ../source/dataset.c ../source/status.c host_transport.c host_main.c

all: test

build/host_mtp: $(SRCS) $(wildcard ../source/*.h)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SRCS) -lpthread

build/rx_header_test: rx_header_test.c ../source/mtp.c $(wildcard ../source/*.h)
	@mkdir -p build
	$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Wl,--gc-sections -o $@ $<

test: build/host_mtp build/rx_header_test
	./build/rx_header_test
	python3 mtp_test.py build/host_mtp 512
	python3 mtp_test.py build/host_mtp 1024

clean:
	rm -rf build

.PHONY: all test clean
