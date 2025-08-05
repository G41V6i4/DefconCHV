CC=aarch64-linux-gnu-gcc
CFLAGS=-Wall -g -fno-stack-protector -s -static -march=armv8.3-a+pauth
TARGET=infotainment_service
SOURCE=info.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

.PHONY: clean