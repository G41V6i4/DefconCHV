CC=gcc
CFLAGS=-Wall -g -fno-stack-protector -z execstack
TARGET=infotainment_service
SOURCE=info.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

.PHONY: clean
