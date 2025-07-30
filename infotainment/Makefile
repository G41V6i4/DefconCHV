CC=aarch64-linux-gnu-gcc
CFLAGS=-Wall -g -fno-stack-protector -s -static -march=armv8-a
TARGET=infotainment_service
SOURCE=info.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

# AArch64 (ARM 64비트)
aarch64: CC=aarch64-linux-gnu-gcc
aarch64: CFLAGS=-Wall -g -fno-stack-protector -s -static -march=armv8-a
aarch64: $(TARGET)

# x86-64 테스트용
x86-64: CC=gcc
x86-64: CFLAGS=-Wall -g -fno-stack-protector -s -static
x86-64: $(TARGET)

.PHONY: clean aarch64 x86-64