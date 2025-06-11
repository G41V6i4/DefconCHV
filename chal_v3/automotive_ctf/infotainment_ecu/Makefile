CC = gcc
CFLAGS = -Wall -g -fno-stack-protector -z execstack
LDFLAGS = -pthread

TARGET = infotainment_simulator

all: $(TARGET)

$(TARGET): infotainment_simulator.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

vulnerable: CFLAGS += -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0 -no-pie
vulnerable: clean $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean vulnerable
