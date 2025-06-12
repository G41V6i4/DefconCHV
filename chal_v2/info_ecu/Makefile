CC = gcc
CFLAGS = -Wall -g -fno-stack-protector -z execstack
LDFLAGS = -pthread

TARGET = infotainment_simulator
SOURCES = infotainment_simulator.c
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Build the target
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Vulnerable version (for CTF)
vulnerable: CFLAGS += -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0 -no-pie
vulnerable: clean $(TARGET)

# Debug version
debug: CFLAGS += -DDEBUG -g3
debug: clean $(TARGET)

# Clean build files
clean:
	rm -f $(TARGET) $(OBJECTS)

# Install target
install: $(TARGET)
	cp $(TARGET) /app/

.PHONY: all clean vulnerable debug install