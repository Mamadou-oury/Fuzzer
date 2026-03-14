CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Wextra -pedantic -Iinclude
TARGET = fuzzer

SRCS = \
	src/common.c \
	src/main.c \
	src/case_builder.c \
	src/tar_writer.c \
	src/runtime.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS) src/*.o archive.tar success_*.tar crashing
