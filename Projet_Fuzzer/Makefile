CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Wextra -pedantic -Iinclude
TARGET = fuzzer

SRCS = \
	src/common.c \
	src/main.c \
	src/case_builder.c \
	src/case_material.c \
	src/case_phase_a.c \
	src/case_phase_b.c \
	src/case_phase_c.c \
	src/case_phase_d.c \
	src/case_phase_e.c \
	src/case_campaign.c \
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
	# Remove top-level files/directories with non-printable names left by fuzz runs.
	LC_ALL=C find . -mindepth 1 -maxdepth 1 -name '*[! -~]*' -exec rm -rf -- {} +
