# auth_server - Nginx auth_request 鉴权网关
# 用法: make && ./auth_server [port] [--demo]
#   --demo: 跳过 JWT 鉴权(联调用)，默认启用完整链路 JWT+Redis

CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS := -lssl -lcrypto -lhiredis
SRC     := $(wildcard src/*.c)
OBJ     := $(SRC:.c=.o)
TARGET  := auth_server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c $(wildcard src/*.h)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
