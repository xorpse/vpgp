
SRC=src
SRCS=$(SRC)/buffer.c \
     $(SRC)/dsa.c \
     $(SRC)/key.c \
     $(SRC)/packet.c \
     $(SRC)/par.c \
     $(SRC)/rng.c \
     $(SRC)/rsa.c \
     $(SRC)/seq.c \
     $(SRC)/sig.c \
     $(SRC)/main.c
OBJS=${SRCS:.c=.o}
EXE=vpgp

LDFLAGS=-lcrypto -lpthread
CFLAGS=-Wno-unused-function -Wall -Werror -std=gnu99 -I $(SRC)

.SUFFIXES: .o .c

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(OBJS) $(EXE)
