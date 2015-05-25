CC = gcc
CCFLAGS = -g -O0
SRC = $(wildcard *c)
BIN = victim.out
OBJ = $(SRC:.c=.o)
LIBPATH = /usr/local/lib
LIB = -L $(LIBPATH) -lgnutls

$(BIN):$(OBJ)
	$(CC) $(CCFLAGS) $(SRC) $(LIB) -o $(BIN)

$(OBJ):$(SRC)

.PHONY:clean
clean:
	-rm -f $(OBJ)
