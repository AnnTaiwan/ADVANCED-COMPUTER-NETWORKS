# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Shell program source files
SRCS = prog.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable
EXES = prog

# Headers
# HEADER = arp.h

# Default target
all: $(EXES)

# Link executable from object files
$(EXES): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)
    
# Compile .c to .o, ensuring header dependencies are tracked
%.o: %.c 
	$(CC) $(CFLAGS) -c $<

# Clean up
clean:
	rm -f $(EXES) $(OBJS)

.PHONY: all clean

