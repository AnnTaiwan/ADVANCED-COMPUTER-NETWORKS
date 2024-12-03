# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g 

# Shell program source files
SRCS = fill_packet.c  main.c  pcap.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable
EXES = ipscanner

# Headers
HEADER = fill_packet.h pcap.h

# Default target
all: $(EXES)

# Link executable from object files
$(EXES): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lpcap
    
# Compile .c to .o, ensuring header dependencies are tracked
%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -c $<

# Clean up
clean:
	rm -f $(EXES) $(OBJS)

.PHONY: all clean

