CFLAGS   = 
LDFLAGS  = -lpcap -pthread -z muldefs
PROG = waspcap
CXX = gcc

OBJS = control_management_pcap.o  main.o  network_layer.o  transport_layer.o

# top-level rule to create the program.
all: $(PROG)

# compiling other source files.
%.o: %.c
	$(CXX) $(CFLAGS) -c $<

# linking the program
$(PROG): $(OBJS)
	$(CXX) $(OBJS) -o $(PROG) $(LDFLAGS)

# cleaning everything that can be automatically recreated with "make"
clean:
	rm $(PROG) *.o

