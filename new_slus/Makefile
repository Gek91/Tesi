# build slus executable when user executes "make" 

slus: slus_main.o
	$(CC) $(LDFLAGS) slus_main.o -o slus -lnfnetlink -lnetfilter_queue

slus.o:	slus_main.c
	$(CC) $(CFLAGS) -c slus_main.c 

# remove object files and executable when user executes "make clean"
clean:
	rm *.o slus 

