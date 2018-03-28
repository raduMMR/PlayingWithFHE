# g++ -std=c++11 TFHE_INT_8.h TFHE_INT_8.cpp main.cpp -o my_int -ltfhe-spqlios-fma 

PROG = my_int
CC = g++
CPPFLAGS = -std=c++11 -Wall -I/usr/local/include
LDFLAGS = -L/usr/local/lib -ltfhe-spqlios-fma
OBJS = main.o TFHE_INT.o

$(PROG) : $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS)
main.o:
	$(CC) $(CPPFLAGS) -c main.cpp 
TFHE_INT.o: TFHE_INT.h 
	$(CC) $(CPPFLAGS) -c TFHE_INT.cpp
clean:
	rm -f core $(PROG) $(OBJS)

