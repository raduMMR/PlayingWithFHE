all:
	rm -f my_int
	g++ -std=c++11 TFHE_INT.h TFHE_INT.cpp main.cpp -o my_int -ltfhe-spqlios-fma 
	./my_int 1 1
clean:
	rm -f my_int

