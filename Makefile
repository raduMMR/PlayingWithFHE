all:
	g++ -std=c++11 TFHE_INT.h TFHE_INT.cpp main.cpp -o my_int -ltfhe-spqlios-fma 
clean:
	rm -f my_int

