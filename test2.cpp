#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <ctime>
using namespace std;

#define N 8

int main(int argc, char **argv) {

	if(argc != 3)
    {
        cout<<"Nr de parametri incorect.\n";
        return -1;
    }
    int8_t plaintext1 = atoi(argv[1]);
    int8_t plaintext2 = atoi(argv[2]);

    cout<<"Sa batem HElib-ul !!!!"<<endl;
	cout<<"Generare parametri si cheii ..."<<endl;
	const int minimum_lambda  = 110;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
	uint32_t seed[] = {314, 1592, 657};
	tfhe_random_generator_setSeed(seed, 3);
	TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	cout<<"Terminat setup\n";

	cout<<"Criptare numere ...\n";
	LweSample* ca = new_gate_bootstrapping_ciphertext(params);
	for (int i=0; i<N; i++) {
        bootsSymEncrypt(&ca[i], (plaintext1>>i)&1, key);
    }
	LweSample* cb = new_gate_bootstrapping_ciphertext(params);
	for (int i=0; i<N; i++) {
        bootsSymEncrypt(&cb[i], (plaintext2>>i)&1, key);
    }
	cout<<"Terminate de criptat numere.\n";

	cout<<"Inmultire numere ...\n";
	LweSample* result = new_gate_bootstrapping_ciphertext_array(N*2, params);
    LweSample* nr1 = new_gate_bootstrapping_ciphertext_array(N*2, params);
    LweSample* nr2 = new_gate_bootstrapping_ciphertext_array(N*2, params);
    for(int i=0; i<N; i++){
        bootsCOPY(&nr1[i], &ca[0], &key->cloud);
        bootsCOPY(&nr2[i], &cb[0], &key->cloud);
        bootsCONSTANT(&result[i], 0, &key->cloud);
    }
    for(int i=N; i<2*N; i++){
        bootsCOPY(&nr1[i], &ca[i-N], &key->cloud);
        bootsCOPY(&nr2[i], &cb[i-N], &key->cloud);
        bootsCONSTANT(&result[i], 0, &key->cloud);
    }


    int pas=0;
    LweSample* bit_product = new_gate_bootstrapping_ciphertext(params);
    LweSample* carry = new_gate_bootstrapping_ciphertext(params);
    bootsCONSTANT(carry, 0, &key->cloud);
    LweSample* aux = new_gate_bootstrapping_ciphertext(params);
    LweSample* prev = new_gate_bootstrapping_ciphertext(params);

    for(int i=0; i<2*N; i++){
        for(int j=0; j<2*N-pas; j++){
            bootsCOPY(prev, &result[2*N-1-j-pas], &key->cloud);

            bootsAND(bit_product, &nr1[2*N-1-i], &nr2[2*N-1-j], &key->cloud);
            bootsXOR(aux, carry, bit_product, &key->cloud);
            bootsXOR(&result[2*N-1-j-pas], aux, &result[2*N-1-j-pas], &key->cloud);

            bootsAND(aux, bit_product, carry, &key->cloud);
            bootsAND(bit_product, bit_product, prev, &key->cloud);
            bootsOR(aux, aux, bit_product, &key->cloud);
            bootsAND(carry, carry, prev, &key->cloud);
            bootsOR(carry, aux, carry, &key->cloud);
        }
        pas++;
    }
	cout<<"Terminat de inmultit numerele.\n";

	int16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&result[i], key);
        int_answer |= (ai<<(16-i);
    }
	cout<<"Produsul este "<<int_answer<<endl;

	/*clock_t begin = clock();
	clock_t end = clock();
	double elapsed_secs = double(end-begin)/CLOCKS_PER_SEC;
	cout<<"Timp = "<<elapsed_secs<<" secunde.\n";*/

	// clean up pointers
    delete_gate_bootstrapping_ciphertext(bit_product);
    delete_gate_bootstrapping_ciphertext(carry);
    delete_gate_bootstrapping_ciphertext(aux);
    delete_gate_bootstrapping_ciphertext(prev);
    delete_gate_bootstrapping_ciphertext_array(2*N, nr1);
    delete_gate_bootstrapping_ciphertext_array(2*N, nr2);
	delete_gate_bootstrapping_ciphertext_array(2*N, result);
	delete_gate_bootstrapping_secret_keyset(key);
	delete_gate_bootstrapping_parameters(params);
	delete_gate_bootstrapping_ciphertext(ctxt1);
	delete_gate_bootstrapping_ciphertext(ctxt2);
	delete_gate_bootstrapping_ciphertext(product);
	delete_gate_bootstrapping_ciphertext(enc1);
	delete_gate_bootstrapping_ciphertext(enc2);
}
