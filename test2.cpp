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
	cout<<"Generare parametri si chei ..."<<endl;
	const int minimum_lambda  = 80;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
	uint32_t seed[] = {314, 1592, 657};
	tfhe_random_generator_setSeed(seed, 3);
	TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	cout<<"Terminat setup\n";

	cout<<"Criptare numere ...\n";
	LweSample* ca = new_gate_bootstrapping_ciphertext_array(N, params);
	for (int i=0; i<N; i++) {
		bootsSymEncrypt(&ca[i], (plaintext1>>(N-1-i))&1, key);
   	}
	LweSample* cb = new_gate_bootstrapping_ciphertext_array(N, params);
	for (int i=0; i<N; i++) {
        	bootsSymEncrypt(&cb[i], (plaintext2>>(N-1-i))&1, key);
    	}
	cout<<"Terminat de criptat numere.\n";

	cout<<"Inmultire numere ...\n";
	LweSample* result = new_gate_bootstrapping_ciphertext_array(N, params);
    LweSample* nr1 = new_gate_bootstrapping_ciphertext_array(N, params);
    LweSample* nr2 = new_gate_bootstrapping_ciphertext_array(N, params);
	clock_t begin = clock();
    /*for(int i=0; i<N; i++){
        bootsCOPY(&nr1[i], &ca[0], &key->cloud);
        bootsCOPY(&nr2[i], &cb[0], &key->cloud);
        bootsCONSTANT(&result[i], 0, &key->cloud);
    }*/
    for(int i=0; i<N; i++){
        bootsCOPY(&nr1[i], &ca[i], &key->cloud);
        bootsCOPY(&nr2[i], &cb[i], &key->cloud);
        bootsCONSTANT(&result[i], 0, &key->cloud);
    }


    int pas=0;
    LweSample* bit_product = new_gate_bootstrapping_ciphertext(params);
    LweSample* carry = new_gate_bootstrapping_ciphertext(params);
    LweSample* aux = new_gate_bootstrapping_ciphertext(params);
    LweSample* prev = new_gate_bootstrapping_ciphertext(params);

    for(int i=0; i<N; i++){
	    bootsCONSTANT(carry, 0, &key->cloud);

        for(int j=0; j<N-pas; j++){
            bootsCOPY(prev, &result[N-1-j-pas], &key->cloud);
            bootsAND(bit_product, &nr1[N-1-i], &nr2[N-1-j], &key->cloud);
            bootsXOR(aux, carry, bit_product, &key->cloud);
<<<<<<< HEAD
            bootsXOR(&result[N-1-j-pas], aux, &result[N-1-j-pas], &key->cloud);	
=======
cout<<bootsSymDecrypt(aux, key)<<" xor "<<bootsSymDecrypt(&result[N-1-j-pas], key)<<"=";
            bootsXOR(&result[N-1-j-pas], aux, &result[N-1-j-pas], &key->cloud);
 cout<<bootsSymDecrypt(&result[N-1-j-pas], key)<<endl;
	/*if(i==2){
		cout<<"result="<<bootsSymDecrypt(&result[2*N-1-j-pas], key)<<endl;
	}*/	
>>>>>>> 41ec87b2bbd20a1ed8051d46396e98d57ceca202
            bootsAND(aux, bit_product, carry, &key->cloud);
            bootsAND(bit_product, bit_product, prev, &key->cloud);
            bootsOR(aux, aux, bit_product, &key->cloud);
            bootsAND(carry, carry, prev, &key->cloud);
            bootsOR(carry, aux, carry, &key->cloud);
        }
        pas++;
    }
	clock_t end = clock();
	double elapsed_secs = double(end-begin)/CLOCKS_PER_SEC;
	cout<<"Timp = "<<elapsed_secs<<" secunde.\n";

	cout<<"Terminat de inmultit numerele.\n";

	// int16_t int_answer = bootsSymDecrypt(&result[0], key)*(int)pow(2, 2*N-1);
	int8_t int_answer = 0;
   for (int i=0; i<N; i++) {
        int ai = bootsSymDecrypt(&result[i], key);
        int_answer |= (ai<<(N-1-i));
	cout<<ai;
    }
   cout<<endl;

	/*for(int i=1; i<2*N; i++){
		int_answer += bootsSymDecrypt(&result[i], key)*(int)pow(2, 2*N-1-i); 
	}*/

	cout<<"Produsul este "<<(int)int_answer<<endl;

//FILE* cloud_data = fopen("cloud.data","wb");
    // for (int i=0; i<N; i++)
      //  export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ca[0], params);
// fclose(cloud_data);


    delete_gate_bootstrapping_ciphertext(bit_product);
    delete_gate_bootstrapping_ciphertext(carry);
    delete_gate_bootstrapping_ciphertext(aux);
    delete_gate_bootstrapping_ciphertext(prev);
    delete_gate_bootstrapping_ciphertext_array(N, nr1);
    delete_gate_bootstrapping_ciphertext_array(N, nr2);
	delete_gate_bootstrapping_ciphertext_array(N, result);
	delete_gate_bootstrapping_secret_keyset(key);
	delete_gate_bootstrapping_parameters(params);
	delete_gate_bootstrapping_ciphertext_array(N, ca);
	delete_gate_bootstrapping_ciphertext_array(N, cb);
}
