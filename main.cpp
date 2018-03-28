#include <iostream>
// #include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <ctime>
#include "TFHE_INT.h"
using namespace std;

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
	const int minimum_lambda  = 110;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
	uint32_t seed[] = {314, 1592, 657};
	tfhe_random_generator_setSeed(seed, 3);
	TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	cout<<"Terminat setup\n";

    LweSample* ca = NULL;
    LweSample* cb = NULL;
    LweSample* product = NULL;

    cout<<"Criptare numere...\n";
    ca = TFHE_INT_8::encrypt_int( plaintext1, key);
    cb = TFHE_INT_8::encrypt_int( plaintext2, key);
    cout<<"Terminat de criptat numere.\n";

    cout<<"Inmultire numere...\n";
    product = TFHE_INT_8::multiply(ca, cb, &key->cloud);
    cout<<"Terminat de inmultit numerele.\n";

    int result = TFHE_INT_8::decrypt_int(product, key);
    cout<<"Rezultatul inmultirii = "<<result<<endl;

	delete_gate_bootstrapping_ciphertext_array(8, product);
	delete_gate_bootstrapping_secret_keyset(key);
	delete_gate_bootstrapping_parameters(params);
	delete_gate_bootstrapping_ciphertext_array(8, ca);
	delete_gate_bootstrapping_ciphertext_array(8, cb);
}
