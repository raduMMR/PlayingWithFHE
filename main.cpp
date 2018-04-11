#include <iostream>
#include <tfhe/tfhe.h>
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

// FILE* cloud_key = fopen("cloud.key","wb");
//     export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
//     fclose(cloud_key);

	cout<<"Terminat setup\n";

    LweSample* ca = new_gate_bootstrapping_ciphertext_array(8, params);;
    LweSample* cb = new_gate_bootstrapping_ciphertext_array(8, params);;
    LweSample* product = NULL; //new_gate_bootstrapping_ciphertext_array(8, params);;

    cout<<"Criptare numere...\n";
    ca = TFHE_INT_8::encrypt_int( plaintext1, key);
    cb = TFHE_INT_8::encrypt_int( plaintext2, key);
    cout<<"Terminat de criptat numere.\n";

/*LweSample* bit1 = new_gate_bootstrapping_ciphertext(params);
LweSample* bit2 = new_gate_bootstrapping_ciphertext(params); 
for(int i=0; i<1000; i++){
	int8_t pt1 = rand()%2;
	int8_t pt2 = rand()%2;
	bootsSymEncrypt(bit1, pt1, key);
	bootsSymEncrypt(bit2, pt2, key);
	bootsXOR(bit1, bit1, bit2, &key->cloud);
	if((pt1 + bootsSymDecrypt(bit2, key)) %2 != bootsSymDecrypt(bit1, key) ) {
		cout<<"Eroare test "<<i<<endl;
	}
}
delete_gate_bootstrapping_ciphertext(bit1);
delete_gate_bootstrapping_ciphertext(bit2);*/

    cout<<"Inmultire numere...\n";
    product =  TFHE_INT_8::multiply(ca, cb, &key->cloud, key);
    LweSample* result = new_gate_bootstrapping_ciphertext_array(8, params);
    LweSample* bit_product = new_gate_bootstrapping_ciphertext(params);
    LweSample* carry = new_gate_bootstrapping_ciphertext(params);
    LweSample* aux = new_gate_bootstrapping_ciphertext(params);
    LweSample* prev = new_gate_bootstrapping_ciphertext(params);
    int pas=0;
    for(int i=0; i<8; i++){
	bootsCONSTANT(carry, 0, &key->cloud);

        for(int j=0; j<8-pas; j++){
            bootsCOPY(prev, &result[7-j-pas], &key->cloud);
            bootsAND(bit_product, &ca[7-i], &cb[7-j], &key->cloud);
            bootsXOR(aux, carry, bit_product, &key->cloud);
	        bootsXOR(&result[7-j-pas], aux, prev, &key->cloud);
            bootsAND(aux, bit_product, carry, &key->cloud);
            bootsAND(bit_product, bit_product, prev, &key->cloud);
            bootsOR(aux, aux, bit_product, &key->cloud);
            bootsAND(carry, carry, prev, &key->cloud);
            bootsOR(carry, aux, carry, &key->cloud);
        }
        pas++;
    }
    delete_gate_bootstrapping_ciphertext(bit_product);
    delete_gate_bootstrapping_ciphertext(carry);
    delete_gate_bootstrapping_ciphertext(aux);
    delete_gate_bootstrapping_ciphertext(prev);
    delete_gate_bootstrapping_ciphertext_array(8, result);
    cout<<"Terminat de inmultit numerele.\n";

    int result1 = TFHE_INT_8::decrypt_int(result, key);
    cout<<"Rezultatul inmultirii = "<<result1<<endl;

if(product != NULL)
	delete_gate_bootstrapping_ciphertext_array(8, product);
	delete_gate_bootstrapping_secret_keyset(key);
	delete_gate_bootstrapping_parameters(params);
	delete_gate_bootstrapping_ciphertext_array(8, ca);
	delete_gate_bootstrapping_ciphertext_array(8, cb);
}
