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

FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

	cout<<"Terminat setup\n";

    LweSample* ca = new_gate_bootstrapping_ciphertext_array(8, params);;
    LweSample* cb = new_gate_bootstrapping_ciphertext_array(8, params);;
    LweSample* product = new_gate_bootstrapping_ciphertext_array(8, params);;

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
    TFHE_INT_8::multiply(product, ca, cb, &key->cloud, key);
    cout<<"Terminat de inmultit numerele.\n";

    int result = TFHE_INT_8::decrypt_int(product, key);
    cout<<"Rezultatul inmultirii = "<<result<<endl;

	delete_gate_bootstrapping_ciphertext_array(8, product);
	delete_gate_bootstrapping_secret_keyset(key);
	delete_gate_bootstrapping_parameters(params);
	delete_gate_bootstrapping_ciphertext_array(8, ca);
	delete_gate_bootstrapping_ciphertext_array(8, cb);
}
