#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <ctime>
using namespace std;

int main() {
// generate a keyset
const int minimum_lambda  = 110;
TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
// generate a random key
uint32_t seed[] = {314, 1592, 657};
tfhe_random_generator_setSeed(seed, 3);
TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

LweSample* ctxt1 = new_gate_bootstrapping_ciphertext(params);
LweSample* ctxt2 = new_gate_bootstrapping_ciphertext(params);
LweSample* enc1 = new_gate_bootstrapping_ciphertext(params);
LweSample* enc2 = new_gate_bootstrapping_ciphertext(params);
LweSample* product = new_gate_bootstrapping_ciphertext(params);
// testing the library
int8_t a = 0;
int8_t b = 1;
bootsSymEncrypt(ctxt1, (a>>0)&1, key);
bootsSymEncrypt(ctxt2, (b>>0)&1, key);
bootsCONSTANT(enc1, 0, &key->cloud);
bootsCONSTANT(enc2, 1, &key->cloud);

/*bootsAND(product, ctxt1, enc1, &key->cloud);
printf("0 & 0 = %d\n", bootsSymDecrypt(product, key));
bootsAND(product, ctxt1, enc2, &key->cloud);
printf("0 & 1 = %d\n", bootsSymDecrypt(product, key));
bootsAND(product, ctxt1, enc1, &key->cloud);
printf("1 & 0 = %d\n", bootsSymDecrypt(product, key));
bootsAND(product, ctxt2, enc2, &key->cloud);
printf("1 & 1 = %d\n", bootsSymDecrypt(product, key));*/
/*clock_t begin = clock();
for(int i=0; i<500; i++){
	// bootsAND(product, ctxt1, ctxt2, &key->cloud);	
	//if( bootsSymDecrypt(product, key) != (a && b) ){
	// printf("%d && %d = %d. Pas i = %d\n", a, b, bootsSymDecrypt(product, key), i);
	//}
}
clock_t end = clock();
double elapsed_secs = double(end-begin)/CLOCKS_PER_SEC;
cout<<"Timp = "<<elapsed_secs<<" secunde.\n";*/
// clean up pointers
delete_gate_bootstrapping_secret_keyset(key);
delete_gate_bootstrapping_parameters(params);
delete_gate_bootstrapping_ciphertext(ctxt1);
delete_gate_bootstrapping_ciphertext(ctxt2);
delete_gate_bootstrapping_ciphertext(product);
delete_gate_bootstrapping_ciphertext(enc1);
delete_gate_bootstrapping_ciphertext(enc2);
}
