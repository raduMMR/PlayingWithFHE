#include "TFHE_INT.h"
#include <iostream>
#include <ctime>
using namespace std;

LweSample* TFHE_INT_8::encrypt_int(const int number, const TFheGateBootstrappingSecretKeySet* sk)
{
	LweSample* enc_int = new_gate_bootstrapping_ciphertext_array(8, sk->params);
	for (int i=0; i<8; i++) {
		bootsSymEncrypt(&enc_int[i], (number>>(7-i))&1, sk);
   	}
	return enc_int;
}

int TFHE_INT_8::decrypt_int(const LweSample* enc_int, const TFheGateBootstrappingSecretKeySet* sk)
{
    int8_t int_answer = 0;
    for (int i=0; i<8; i++) {
        int ai = bootsSymDecrypt(&enc_int[i], sk);
        int_answer |= (ai<<(7-i));
    }
    return int_answer;
}

void TFHE_INT_8::add(LweSample* sum, const LweSample* nr1, const LweSample* nr2, 
    const TFheGateBootstrappingCloudKeySet* ck)
{
    LweSample* aux = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* carry = new_gate_bootstrapping_ciphertext(ck->params);
    bootsCONSTANT(carry, 0, ck);

    for(int i=7; i>=0; i--){
        bootsXOR(&sum[i], &nr1[i], &nr2[i], ck);
        bootsXOR(&sum[i], &sum[i], carry, ck);

        bootsAND(aux, &nr1[i], carry, ck);
        bootsAND(carry, carry, &nr2[i], ck);
        bootsOR(carry, aux, carry, ck);
        bootsAND(aux, &nr1[i], &nr2[i], ck);
        bootsOR(carry, aux, carry, ck);
    }
    // TO DO: addition with overflow check!!!

    delete_gate_bootstrapping_ciphertext(carry);
    delete_gate_bootstrapping_ciphertext(aux);
}

LweSample* TFHE_INT_8::multiply(const LweSample* ca, const LweSample* cb, 
    const TFheGateBootstrappingCloudKeySet* ck1, const TFheGateBootstrappingSecretKeySet *sk)
{
/*for(int i=0; i<8; i++){
cout<<bootsSymDecrypt(&ca[i], sk);
}
cout<<endl;
for(int i=0; i<8; i++){
cout<<bootsSymDecrypt(&cb[i], sk);
}
cout<<endl;*/
FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* ck = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

/*LweSample* bit1 = new_gate_bootstrapping_ciphertext(ck->params);
LweSample* bit2 = new_gate_bootstrapping_ciphertext(ck->params);
for(int i=0; i<10; i++){
	int8_t ptxt1 = rand()%2;
	int8_t ptxt2 = rand()%2;
	bootsSymEncrypt(bit1, ptxt1, sk);
	bootsSymEncrypt(bit2, ptxt2, sk);
	bootsXOR(bit1, bit1, bit2, ck);
	if( (ptxt1+ptxt2)%2 != bootsSymDecrypt(bit1, sk)){
		cout<<(int)ptxt1<<" xor "<<(int)ptxt2<<" = "<<bootsSymDecrypt(bit1, sk)<<endl;
	}
}
delete_gate_bootstrapping_ciphertext(bit1);
delete_gate_bootstrapping_ciphertext(bit2);
return;*/

LweSample* result = new_gate_bootstrapping_ciphertext_array(8, ck->params);
    LweSample* bit_product = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* carry = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* aux = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* prev = new_gate_bootstrapping_ciphertext(ck->params);
    int pas=0;
    for(int i=0; i<8; i++){
	bootsCONSTANT(carry, 0, ck);

        for(int j=0; j<8-pas; j++){
            bootsCOPY(prev, &result[7-j-pas], ck);
            bootsAND(bit_product, &ca[7-i], &cb[7-j], ck);
            bootsXOR(aux, carry, bit_product, ck);

	// int unu = rand()%2;
	// int doi = rand()%2;
	// bootsSymEncrypt(aux, unu, sk); bootsSymEncrypt(prev, doi, sk);
	bootsXOR(&result[7-j-pas], aux, prev, ck);

            // bootsXOR(&result[7-j-pas], aux, prev, ck);
if((bootsSymDecrypt(aux, sk) + bootsSymDecrypt(prev, sk)) %2 != bootsSymDecrypt(&result[7-j-pas], sk)){
	cout<<"Eroare\n";
}
            bootsAND(aux, bit_product, carry, ck);
            bootsAND(bit_product, bit_product, prev, ck);
            bootsOR(aux, aux, bit_product, ck);
            bootsAND(carry, carry, prev, ck);
            bootsOR(carry, aux, carry, ck);
        }
        pas++;
    }
    delete_gate_bootstrapping_ciphertext(bit_product);
    delete_gate_bootstrapping_ciphertext(carry);
    delete_gate_bootstrapping_ciphertext(aux);
    delete_gate_bootstrapping_ciphertext(prev);
    // delete_gate_bootstrapping_ciphertext_array(8, result);
    delete_gate_bootstrapping_cloud_keyset(ck);
return result;
}

