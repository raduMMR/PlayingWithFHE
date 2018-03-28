#include "TFHE_INT.h"
#include <iostream>
#include <ctime>
using namespace std;

LweSample* TFHE_INT_8::encrypt_int(const int number, const TFheGateBootstrappingSecretKeySet* sk)
{
    LweSample* enc_int = new_gate_bootstrapping_ciphertext_array(N, sk->params);
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

LweSample* TFHE_INT_8::add(const LweSample* nr1, const LweSample* nr2, 
    const TFheGateBootstrappingCloudKeySet* ck)
{
    LweSample* sum = new_gate_bootstrapping_ciphertext_array(N, ck->params);
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

    return sum;
}

LweSample* TFHE_INT_8::multiply(const LweSample* ca, const LweSample* cb, 
    const TFheGateBootstrappingCloudKeySet* ck)
{
    LweSample* result = new_gate_bootstrapping_ciphertext_array(8, ck->params);
    LweSample* bit_product = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* carry = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* aux = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* prev = new_gate_bootstrapping_ciphertext(ck->params);
    int pas=0;

    for(int i=0; i<8; i++){
	    bootsCONSTANT(carry, 0, ck);

        for(int j=0; j<8-pas; j++){
            bootsCOPY(prev, &result[15-j-pas], ck);
            bootsAND(bit_product, &ca[15-i], &cb[15-j], ck);
            bootsXOR(aux, carry, bit_product, ck);
            bootsXOR(&result[15-j-pas], aux, &result[15-j-pas], ck);
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

    return result;
}

