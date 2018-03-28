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

// int TFHE_INT::decrypt_int16(const LweSample* enc_int, const TFheGateBootstrappingSecretKeySet* sk)
// {
//     int16_t int_answer = 0;
//     for (int i=0; i<2*N; i++) {
//         int ai = bootsSymDecrypt(&enc_int[i], sk);
//         int_answer |= (ai<<(2*N-1-i));
//     }
//     return int_answer;
// }

LweSample* TFHE_INT_8::add(const LweSample* nr1, const LweSample* nr2, 
    const TFheGateBootstrappingCloudKeySet* ck)
{
    LweSample* sum = new_gate_bootstrapping_ciphertext_array(N, ck->params);
    return sum;
}

LweSample* TFHE_INT_8::multiply(const LweSample* ca, const LweSample* cb, 
    const TFheGateBootstrappingCloudKeySet* ck)
{
    LweSample* result = new_gate_bootstrapping_ciphertext_array(8, ck->params);

	clock_t begin = clock();

    int pas=0;
    LweSample* bit_product = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* carry = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* aux = new_gate_bootstrapping_ciphertext(ck->params);
    LweSample* prev = new_gate_bootstrapping_ciphertext(ck->params);

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
}

// LweSample* TFHE_INT::multiply(const LweSample* ca, const LweSample* cb, 
//     const TFheGateBootstrappingCloudKeySet* ck)
// {
//     LweSample* result = new_gate_bootstrapping_ciphertext_array(N*2, ck->params);
//     LweSample* nr1 = new_gate_bootstrapping_ciphertext_array(N*2, ck->params);
//     LweSample* nr2 = new_gate_bootstrapping_ciphertext_array(N*2, ck->params);
// 	clock_t begin = clock();
//     for(int i=0; i<N; i++){
//         bootsCOPY(&nr1[i], &ca[0], ck);
//         bootsCOPY(&nr2[i], &cb[0], ck);
//         bootsCONSTANT(&result[i], 0, ck);
//     }
//     for(int i=N; i<2*N; i++){
//         bootsCOPY(&nr1[i], &ca[i-N], ck);
//         bootsCOPY(&nr2[i], &cb[i-N], ck);
//         bootsCONSTANT(&result[i], 0, ck);
//     }


//     int pas=0;
//     LweSample* bit_product = new_gate_bootstrapping_ciphertext(ck->params);
//     LweSample* carry = new_gate_bootstrapping_ciphertext(ck->params);
//     LweSample* aux = new_gate_bootstrapping_ciphertext(ck->params);
//     LweSample* prev = new_gate_bootstrapping_ciphertext(ck->params);

//     for(int i=0; i<2*N; i++){
// 	    bootsCONSTANT(carry, 0, ck);

//         for(int j=0; j<2*N-pas; j++){
//             bootsCOPY(prev, &result[2*N-1-j-pas], ck);
//             bootsAND(bit_product, &nr1[2*N-1-i], &nr2[2*N-1-j], ck);
//             bootsXOR(aux, carry, bit_product, ck);
//             bootsXOR(&result[2*N-1-j-pas], aux, &result[2*N-1-j-pas], ck);
//             bootsAND(aux, bit_product, carry, ck);
//             bootsAND(bit_product, bit_product, prev, ck);
//             bootsOR(aux, aux, bit_product, ck);
//             bootsAND(carry, carry, prev, ck);
//             bootsOR(carry, aux, carry, ck);
//         }
//         pas++;
//     }
// }