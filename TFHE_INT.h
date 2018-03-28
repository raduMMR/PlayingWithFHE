#include <tfhe/tfhe.h>

/**
 * TFHE_INT is the homomorphic equivalent of int8_t
 * data type. This class encapsulates an integer
 * and provider the common operations used for integers:
 * addition, multiplication,
*/
class TFHE_INT_8 {
    static const int N = 8;
public:

    static LweSample* encrypt_int(const int number, const TFheGateBootstrappingSecretKeySet* sk);

    static int decrypt_int(const LweSample* enc_int, const TFheGateBootstrappingSecretKeySet* sk);

    // static int decrypt_int16(const LweSample* enc_int, const TFheGateBootstrappingSecretKeySet* sk);

    static LweSample* add(const LweSample* nr1, const LweSample* nr2, const TFheGateBootstrappingCloudKeySet* ck);

    static LweSample* multiply(const LweSample* nr1, const LweSample* nr2, const TFheGateBootstrappingCloudKeySet* ck);

};