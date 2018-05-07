#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <cassert>
#include <assert.h>
#include <cstdio>

// Global variables.
FHEcontext *context;
FHESecKey *secretKey;
EncryptedArray *ea;
static bool noPrint = false;
int NSLOTS=0;

double clock_diff(const clock_t &t1, const clock_t &t2){
    return double(t2 - t1) / CLOCKS_PER_SEC;
}

void setGlobalVariables(long p, long r, long d, long c, long k, long w, 
               long L, long m, const Vec<long>& gens, const Vec<long>& ords);

void cleanGlobalVariables();

Ctxt* encryptBitVal (const vector<long> bit);
vector<Ctxt*> encryptIntVal (const vector<long> val, int t_bits);

vector<long> decryptBitVal (const Ctxt *ct);
vector<long> decryptIntVal(const vector<Ctxt*> enc_bits);


Ctxt* compute_z (int i, int j, vector<Ctxt*>& ct_x, vector<Ctxt*>& ct_y);
Ctxt* compute_t (int i, int j, vector<Ctxt*>& ct_x, vector<Ctxt*>& ct_y);
Ctxt* compute_s (int i, int j, vector<Ctxt*>& ct_x, vector<Ctxt*>& ct_y);


vector<Ctxt*> hom_LBP(vector<Ctxt*> enc_pixeli, vector<vector<Ctxt*>> vecini, int t_bits);

void test_LBP() {
    assert(NSLOTS != 0);

    int t_bits=8;

    vector<long> pixeli;
    for(int i=0; i<NSLOTS; i++) {
        pixeli.push_back(rand() % 256);
    }

    vector<vector<long>> vecini(t_bits);
    for(int i=0; i<t_bits; i++) {
        for(int j=0; j<NSLOTS; j++) {
            // toti vecinii de pe pozitia i ai pixelilor.
            vecini[i].push_back(rand() % 256);
        }
    }

    vector<long> lbp_codes(NSLOTS);
    for(int i=0; i<NSLOTS; i++) {
        lbp_codes[i] = 0;
        for(int j=0; j<t_bits; j++) {
            lbp_codes[i] |= (vecini[j][i] >= pixeli[i]) << j;
        }
    }

    // encrypting pixels.
    cout << "Encrypting pixels ...\n";
    vector<vector<Ctxt*> > enc_vecini(t_bits);
    for(int i=0; i<t_bits; i++) {
        enc_vecini[i] = encryptIntVal(vecini[i], t_bits);
    }
    vector<Ctxt*> enc_pixeli = encryptIntVal(pixeli, t_bits);
    cout << "Done pixels encryption.\n";

    // computing LBP codes.
    cout << "Homomorphic LBP computation ...\n";
    vector<Ctxt*> hom_lbp = hom_LBP(enc_pixeli, enc_vecini, t_bits);
    cout << "Done LBP computation.\n";

    // comparison.
    bool success = true;
    vector<long> dec_lbp = decryptIntVal(hom_lbp);
    for(int i=0; i<dec_lbp.size(); i++) {
        if(dec_lbp[i] != lbp_codes[i]) {
            cout << "ESEC\n";
            success = false;
            break;
        }
    }
    if( success == true) {
        cout << "Succes!!!!!!!!\n";
    }

    // cleaning up.
    cout << "Cleaning up ctxts...\n";
    for(int i=0; i<t_bits; i++) {
        for(int j=0; j<t_bits; j++) {
            delete enc_vecini[i][j];
        }
    }

    for(int i=0; i<t_bits; i++) {
        delete enc_pixeli[i];
    }
    cout << "Done cleaning up ctxts.\n";

}


// void test_EncDec() {
//     int t_bits = 8;
//     vector<Ctxt*> vec_ctxt;
//     for(int i=0; i<128; i++) {
//         int val = rand() % 256;
//         vec_ctxt = encryptIntVal(val, t_bits);
//         if(val != decryptIntVal(vec_ctxt)) {
//             cout << "ESEC ENC_DEC\n";
//             cout << "val=" << val << ", dec_val = " << decryptIntVal(vec_ctxt);
//         }
//         for(int j=0; j<vec_ctxt.size(); j++) {
//             delete vec_ctxt[j];
//         }
//     }
// }

void test_Compute_s() {

    int t_bits = 8;
    int val1, val2;
    vector<Ctxt*> nr1;
    vector<Ctxt*> nr2;

    for(int i=0; i<128; i++) {
        val1 = rand() % 256;
        val2 = rand() % 256;

        vector<long> batch1(NSLOTS, val1);
        vector<long> batch2(NSLOTS, val2);

        nr1 = encryptIntVal(batch1, t_bits);
        nr2 = encryptIntVal(batch2, t_bits);

        Ctxt *gte = compute_s(0, t_bits, nr1, nr2);
        // cout << val1 << " >= " << val2 << " => " << decryptBitVal(gte) << endl;

        bool success = true;
        vector<long> plain_gte = decryptBitVal(gte);
        for(int j=0; j<NSLOTS; j++) {
            if(plain_gte[j] != (val1 >= val2)) {
                cout << "Rezultat gresit, slot " << j << endl;
                success = false;
                break;
            }
        }

        // cleaning.
        delete gte;
        for(int j=0; j<nr1.size(); j++) {
            delete nr1[j];
        }
        for(int j=0; j<nr2.size(); j++) {
            delete nr2[j];
        }

        if(success == true) {
            cout << "Test " << i << " incheiat cu succes.\n";
        }
        else {
            cout << "Test " << i << " esuat\n";
            break;
        }
    }

}

int main(int argc, char **argv) {

    ArgMapping amap;

    bool dry=false;
    amap.arg("dry", dry, "dry=1 for a dry-run");

    long R=1;
    amap.arg("R", R, "number of rounds");

    long p=2;
    amap.arg("p", p, "plaintext base");

    long r=1;
    amap.arg("r", r,  "lifting");

    long d=1;
    amap.arg("d", d, "degree of the field extension");
    amap.note("d == 0 => factors[0] defines extension");

    long c=2;
    amap.arg("c", c, "number of columns in the key-switching matrices");

    
    long k=80;
    amap.arg("k", k, "security parameter");

    long L=0;
    amap.arg("L", L, "# of levels in the modulus chain",  "heuristic");

    long s=0;
    amap.arg("s", s, "minimum number of slots");

    long repeat=1;
    amap.arg("repeat", repeat,  "number of times to repeat the test");

    long chosen_m=0;
    amap.arg("m", chosen_m, "use specified value as modulus", NULL);

    Vec<long> mvec;
    amap.arg("mvec", mvec, "use product of the integers as  modulus", NULL);
    amap.note("e.g., mvec='[5 3 187]' (this overwrite the m argument)");

    Vec<long> gens;
    amap.arg("gens", gens, "use specified vector of generators", NULL);
    amap.note("e.g., gens='[562 1871 751]'");

    Vec<long> ords;
    amap.arg("ords", ords, "use specified vector of orders", NULL);
    amap.note("e.g., ords='[4 2 -4]', negative means 'bad'");

    long seed=0;
    amap.arg("seed", seed, "PRG seed");

    long nt=1;
    amap.arg("nt", nt, "num threads");

    amap.arg("noPrint", noPrint, "suppress printouts");

    amap.parse(argc, argv);

    SetSeed(ZZ(seed));
    SetNumThreads(nt);
    
    if (L==0) { // determine L based on R,r
        L = 3*R+3;
        if (p>2 || r>1) { // add some more primes for each round
        long addPerRound = 2*ceil(log((double)p)*r*3)/(log(2.0)*FHE_p2Size) +1;
        L += R * addPerRound;
        }
    }

    long w = 64; // Hamming weight of secret key
    //  long L = z*R; // number of levels

    if (mvec.length()>0)
        chosen_m = computeProd(mvec);
    std::cout << argv[0] << ": ";
    long m = FindM(k, L, c, p, d, s, chosen_m, !noPrint);

    setDryRun(dry);
    cout << "Generare context ...\n";
    setGlobalVariables(p, r, d, c, k, w, L, m, gens, ords);
    cout << "Terminat de generat context.\n";

    // test_Compute_s();
    clock_t begin = clock();
    test_LBP();
    clock_t end = clock();

    cout << "TIMP: " << clock_diff(begin, end) << " secunde.\n";

    cout << "Cleaning up ...\n";
    cleanGlobalVariables();
    cout << "Terminat cleaning up.\n";

    cout << "Program terminat.\n";
    return 0;
}

/*************************************************************************************/
void setGlobalVariables(long p, long r, long d, long c, long k, long w, 
               long L, long m, const Vec<long>& gens, const Vec<long>& ords) {
    
    vector<long> gens1, ords1;
    convert(gens1, gens);
    convert(ords1, ords);

    context = new FHEcontext(m, p, r, gens1, ords1);
    buildModChain(*context, L, c);

    ZZX G;
    if (d == 0)
        G = context->alMod.getFactorsOverZZ()[0];
    else
        G = makeIrredPoly(p, d); 

    secretKey = new FHESecKey(*context);
    // const FHEPubKey& publicKey = secretKey;
    secretKey->GenSecKey(w); // A Hamming-weight-w secret key
    addSome1DMatrices(*secretKey); // compute key-switching matrices that we need

    ea = new EncryptedArray(*context, G);

    NSLOTS = ea->size();
}

/*************************************************************************************/
void cleanGlobalVariables() {
    delete context;
    delete secretKey;
    delete ea;
}

/*************************************************************************************/
Ctxt* encryptBitVal (const vector<long> bits) {
    const FHEPubKey& publicKey = *secretKey;
    Ctxt* ctxt = new Ctxt(publicKey);
    ea->encrypt(*ctxt, publicKey, bits);
    return ctxt;
}

/*************************************************************************************/
vector<Ctxt*> encryptIntVal (const vector<long> val, int t_bits) {
    vector<Ctxt*> vec_ctxt(t_bits);
    for(int i=0; i<t_bits; i++){
        vector<long> bits(NSLOTS);
        for(int j=0; j<NSLOTS; j++) {
            bits[j] = (val[j] >> i) & 1;
        }
        vec_ctxt[i] = encryptBitVal(bits);
    }
    return vec_ctxt;
}

/*************************************************************************************/
vector<long> decryptBitVal (const Ctxt *ct) {
    vector<long> decs;
    ea->decrypt(*ct, *secretKey, decs);
    return decs;
}

/*************************************************************************************/
vector<long> decryptIntVal(const vector<Ctxt*> enc_bits) {
    vector<long> vals(NSLOTS, 0);
    for(int i=0; i<enc_bits.size(); i++) {
        vector<long> decrypted_bits = decryptBitVal(enc_bits[i]);
        for(int j=0; j<NSLOTS; j++) {
            vals[j] |= decrypted_bits[j] << i;
        }
    }
    return vals;
}

/*************************************************************************************/
Ctxt* compute_z (int i, int j, vector<Ctxt*>& ct_x, vector<Ctxt*>& ct_y)
{
	Ctxt *ret = NULL;
	if (j == 1)
	{
		ret = encryptBitVal(vector<long>(NSLOTS, 1));
		*ret += *ct_x[i]; 
		*ret += *ct_y[i];
		return ret;
	}
	
	int l;
	l = (j%2 == 0) ? j/2: j/2 + 1; 
	//cout << endl << "compute_z...." << "j="<<j<< "; l=" << l; 
		
	ret = compute_z(i+l, j-l, ct_x, ct_y);
	Ctxt *ct = compute_z (i, l, ct_x, ct_y);	
	*ret *= *ct;
	delete ct;
	
	return ret;
}

/*************************************************************************************/
Ctxt* compute_t (int i, int j, vector<Ctxt*>& ct_x, vector<Ctxt*>& ct_y)
{
	Ctxt *ret = NULL;
	if (j == 1)
	{
		ret  = new Ctxt (*ct_x[i]);
		*ret *= *ct_y[i]; 
		*ret += *ct_x[i];
		return ret;
	}
			
	int l;
	l = (j%2 == 0) ? j/2: j/2 + 1; 

	ret = compute_t(i+l, j-l, ct_x, ct_y);
	Ctxt *ct_z = compute_z (i+l, j-l, ct_x, ct_y);
	Ctxt *ct_t = compute_t (i, l, ct_x, ct_y);
	
	*ct_z *= *ct_t;		
	*ret += *ct_z;	
	
	delete ct_z;
	delete ct_t;	
	return ret;	
}

/*************************************************************************************/
Ctxt* compute_s (int i, int j, vector<Ctxt*>& ct_x, vector<Ctxt*>& ct_y)
{
	Ctxt *ret = NULL;
	if (j == 1)
	{
		Ctxt *ct_1 = encryptBitVal(vector<long>(NSLOTS, 1));
		ret  = new Ctxt (*ct_x[i]);
		*ret *= *ct_y[i]; 
		*ret += *ct_y[i];
		*ret += *ct_1;
		
		delete ct_1;		
		return ret;
	}
			
	int l;
	l = (j%2 == 0) ? j/2: j/2 + 1; 

	ret = compute_t(i+l, j-l, ct_x, ct_y);
	Ctxt *ct_z = compute_z (i+l, j-l, ct_x, ct_y);
	Ctxt *ct_s = compute_s (i, l, ct_x, ct_y);
	
	*ct_z *= *ct_s;	
	*ret += *ct_z;	
	
	delete ct_z;
	delete ct_s;	
	return ret;	
}

/*************************************************************************************/
vector<Ctxt*> hom_LBP(vector<Ctxt*> enc_pixeli, vector<vector<Ctxt*>> vecini, int t_bits) {
    vector<Ctxt*> lbp_codes;
    for(int i=0; i<t_bits; i++) {
        lbp_codes.push_back(compute_s(0, t_bits, vecini[i], enc_pixeli));
    }
    return lbp_codes;
}

/*************************************************************************************/
