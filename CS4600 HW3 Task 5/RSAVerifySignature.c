#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>

/* Function to print a BIGNUM variable in hexadecimal format */
void printBN(const char* msg, BIGNUM* a)
{
    char* number_str = BN_bn2hex(a);
    printf("%s %s", msg, number_str);
    OPENSSL_free(number_str);
}


int main() {
    // Declare and initialize variables and context
    BIGNUM* n = BN_new(); // modulus n
    BIGNUM* e = BN_new(); // public exponent
    BIGNUM* m = BN_new(); // plaintext message
    BIGNUM* s = BN_new(); // signature
    BIGNUM* decrypted_m = BN_new(); // decrypted plaintext message
    BN_CTX* ctx = BN_CTX_new(); // context


    // Initialize known values for n, e, and s
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    // Set the plaintext message
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e"); // "Launch a missile."



    // Verify the signature by calculating m^e (mod n) and comparing with k
    BN_mod_exp(decrypted_m, s, e, n, ctx); // decrypted_m = s^e (mod n)
    int verified = BN_cmp(m, decrypted_m) == 0;

    // Print the results
    printf("Plaintext message: \"Launch a missile.\"\n");
    printBN("Signature:", s);
    printf("\n");
    printf("Signature verified: %s\n", verified ? "yes" : "no");


    // Free memory
    BN_free(n);
    BN_free(e);
    BN_free(m);
    BN_free(s);
    BN_free(decrypted_m);
    BN_CTX_free(ctx);


    return 0;
}