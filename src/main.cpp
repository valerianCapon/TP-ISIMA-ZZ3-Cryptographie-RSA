//
//  TP6_RSA
//

#include <stdio.h>
#include <iostream>
#include <gmp.h>

//################################ RSA ############################### 

//################################ QUESTION 1 ########################
#define BITSTRENGTH 1024             /* size of modulus (n) in bits */
#define PRIMESIZE (BITSTRENGTH / 2) /* size of the primes p and q  */


// Fonction pour générer une paire de clés RSA
void generateRSAKeys(mpz_t publicKey, mpz_t privateKey, mpz_t modulus, unsigned int keySize)
{
    // Générer deux nombres premiers aléatoires
    mpz_t p, q;
    mpz_inits(p, q, NULL);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    mpz_urandomb(p, state, keySize / 2);
    mpz_urandomb(q, state, keySize / 2);
    mpz_nextprime(p, p);
    mpz_nextprime(q, q);




    // Calculer le module (n = p * q)
    mpz_mul(modulus, p, q);

    // Calculer la fonction totient (x = (p - 1) * (q - 1))
    mpz_t x;
    mpz_init(x);
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(x, p, q);

    // Choisir un exposant public (e) relativement premier à x
    mpz_t e;
    mpz_t tmp;
    mpz_inits(e, tmp, NULL);
    do
    {
        mpz_urandomb(e, state, keySize / 2);
        mpz_gcd(tmp, e, x);
    } while (mpz_cmp_ui(tmp, 1) != 0);

    // Calculer l'exposant privé (d)
    mpz_t d;
    mpz_init(d);
    mpz_invert(d, e, x);

    // Copier les résultats dans les paramètres de sortie
    mpz_set(publicKey, e);
    mpz_set(privateKey, d);

    // Libérer la mémoire
    mpz_clears(p, q, x, e, d, tmp, NULL);
    gmp_randclear(state);
}

//################################ QUESTION 2 #########################
// Fonction de chiffrement RSA
void encryptRSA(mpz_t ciphertext, const mpz_t plaintext, const mpz_t publicKey, const mpz_t modulus)
{
    mpz_powm(ciphertext, plaintext, publicKey, modulus);
}

// Fonction de déchiffrement RSA
void decryptRSA(mpz_t decryptedtext, const mpz_t ciphertext, const mpz_t privateKey, const mpz_t modulus)
{
    mpz_powm(decryptedtext, ciphertext, privateKey, modulus);

}
//################################ RSA ############################### 




//################################ GMP ############################### 
//################################ QUESTION 2 ########################


bool isProbablyPrime(mpz_t n, unsigned int k){
    unsigned int s = 0;
    mpz_t t;
    mpz_inits(t, NULL);
    if(mpz_cmp_ui(n,3) == 0){
        return true;
    }
    // Write n −1 as t ×2s with t odd by factoring powers of 2 from n −1
    mpz_set(t, n);
    while (mpz_even_p(t))
    {
        mpz_divexact_ui(t, t, 2);
        ++s;
    }
    
    


    return false;
}



void myNextPrime(mpz_t dest, mpz_t src){
    unsigned int k = 10;
    mpz_set(dest,src);

    if (mpz_cmp_ui(dest, 2) <= 0 && !mpz_odd_p(dest))
    {
        std::cout << "Error : myNextPrime, given value is not greater then 2 or not odd" << std::endl;
        exit(0);
    }
    
    while (!isProbablyPrime(dest, k))
    {
        mpz_add_ui(dest, dest, 1);
    }
    
}


//################################ GMP ############################### 





int main()
{
    // Déclarer les variables pour les clés
    mpz_t publicKey, privateKey, modulus;
    mpz_inits(publicKey, privateKey, modulus, NULL);

    // Appeler la fonction pour générer les clés RSA
    generateRSAKeys(publicKey, privateKey, modulus, BITSTRENGTH);

    // Afficher les résultats
    gmp_printf("Public Key (e): %Zd\n", publicKey);
    gmp_printf("Private Key (d): %Zd\n", privateKey);
    gmp_printf("Modulus (n): %Zd\n", modulus);

    // Message à chiffrer
    mpz_t plaintext, ciphertext, decryptedtext;
    mpz_inits(plaintext, ciphertext, decryptedtext, NULL);
    mpz_set_str(plaintext, "12345", 10); // Exemple de message
    std::cout << "Message : " << mpz_get_str(NULL, 10, plaintext) << std::endl;


    // Chiffrement
    encryptRSA(ciphertext, plaintext, publicKey, modulus);
    std::cout << "Message chiffré : " << mpz_get_str(NULL, 10, ciphertext) << std::endl;

    // Déchiffrement
    decryptRSA(decryptedtext, ciphertext, privateKey, modulus);
    std::cout << "Message déchiffré : " << mpz_get_str(NULL, 10, decryptedtext) << std::endl;

    // Libérer la mémoire
    mpz_clears(publicKey, privateKey, modulus, NULL);
    mpz_clears(plaintext, ciphertext, decryptedtext, NULL);

    return 0;
}








// /* Main subroutine */
// int main()
// {
//     /* Initialize the GMP integers */
//     mpz_init(d);
//     mpz_init(e);
//     mpz_init(n);

//     /* This function creates the keys. The basic algorithm is...
//      *
//      *  1. Generate two large distinct primes p and q randomly
//      *  2. Calculate n = pq and x = (p-1)(q-1)
//      *  3. Select a random integer e (1<e<x) such that gcd(e,x) = 1
//      *  4. Calculate the unique d such that ed = 1(mod x)
//      *  5. Public key pair : (e,n), Private key pair : (d,n)
//      *
//      */

//     /* This function creates the keys. The basic algorithm is...
//      *
//      *  1. Generate two large distinct primes p and q randomly
//      *  2. Calculate n = pq and x = (p-1)(q-1)
//      *  3. Select a random integer e (1<e<x) such that gcd(e,x) = 1
//      *  4. Calculate the unique d such that ed = 1(mod x)
//      *  5. Public key pair : (e,n), Private key pair : (d,n)
//      *
//      */

//     /*
//      *  Step 1 : Get two large primes.
//      */
//     mpz_t p,q;
//     mpz_init(p);
//     mpz_init(q);

//     mpz_init_set_str(p, "47", 0);
//     mpz_init_set_str(q, "71", 0);
//     char p_str[1000];
//     char q_str[1000];
//     mpz_get_str(p_str,10,p);
//     mpz_get_str(q_str,10,q);

//     std::cout << "Random Prime 'p' = " << p_str <<  std::endl;
//     std::cout << "Random Prime 'q' = " << q_str <<  std::endl;

//     /*
//      *  Step 2 : Calculate n (=pq) ie the 1024 bit modulus
//      *  and x (=(p-1)(q-1)).
//      */
//     char n_str[1000];
//     mpz_t x;
//     mpz_init(x);

//     /* Calculate n... */
//     mpz_mul(n,p,q);
//     mpz_get_str(n_str,10,n);
//     std::cout << "\t n = " << n_str << std::endl;

//     /* Calculate x... */
//     mpz_t p_minus_1,q_minus_1;
//     mpz_init(p_minus_1);
//     mpz_init(q_minus_1);

//     mpz_sub_ui(p_minus_1,p,(unsigned long int)1);
//     mpz_sub_ui(q_minus_1,q,(unsigned long int)1);

//     mpz_mul(x,p_minus_1,q_minus_1);
//     char phi_str[1000];
//     mpz_get_str(phi_str,10,x);
//     std::cout << "\t phi(n) = " << phi_str << std::endl;

//     /*
//      *  Step 3 : Get small odd integer e such that gcd(e,x) = 1.
//      */
//     mpz_init_set_str(e, "79", 0);
//     char e_str[1000];
//     mpz_get_str(e_str,10,e);
//     std::cout << "\t e = " << e_str << std::endl;

//     /*
//      *  Step 4 : Calculate unique d such that ed = 1(mod x)
//      */
//     mpz_init_set_str(d, "1019", 0);
//     char d_str[1000];
//     mpz_get_str(d_str,10,d);
//     std::cout << "\t d = " << d_str << std::endl << std::endl;

//     /*
//      *  Step 5 : Print the public and private key pairs...
//      */
//     std::cout << "Public Keys  (e,n): ( " << e_str <<" , " << n_str << " )" << std::endl;
//     std::cout << "Private Keys (d,n): ( " << d_str <<" , " << n_str << " )" << std::endl;
//     /*
//      *  Encrypt
//      */

//     //TODO

//     /* Clean up the GMP integers */
//     mpz_clear(p_minus_1);
//     mpz_clear(q_minus_1);
//     mpz_clear(x);
//     mpz_clear(p);
//     mpz_clear(q);

//     mpz_clear(d);
//     mpz_clear(e);
//     mpz_clear(n);

//     mpz_clear(M);
//     mpz_clear(c);
// }
