//
//  TP6_RSA
//
#include <stdio.h>
#include <iostream>
#include <gmp.h>

bool isProbablyPrime(const mpz_t n, const unsigned int k);
void myNextPrime(mpz_t dest, const mpz_t src);
void myPowm(mpz_t m, const mpz_t g, const mpz_t k, const mpz_t p);
int myInvert(mpz_t dest, const mpz_t &n, const mpz_t &m); 

//################################ RSA ############################### 

//################################ QUESTION 1 ########################
#define BITSTRENGTH 1024             /* size of modulus (n) in bits */
#define PRIMESIZE (BITSTRENGTH / 2) /* size of the primes p and q  */
#define PLAINTEXT "123456"



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
    myNextPrime(p, p);
    myNextPrime(q, q);



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
    // myInvert(d,e,x); //Segmantation Fault

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
   myPowm(ciphertext, plaintext, publicKey, modulus);
}

// Fonction de déchiffrement RSA
void decryptRSA(mpz_t decryptedtext, const mpz_t ciphertext, const mpz_t privateKey, const mpz_t modulus)
{
    myPowm(decryptedtext, ciphertext, privateKey, modulus);
}
//################################ RSA ############################### 




//################################ GMP ############################### 
//################################ QUESTION 3 ########################
//----
bool isProbablyPrime(const mpz_t n, const unsigned int k){
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    
    if(mpz_cmp_ui(n,3) == 0){
        return true;
    }
    
    
    // Write n −1 as t×2^s with t odd by factoring powers of 2 from n −1
    unsigned int s = 0;
    mpz_t t, n_minus_one;
    mpz_inits(t, n_minus_one, NULL);
    mpz_set(n_minus_one, n);
    mpz_sub_ui(n_minus_one, n_minus_one, 1);

    mpz_set(t, n_minus_one);
    while (mpz_even_p(t))
    {
        mpz_divexact_ui(t, t, 2);
        ++s;
    }

    mpz_t a, square;
    mpz_inits(a,square,NULL);
    mpz_set_ui(square, 2);
    for (unsigned int i = 0; i < k; i++)
    {
        //Pick a randomly in the range [2, n-1]
        mpz_urandomm(a, state, n_minus_one);
        mpz_add_ui(a, a, 2);

        // x <- a^t mod n
        myPowm(a,a, t, n);

        if (mpz_cmp_ui(a, 1) == 0 || mpz_cmp(a, n_minus_one) == 0)
        {
            continue; // Inconclusive, try the next iteration
        }


        for (unsigned int i = 1; i < s; i++)
        {
            myPowm(a, a, square, n);
            if (mpz_cmp_ui(a,1)==0)
            {
                //n is composite
                gmp_randclear(state);
                mpz_clears(a, square, t, n_minus_one);
                return false;
            }

            if (mpz_cmp(a, n_minus_one)==0)
            {
                break;
            }
        }

        if (mpz_cmp(a, n_minus_one) != 0)
        {
            // n is composite
            mpz_clears(t, n_minus_one, a, NULL);
            return false; 
        }
    }
    
    return true;
}

void myNextPrime(mpz_t dest, const mpz_t src){
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


//----
void myPowm(mpz_t m, const mpz_t g, const mpz_t k, const mpz_t p) {
    // Créer des copies locales pour travailler avec
    mpz_t g_copy, k_copy, p_copy;
    mpz_inits(g_copy, k_copy, p_copy, NULL);

    mpz_set(g_copy, g);
    mpz_set(k_copy, k);
    mpz_set(p_copy, p);

    // Si k_copy est négatif, inverser g_copy et rendre k_copy positif
    if (mpz_sgn(k_copy) < 0) {
        mpz_invert(m, g_copy, p_copy);
        mpz_neg(m, m);
        mpz_neg(k_copy, k_copy);
    }

    // Si k_copy est égal à 0, assigner 1 à m
    if (mpz_sgn(k_copy) == 0) {
        mpz_set_ui(m, 1);
        return;
    }

    mpz_t result, y;
    mpz_inits(result, y, NULL);

    mpz_set_ui(result, 1);
    mpz_set_ui(y, 1);

    while (mpz_cmp_ui(k_copy, 1) > 0) {
        if (mpz_even_p(k_copy)) {
            mpz_mul(result, result, g_copy);
            mpz_mod(result, result, p_copy);
            mpz_mul(g_copy, g_copy, g_copy);
            mpz_mod(g_copy, g_copy, p_copy);
            mpz_tdiv_q_2exp(k_copy, k_copy, 1);  // Utiliser mpz_tdiv_q_2exp pour diviser k_copy par 2
        } else {
            mpz_mul(y, g_copy, y);
            mpz_mod(y, y, p_copy);
            mpz_mul(g_copy, g_copy, g_copy);
            mpz_mod(g_copy, g_copy, p_copy);
            mpz_sub_ui(k_copy, k_copy, 1);
            mpz_tdiv_q_2exp(k_copy, k_copy, 1);  // Utiliser mpz_tdiv_q_2exp pour diviser k_copy par 2
        }
    }

    // Calcul final de m
    mpz_mul(m, g_copy, y);
    mpz_mod(m, m, p_copy);

    // Libérer la mémoire
    mpz_clears(result, y, g_copy, k_copy, p_copy, NULL);
}


//----
// ATTENTION : CETTE FONCTION NE MARCHE PAS -> Segmentation fault lors de la loop
void myEuclideanExtended(mpz_t pgcd, mpz_t sOut, mpz_t tOut, const mpz_t aIn, const mpz_t bIn) {
    // Initialiser les variables pour l'identité de Bézout : as + bt = gcd(a, b)
    mpz_t s, oldS, t, oldT, remainder, oldRemainder;
    mpz_init_set_ui(s, 0);                  // Initialiser s avec 0
    mpz_init_set_ui(oldS, 1);               // Initialiser oldS avec 1
    mpz_init_set_ui(t, 1);                  // Initialiser t avec 1
    mpz_init_set_ui(oldT, 0);               // Initialiser oldT avec 0
    mpz_init_set(remainder, aIn);           // Initialiser remainder avec a
    mpz_init_set(oldRemainder, bIn);        // Initialiser oldRemainder avec b

    // Variables temporaires pour les calculs
    mpz_t quotient, temp, product, subtraction;
    mpz_init(quotient);
    mpz_init(temp);
    mpz_init(product);
    mpz_init(subtraction);

    // Boucle principale de l'algorithme d'Euclide étendu
    while (mpz_get_ui(remainder) != 0) {
        // Calculer le quotient et mettre à jour remainder et oldRemainder
        mpz_tdiv_q(quotient, oldRemainder, remainder);

        mpz_set(temp, remainder);
        mpz_mul(product, quotient, remainder);
        mpz_sub(subtraction, oldRemainder, product);
        mpz_set(remainder, subtraction);
        mpz_set(oldRemainder, temp);

        // Mettre à jour s, t en fonction du quotient
        mpz_set(temp, s);
        mpz_mul(product, quotient, s);
        mpz_sub(subtraction, oldS, product);
        mpz_set(s, subtraction);
        mpz_set(oldS, temp);

        mpz_set(temp, t);
        mpz_mul(product, quotient, t);
        mpz_sub(subtraction, oldT, product);
        mpz_set(t, subtraction);
        mpz_set(oldT, temp);
    }

    // Définir les valeurs de retour selon l'identité de Bézout
    mpz_set(pgcd, oldRemainder);
    mpz_set(sOut, oldS);
    mpz_set(tOut, oldT);

    // Libérer la mémoire des variables temporaires
    mpz_clears(quotient, temp, product, subtraction);

    // Libérer la mémoire des variables de l'identité de Bézout
    mpz_clears(s, oldS, t, oldT, remainder, oldRemainder);
}


int myInvert(mpz_t dest, const mpz_t &n, const mpz_t &m) {
    mpz_t s, t, gcd;
    mpz_inits(s, t, gcd, NULL);

    std::cout << "prout" << std::endl;
    std::cout << "Dest = " << mpz_get_str(NULL, 10, gcd) << std::endl;
    myEuclideanExtended(gcd, s, t, n, m);
    std::cout << "Dest = " << mpz_get_str(NULL, 10, gcd) << std::endl;
    std::cout << "prout" << std::endl;
    if (mpz_cmp_ui(gcd, 1) != 0) {
        // L'inverse n'existe pas
        mpz_clears(s, t, gcd, NULL);
        return 0;
    }

    // Calculer l'inverse modulaire positif
    mpz_mod(dest, s, n);

    // S'assurer que le résultat est non négatif
    while (mpz_sgn(dest) == -1) {
        mpz_add(dest, dest, n);
    }

    mpz_clears(s, t, gcd, NULL);
    // Succès
    return 1;
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
    mpz_set_str(plaintext, PLAINTEXT, 10); // Exemple de message
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

//Code à rendre