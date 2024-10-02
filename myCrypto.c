/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  Team #   MUST WRITE YOUR TEAM NUMBER HERE
     1- MUST WRITE YOUR FULL NAME
     2- MUST WRITE YOUR FULL NAME

Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}



// Encrypts plaintext
unsigned encrypt(uint8_t *pPlainText, unsigned plainText_len,
    const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText)
{
    int status;
    unsigned len = 0, encryptedLen = 0;

    // init encrypt operation
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        handleErrors("encrypt: failed to create CTX");
    
    
    status = EVP_EncryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");
    
    // Perform the encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    // Advance ciphertext pointer
    pCipherText += len;

    // Finalize encryption
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;
}

// Decrypts ciphertext
unsigned decrypt(uint8_t *pCipherText, unsigned cipherText_len,
    const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int status;
    unsigned len = 0, decryptedLen = 0;

    // init encrypt operation
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        handleErrors("decrypt: failed to create CTX");
    
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");
    
    // Perform the encryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    // Advance ciphertext pointer
    pDecryptedText += len;

    // Finalize encryption
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;
}

//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen' 
//
// Returns: 
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    // Guard against incoming NULL pointers
    if (!sig || !sigLen || !privKey || !inData || inLen == 0)
        handleErors("myCrypto: Null pointer in privKeySign");

    // Create, Initialize, and Pad a context for RSA private-key signing
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new(privKey, NULL);

    if (!ctx)
        handleErrors("myCrypto: Couldn't create context");
    
    if ( !EVP_PKEY_sign_init(ctx) )
        handleErrors("myCrypto: Couldn't sign init ctx");

    if ( !EVP_PKEY_CTX_set_rsa_padding( ctx, RSA_PKCS1_OAEP_PADDING ) )
        handleErrors("myCrypto: Couldn't set rsa padding");

    // Determine how big the size of the signature could be
    size_t cipherLen; // Why do we need this what
    if ( !EVP_PKEY_sign(ctx, NULL, sigLen, inData, inLen) )
        handleErrors("myCrypto: Couldn't retrieve cipherLen");

    // size_t cipherLen = EVP_PKEY_size(privKey);
    // if ( !cipherLen )
    //     handleErrors("myCrypto: Couldn't retrieve cipherLen");

    // Allocate memory for ciphertext
    uint8_t *sig = malloc(sigLen);

    if  ( !EVP_PKEY_sign(ctx, sig, sigLen, inData, inLen) )
        handleErrors("myCrypto: Couldn't sign");
    // Next allocate memory for the ciphertext

    // Now, actually sign the inData using EVP_PKEY_sign( )

    // All is good
    EVP_PKEY_CTX_free( ctx );     // remember to do this if any failure is encountered above

    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !pubKey  ||  !data  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA public-key signature verification
    EVP_PKEY_CTX *ctx;

    // EVP_PKEY_CTX_new( );
    // EVP_PKEY_verify_init( )
    // EVP_PKEY_CTX_set_rsa_padding(  )

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify( /* .... */ ) ;

    //  free any dynamically-allocated objects 

    return decision ;

}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    EVP_MD_CTX *mdCtx ;
    size_t nBytes ;
    unsigned int  mdLen ;

	// Use EVP_MD_CTX_create() to create new hashing context    
    // EVP_MD_CTX_new()
    
    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the HASH_ALGORITHM() hashing function 
    // EVP_DigestInit(  )

    while ( 1 )   // Loop until end-of input file
    {
        // Read a chund of input from fd_in. Exit the loop when End-of-File is reached

        // VP_DigestUpdate( )
        
        // if ( fd_out > 0 ) send the above chunk of data to fd_out
            
    }

    // EVP_DigestFinal( )
    
    // EVP_MD_CTX_destroy( );

    return mdLen ;
}

