/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  Team #   MUST WRITE YOUR TEAM NUMBER HERE
     1- Patrick Dodds
     2- Conor McFadden

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

int privKeySign(uint8_t **sig, size_t *sigLen, EVP_PKEY *privKey, uint8_t *inData, size_t inLen) {
    if (!sig || !sigLen || !privKey || !inData || inLen == 0) {
        handleErrors("Null pointer or zero-length input");
        return 0;
    }

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) handleErrors("Could not create context");

    EVP_PKEY_CTX *ctx = NULL;
    if (EVP_DigestSignInit(mdCtx, &ctx, HASH_ALGORITHM(), NULL, privKey) != 1) {
        EVP_MD_CTX_free(mdCtx);
        handleErrors("DigestSignInit failed");
        return 0;
    }

    // Set padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        EVP_MD_CTX_free(mdCtx);
        handleErrors("privKeySign: Failed to set RSA padding");
        return 0;
    }

    // signature length 
    if (EVP_DigestSign(mdCtx, NULL, sigLen, inData, inLen) != 1) {
        EVP_MD_CTX_free(mdCtx);
        handleErrors("Failed to determine signature length");
        return 0;
    }

    *sig = (uint8_t *)malloc(*sigLen);
    if (*sig == NULL) {
        EVP_MD_CTX_free(mdCtx);
        handleErrors("Memory allocation failed");
        return 0;
    }

    // Generate the signature
    if (EVP_DigestSign(mdCtx, *sig, sigLen, inData, inLen) != 1) {
        EVP_MD_CTX_free(mdCtx);
        free(*sig);
        handleErrors("Failed to sign data");
        return 0;
    }

    EVP_MD_CTX_free(mdCtx);
    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify(uint8_t *sig, size_t sigLen, EVP_PKEY *pubKey, uint8_t *data, size_t dataLen)
 {
    if (!sig || !pubKey || !data) {
        printf("\n Null pointers\n");
        return 0;
    }

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) handleErrors("Could not create context");

    // Initialize 
    EVP_PKEY_CTX *ctx = NULL;
    if (EVP_DigestVerifyInit(mdCtx, &ctx, HASH_ALGORITHM(), NULL, pubKey) != 1) {
        EVP_MD_CTX_free(mdCtx);
        handleErrors("DigestVerifyInit failed");
        return 0;
    }

    // Set padding RSA_PKCS1_PADDING
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        EVP_MD_CTX_free(mdCtx);
        handleErrors("Failed to set RSA padding");
        return 0;
    }

    // Verify the signature
    int result = EVP_DigestVerify(mdCtx, sig, sigLen, data, dataLen);
    EVP_MD_CTX_free(mdCtx);

    if (result != 1) {
        handleErrors("Verification failed");
        return 0;
    }

    return 1;
}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    // EVP_MD_CTX *mdCtx ;
    // size_t nBytes ;
    // unsigned int  mdLen ;
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) handleErrors("fileDigest: Could not create hashing context");

    if (!EVP_DigestInit_ex(mdCtx, HASH_ALGORITHM(), NULL)) {
        handleErrors("fileDigest: Digest initialization failed");
    }

    unsigned char buffer[8192];
    ssize_t bytesRead;
    unsigned int mdLen;

    while ((bytesRead = read(fd_in, buffer, sizeof(buffer))) > 0) {
        if (!EVP_DigestUpdate(mdCtx, buffer, bytesRead)) {
            handleErrors("fileDigest: Digest update failed");
        }

        if (fd_out > 0 && write(fd_out, buffer, bytesRead) != bytesRead) {
            handleErrors("fileDigest: Failed to write to output");
        }
    }

    if (bytesRead < 0) {
        handleErrors("fileDigest: Read error");
    }

    if (!EVP_DigestFinal_ex(mdCtx, digest, &mdLen)) {
        handleErrors("fileDigest: Digest finalization failed");
    }

    EVP_MD_CTX_destroy(mdCtx);
    return mdLen;
}

