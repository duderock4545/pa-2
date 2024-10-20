/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   amal.c

Written By:  Team #   MUST WRITE YOUR TEAM NUMBER HERE
     1- Patrick Dodds
     2- Conor McFadden

Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main(int argc, char *argv[])
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    int fd_in, fd_ctrl, fd_data;
    size_t mdLen;
    uint8_t *signature = NULL;
    size_t signature_len;
    
    // Open log file
    FILE *log = fopen("amal/logAmal.txt", "w");
    if (!log) {
        fprintf(stderr, "Error: Unable to open logAmal.txt\n");
        return -1;
    }
    
    // Log: Amal starting
    fprintf(log, "Amal: Starting process\n");

    // Check arguments (should receive pipe FDs)
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ctrl pipe fd> <data pipe fd>\n", argv[0]);
        fclose(log);
        return -1;
    }

    // Get the FD arguments from the dispatcher
    fd_ctrl = atoi(argv[1]);
    fd_data = atoi(argv[2]);
    fprintf(log, "Amal: Received pipe FDs, Control Pipe: %d, Data Pipe: %d\n", fd_ctrl, fd_data);

    // Open bunny.mp4 file
    fd_in = open("../bunny.mp4", O_RDONLY);
    if (fd_in < 0) {
        fprintf(log, "Error: Unable to open bunny.mp4\n");
        fclose(log);
        return -1;
    }
    fprintf(log, "Amal: Opened bunny.mp4\n");

    // Compute the digest
    mdLen = fileDigest(fd_in, fd_data, digest);
    fprintf(log, "Amal: Computed digest\n");
    BIO_dump_fp(log, digest, mdLen);

    // Load Amal's private key
    EVP_PKEY *rsa_privK = NULL;
    FILE *privKeyFile = fopen("amal/amal_priv_key.pem", "r");
    if (!privKeyFile) {
        fprintf(log, "Error: Unable to open Amal's private key\n");
        close(fd_in);
        fclose(log);
        return -1;
    }

    rsa_privK = PEM_read_PrivateKey(privKeyFile, NULL, NULL, NULL);
    fclose(privKeyFile);
    
    if (!rsa_privK) {
        fprintf(log, "Error: Unable to load Amal's private key\n");
        close(fd_in);
        fclose(log);
        return -1;
    }

    // Sign the digest
    if (!privKeySign(&signature, &signature_len, rsa_privK, digest, mdLen)) {
        fprintf(log, "Error: Unable to sign digest\n");
        EVP_PKEY_free(rsa_privK);
        close(fd_in);
        fclose(log);
        return -1;
    }
    fprintf(log, "Amal: Signed digest\n");
    BIO_dump_fp(log, signature, signature_len);

    // Send the signature over the control pipe
    write(fd_ctrl, &signature_len, sizeof(signature_len));
    write(fd_ctrl, signature, signature_len);
    fprintf(log, "Amal: Sent signature to Basim\n");

    // Clean up resources
    close(fd_in);
    close(fd_ctrl);
    close(fd_data);
    EVP_PKEY_free(rsa_privK);
    free(signature);
    fclose(log);

    return 0;
}