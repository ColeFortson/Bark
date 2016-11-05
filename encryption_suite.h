//
//  encryption_suite.h
//  
//
//  Created by Cole Fortson on 11/4/16.
//
//

#ifndef encryption_suite_h
#define encryption_suite_h

unsigned char* rsaEncrypt( RSA *pubKey, const unsigned char* str, int dataSize, int *resultLen )
{
    int rsaLen = RSA_size( pubKey ) ;
    unsigned char* ed = (unsigned char*)malloc( rsaLen ) ;
    
    // RSA_public_encrypt() returns the size of the encrypted data
    // (i.e., RSA_size(rsa)). RSA_private_decrypt()
    // returns the size of the recovered plaintext.
    *resultLen = RSA_public_encrypt( dataSize, (const unsigned char*)str, ed, pubKey, PADDING ) ;
    if( *resultLen == -1 )
        printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
    
    return ed ;
}

unsigned char* rsaDecrypt( RSA *privKey, const unsigned char* encryptedData, int *resultLen )
{
    int rsaLen = RSA_size( privKey ) ; // That's how many bytes the decrypted data would be
    
    unsigned char *decryptedBin = (unsigned char*)malloc( rsaLen ) ;
    *resultLen = RSA_private_decrypt( RSA_size(privKey), encryptedData, decryptedBin, privKey, PADDING ) ;
    if( *resultLen == -1 )
        printf( "ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL) ) ;
    
    return decryptedBin ;
}


#endif /* encryption_suite_h */
