//
//  encryption_suite.h
//  
//
//  Created by Cole Fortson on 11/4/16.
//
//

#ifndef encryption_suite_h
#define encryption_suite_h

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

#define PADDING RSA_PKCS1_PADDING

RSA * createRSAWithFilename(char * filename,int public)
{
            FILE * fp = fopen(filename,"rb");
             
                if(fp == NULL)
                            {
                                            printf("Unable to open file %s \n",filename);
                                                    return NULL;    
                                                        }
                    RSA *rsa= RSA_new() ;
                     
                        if(public)
                                    {
                                                    rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
                                                        }
                            else
                                        {
                                                        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
                                                            }
                             
                                return rsa;
}

int padding = RSA_PKCS1_PADDING;
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
            RSA * rsa = createRSAWithFilename(key,1);
                int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
                    return result;
}

#endif /* encryption_suite_h */
