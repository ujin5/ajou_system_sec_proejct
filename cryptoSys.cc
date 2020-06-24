#include "cryptoSys.h"
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
int RSA_genkey(RSA **rsaKey, int bits)
{
	BIGNUM *bne=NULL;

	bne=BN_new();
	if(BN_set_word(bne, RSA_F4)!=1)
		return 0;

	*rsaKey=RSA_new();
	if(RSA_generate_key_ex(*rsaKey, bits, bne, NULL)!=1)
	{
		BN_free(bne);
		return 0;
	}

	return 1;
}

RSA * createPubKeyRSA(unsigned char * key)
{
    BIO *bio = BIO_new_mem_buf(key, -1);
    BIO_write(bio, key, strlen((char *)key));

    RSA *rsa = NULL;
    PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);
    if(rsa==NULL)
        std::cout<<"rsa==NULL"<<std::endl;
    return rsa;
}
RSA * createPriKeyRSA(char * key)
{
    BIO *bio = BIO_new_mem_buf(key, -1);
    BIO_write(bio, key, strlen((char *)key));

    RSA *rsa = NULL;
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    if(rsa==NULL)
        std::cout<<"rsa==NULL"<<std::endl;
    return rsa;
}
CryptoSystem::CryptoSystem(){
    RSA_genkey(&mMyRSA, 2048);
    std::cout<<getMyPriKey()<<std::endl;
    std::cout<<getMyPubKey()<<std::endl;
}
char * CryptoSystem::getMyPriKey(){
    BIO * private_key = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(private_key, mMyRSA, NULL, NULL, 0, NULL, NULL);
    char * result = new char[BIO_pending(private_key) + 1];
    int n = BIO_read(private_key, result, BIO_pending(private_key));
    result[n] = '\0';
    return result;
}
char * CryptoSystem::getMyPubKey(){
    BIO * public_key = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(public_key, mMyRSA);
    char * result = new char[BIO_pending(public_key) + 1];
    int n = BIO_read(public_key, result, BIO_pending(public_key));
    result[n] = '\0';
    return result;
}
 uint32_t CryptoSystem::encryptRSA(uint8_t * src, uint32_t src_length, uint8_t * dst, uint8_t * key){
    //std::cout<<(char *)key<<std::endl;
    RSA * public_key = createPubKeyRSA(key);
    return RSA_public_encrypt(src_length, src, dst, public_key, RSA_PKCS1_PADDING);
}
uint32_t CryptoSystem::decryptRSA(uint8_t * src, uint32_t src_length, uint8_t * dst){
    RSA * private_key = createPriKeyRSA(getMyPriKey());
    return RSA_private_decrypt(src_length, src, dst, private_key, RSA_PKCS1_PADDING);
}
void CryptoSystem::addPubKey(std::string name, std::string public_key){
    mMutex.lock();
    mPubKeys[name] = public_key;
    mMutex.unlock();
}
std::map<std::string, std::string> CryptoSystem::getMemberPubKey(){
    return mPubKeys;
}