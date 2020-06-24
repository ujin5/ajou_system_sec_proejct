#ifndef __CRYPTO_H__
#define __CRYPTO_H__
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <cstdint>
#include <mutex>
#include <map>
#include <string>
class CryptoSystem{
    public:
        CryptoSystem();
        ~CryptoSystem()=default;
        static uint32_t encryptRSA(uint8_t * src, uint32_t src_length, uint8_t * dst, uint8_t  * key);
        uint32_t decryptRSA(uint8_t * src, uint32_t src_length, uint8_t * dst);
        void addPubKey(std::string name, std::string public_key);
        std::map<std::string, std::string> getMemberPubKey();
        char * getMyPubKey();
        char * getMyPriKey();
        std::mutex mMutex;
    private:
        RSA * mMyRSA;
        std::map<std::string, std::string> mPubKeys;
        
};
#endif