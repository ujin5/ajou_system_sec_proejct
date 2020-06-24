#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>
#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "pkt.h"
#include "cryptoSys.h"
#include "seccompFilter.h"
class Client{
    public:
        Client(std::string name);
        ~Client()=default;
        void genChatRoom(std::string name);
        bool exchangePubKey(std::string name, std::string public_key);
        void enterChatRoom(std::string name);
        uint32_t sendEncMsg(std::string name, char * msg);
        void recvChildMsg(std::string name);
        void recvServPkt();
        bool connectServer(char * host);
        void handleConnect();
        
    private:
        std::map<std::string, SeccompChild *> mChilds;
        std::string mName;
        CryptoSystem mCrpytoSys;
        std::thread * mChildthread;
        std::thread * mIOthread;
        int mSocket;
};
#endif