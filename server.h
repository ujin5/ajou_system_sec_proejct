#include <cstdint>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <thread>
#include <mutex>


#include "pkt.h"
#ifndef _SERVER_H_
#define _SERVER_H_


#define THREAD_N 32

#include "chatRoom.h"
class Server{
    public:
        Server(int port);
        ~Server() = default;
        int32_t parsePkt(uint8_t * packet);
        void handleAccept(int fd);
        bool startServer();
    private:
        std::map<std::string, chatRoom *> mChatRoom;
        std::mutex mAcceptMutex;
        std::vector<std::thread> mAcceptThreads;
        int mSocket;
};
#endif