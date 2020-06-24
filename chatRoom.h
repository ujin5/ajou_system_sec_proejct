#include <cstdint>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include "pkt.h"
#include "server.h"

#ifndef _CHAT_ROOM_H_
#define _CHAT_ROOM_H_
class chatRoom{
    public:
        chatRoom(std::string name);
        ~chatRoom() = default;
        bool enterRoom(int fd, std::string name);
        uint32_t sendMesaage(uint8_t * msg, uint32_t msg_len, int fd);
        //void startRecv();
        bool available(int fd);
    private:
        std::map<std::string, int> mMembers;
        std::string mRoomName;
        //std::thread * mRecvThread;
        //std::thread * mSendThread;
};
#endif