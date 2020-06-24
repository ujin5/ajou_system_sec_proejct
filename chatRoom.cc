#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include "chatRoom.h"
#include "server.h"
#include <cstring>

chatRoom::chatRoom(std::string name){
    mRoomName = name;
}
bool chatRoom::enterRoom(int fd, std::string name){
    
    if(mMembers.find(name) != mMembers.end()){
        std::cout<<"[-] Duplicate nickname :"<<name<<std::endl;
        return false;
    }
    std::cout<<"[+] Enter "<<mRoomName<<" : "<<name<<std::endl;
    mMembers[name] = fd;
    return true;
}
bool chatRoom::available(int fd){
    return std::find_if(
          mMembers.begin(),
          mMembers.end(),
          [fd](const auto& iter) {return iter.second == fd; }) != mMembers.end();
}
uint32_t chatRoom::sendMesaage(uint8_t * msg, uint32_t msg_length, int fd){
    int n = 0;
    for(auto it : mMembers){
        if(it.second == fd)
            continue;
        write(it.second, (uint8_t *)msg, msg_length);
        n++;
    }
    return n;
}