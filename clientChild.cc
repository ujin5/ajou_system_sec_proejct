#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#include "clientChid.h"

ClientChild::ClientChild(int parent_fd, std::string name){
    mParentFd = parent_fd;
    mName = name;
}
void ClientChild::promptMsg(){

    std::string msg;
    std::cout<<"["<<mName<<"] :";
    std::getline(std::cin, msg);
    write(mParentFd, msg.c_str(), msg.length());
}