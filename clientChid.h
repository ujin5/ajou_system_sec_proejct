#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <unistd.h>
#include <algorithm>
#include <thread>

#ifndef _CLIENT_CHILD_H_
#define _CLIENT_CHILD_H_
class ClientChild{
    public:
        ClientChild(int parent_fd, std::string name);
        ~ClientChild() = default;
        void promptMsg();
    private:
        int mParentFd;
        std::string mName;
};
#endif