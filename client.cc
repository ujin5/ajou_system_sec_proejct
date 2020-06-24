#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>


#include "pkt.h"
#include "client.h"
#include "cryptoSys.h"
#include "seccompFilter.h"
#include "clientChid.h"
void hexdump(void *mem, unsigned int len)
{
        unsigned int i, j;
        
        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        printf("0x%06x: ", i);
                }
 
                /* print hex data */
                if(i < len)
                {
                        printf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        printf("   ");
                }
                
                /* print ASCII dump */
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing */
                                {
                                        putchar(' ');
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char */
                                {
                                        putchar(0xFF & ((char*)mem)[j]);        
                                }
                                else /* other char */
                                {
                                        putchar('.');
                                }
                        }
                        putchar('\n');
                }
        }
}
int startChild(int fd, std::string name){
    /*
    std::cout<<"fd : "<<fd<<" name : "<<name<<std::endl;
    std::cout<<"Child PID : "<<getpid()<<std::endl;
    */
    ClientChild child(fd, name);
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    while(true)
        child.promptMsg();
}
int32_t parseSendRspPkt(uint8_t * pkt, std::string& name, std::string& room_name, uint8_t * dst){
    if(pkt[0] != SEND_MESSAGE_RSP)
        return -1;
    else if(pkt[1] == 0xff | pkt[1] == 0xfe)
        return -1;
    pkt += 2;
    room_name = (char *)pkt; 
    pkt += room_name.length() + 1;
    name = (char *)pkt;
    pkt += name.length() + 1;
    uint32_t msg_length = *(uint32_t *)pkt;
    pkt += sizeof(uint32_t);
    memcpy(dst, pkt, msg_length);
    //hexdump(pkt, strlen((char*)pkt));
    return msg_length;
}
bool parseEnterRspPkt(uint8_t * pkt, std::string& name, std::string& room_name, uint8_t * dst){
    if(pkt[0] != ENTER_ROOM_RSP)
        return false;
    else if(pkt[1] == 0xff | pkt[1] == 0xfe)
        return false;
    pkt += 2;
    room_name = (char *)pkt; 
    pkt += room_name.length() + 1;
    name = (char *)pkt;
    pkt += name.length() + 1;
    std::string public_key = (char *)pkt;
    memcpy(dst, public_key.c_str(), public_key.length());
    //hexdump(pkt, strlen((char*)pkt));
    return true;
}
uint32_t sendReqEncPkt(uint8_t * pkt, std::string name, std::string room_name, std::string msg, uint8_t * public_key){
    uint8_t * cur = (uint8_t *)pkt;
    *cur = SEND_MESSAGE_REQ; cur++;
    strcpy((char *)cur, room_name.c_str());
    cur += room_name.length(); *cur = 0; cur++;
    strcpy((char *)cur, name.c_str());
    cur += name.length(); *cur = 0; cur++;
    uint8_t * enc_msg = new uint8_t[1024];
    int n = CryptoSystem::encryptRSA((uint8_t *)msg.c_str(), msg.length(), enc_msg, public_key);
    *(uint32_t *)cur = n;
    cur += sizeof(uint32_t);
    
    
    //hexdump(enc_msg, n);
    memcpy((char *)cur, (char *)enc_msg, n);
    return cur-pkt+n;
}
SeccompChild * spwanChild(){
    SeccompChild * s = new SeccompChild{
        SeccompWhitelist(SYS_exit_group),
        SeccompWhitelist(SYS_exit),
        SeccompWhitelist(SYS_write),
        SeccompWhitelist(SYS_read),
        SeccompWhitelist(SYS_mmap),
    };
    return s;
}

Client::Client(std::string name){
    mName = name;
}
bool Client::connectServer(char * host){
	int sock;
	struct sockaddr_in server;

	sock = socket(AF_INET , SOCK_STREAM , 0);

	server.sin_addr.s_addr = inet_addr(host);
	server.sin_family = AF_INET;
	server.sin_port = htons(1337);

	//Connect to remote server
	if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		std::cout<<"\t\t[-] Connect failed..\t\t"<<std::endl;
		return false;
	}
    mSocket = sock;
    return true;
}
void Client::recvChildMsg(std::string name){
   
    bool running = true;
    while(running){
        uint8_t * msg = new uint8_t[1024];
        int n = mChilds[name]->recvMessage(msg, 1024);
        msg[n] = 0;
        //hexdump(msg, n);
        if(!strncmp((char *)msg, "exit", 4)){
            std::cout<<"\t\t[!] Quit"<<std::endl;
            return;
        }
        mCrpytoSys.mMutex.lock();
        for(auto it : mCrpytoSys.getMemberPubKey() ){
            uint8_t * send_pkt = new uint8_t[2048];
            //std::cout<<it.second<<std::endl;
            int send_n = sendReqEncPkt(send_pkt, mName, name, std::string((char *)msg), (uint8_t *)it.second.c_str());
            //hexdump(send_pkt, send_n);
            write(mSocket, send_pkt, send_n);
        }
        mCrpytoSys.mMutex.unlock();
    }
}
bool Client::exchangePubKey(std::string name, std::string public_key){
    uint8_t buffer[MTU_SIZE] = { 0, };
    uint8_t * cur = buffer;
    *cur = SEND_MESSAGE_REQ; cur++;
    strcpy((char *)cur, name.c_str());
    cur += name.length(); *cur = 0; cur++;
    strcpy((char *)cur, mName.c_str());
    cur += mName.length(); *cur = 0; cur++;
    *(uint32_t *)cur = strlen(mCrpytoSys.getMyPubKey());
    cur += sizeof(uint32_t);
    strcpy((char *)cur, mCrpytoSys.getMyPubKey());
    int n = write(mSocket, buffer, MTU_SIZE);
}
void Client::recvServPkt(){
    uint8_t buffer[MTU_SIZE] = { 0, };
    bool running = true;
    while(running){
        int n = read(mSocket, buffer, MTU_SIZE);
        if(n <= 0){
            std::cout<<"\t\t[!] read error!"<<std::endl;
            running = false;
            continue;
        }
        uint8_t cmd = buffer[0];
        uint8_t * cur = &buffer[2];
        //hexdump(buffer, n);
        switch(cmd){
            case ENTER_ROOM_RSP:{
                std::string room_name = (char *)cur; 
                cur += room_name.length() + 1;
                std::string nick_name = (char *)cur;
                cur += nick_name.length() + 1;
                std::string public_key = (char *)cur;
                //std::cout<<public_key<<std::endl;
                mCrpytoSys.addPubKey(nick_name, public_key);
                exchangePubKey(room_name, public_key);
                std::cout<<"\t\t[!] new Member : "<<nick_name<<std::endl;
            } break;
            case QUIT_ROOM_RSP:{

            } break;
            case SEND_MESSAGE_RSP:{
                std::string room_name, nick_name;
                uint8_t enc_msg[1024] = { 0, };
                uint32_t msg_length = parseSendRspPkt(buffer, nick_name, room_name, enc_msg);
                char msg[1024];
                int n = mCrpytoSys.decryptRSA(enc_msg, msg_length, (uint8_t *)msg);
                msg[n] = '\0';
                std::cout<<"["<<nick_name<<"]"<<" : "<<msg<<std::endl;
            } break;
            default:
                continue;
        }
    }
}
void Client::genChatRoom(std::string name){
    uint8_t gen_req_pkt[MTU_SIZE] = {0, };
    uint8_t gen_rsp_pkt[MTU_SIZE] = {0, };
    uint8_t * cur = gen_req_pkt;
    *cur = CREATE_ROOM_REQ;
    cur++;
    strcpy((char *)cur, name.c_str());
    cur += name.length();
    *cur = 0;
    cur++;
    strcpy((char *)cur, mName.c_str());
    cur += mName.length();
    write(mSocket, gen_req_pkt, cur-gen_req_pkt);
    read(mSocket, gen_rsp_pkt, MTU_SIZE);

    if(gen_rsp_pkt[0] != CREATE_ROOM_RSP){
        std::cout<< "\t\t[-] "<<__func__<<" : Unknown Packet"<<std::endl;
        return;
    }
    
    if(gen_rsp_pkt[1] == 0xff){
        std::cout<< "\t\t[-] "<<__func__<<" : Already there is same room"<<std::endl;
        return;
    }
    else if(gen_rsp_pkt[1] == 0xfe){
        std::cout<< "\t\t[-] "<<__func__<<" : Already there is same NickName"<<std::endl;
        return;
    }

    mChilds[name] = spwanChild();
    int fds[2];
    pipe(fds);
    mChilds[name]->setPipeFD(fds[0]);
    mIOthread = new std::thread(&Client::recvServPkt, this);
    mChildthread = new std::thread(&Client::recvChildMsg, this, name);
    auto child_func = std::bind(startChild, fds[1], mName);
    mChilds[name]->run(child_func);
    mChilds[name]->wait_for_child(); // sync process
    mIOthread->join();
    mChildthread->join();
}
void Client::enterChatRoom(std::string name){
    uint8_t enter_req_pkt[MTU_SIZE] = {0, };
    uint8_t enter_rsp_pkt[MTU_SIZE] = {0, };
    uint8_t * cur = enter_req_pkt;
    *cur = ENTER_ROOM_REQ;
    cur++;
    strcpy((char *)cur, name.c_str());
    cur += name.length(); *cur = 0; cur++;
    strcpy((char *)cur, mName.c_str());
    cur += mName.length(); *cur = 0; cur++;
    strcpy((char *)cur, mCrpytoSys.getMyPubKey());

    write(mSocket, enter_req_pkt, cur-enter_req_pkt+strlen(mCrpytoSys.getMyPubKey()));
    int n = read(mSocket, enter_rsp_pkt, MTU_SIZE);
    //hexdump(enter_rsp_pkt, n);
    std::string room_name, nick_name;
    uint8_t msg[1024] = { 0, };
    if(parseSendRspPkt(enter_rsp_pkt, nick_name, room_name, msg) < 0){
        std::cout<< "\t\t[-] "<<__func__<<" : Error"<<std::endl;
        return;       
    }
    mCrpytoSys.addPubKey(nick_name, (char *)msg);
    mChilds[name] = spwanChild();
    int fds[2];
    pipe(fds);
    mChilds[name]->setPipeFD(fds[0]);
    mIOthread = new std::thread(&Client::recvServPkt, this);
    mChildthread = new std::thread(&Client::recvChildMsg, this, name);
    auto child_func = std::bind(startChild, fds[1], mName);
    mChilds[name]->run(child_func);
    mChilds[name]->wait_for_child(); // sync process
    mIOthread->join();
    mChildthread->join();
}
void Client::handleConnect(){
    int choice;
    bool running = true;
    std::cout<<"\n\n";
    std::cout<<"\t\t[1] Create Chat Room\t\t"<<std::endl;
    std::cout<<"\t\t[2] Enter Chat Room\t\t"<<std::endl;
    std::cout<<"\t\t[3] Quit\t\t"<<std::endl;
    while(running){
        std::cout<<"\t\t > ";
        std::cin>>choice;
        switch(choice){
            case 1:{
                std::string room_name;
                std::cout<<"\t\tRoom Name> ";
                std::cin>>room_name;
                genChatRoom(room_name);
            } break;
            case 2:{
                std::string room_name;
                std::cout<<"\t\tRoom Name> ";
                std::cin>>room_name;
                enterChatRoom(room_name);
            } break;
            case 3:{
                running = false;
            } break;
            default:
                continue;
        }
    }
}

int main(){
    std::string name;
    std::cout<<"\t\t[Safe Message Client]\t\t"<<std::endl;
    std::cout<<"\t\tYour Name > ";
    std::cin>>name;
    Client client(name);
    std::cout<<"\t\t[+] Connecting ....\t\t"<<std::endl;
    if(!client.connectServer("127.0.0.1"))
        exit(-1);
    std::cout<<"\t\t[+] Connected !\t\t"<<std::endl;
    client.handleConnect();
    /*
        SeccompChild * s = swpanChild();
        auto child_func = std::bind(startChild, 0, std::string("AAAA"));
        s->run(child_func);
        delete s;
    */

}