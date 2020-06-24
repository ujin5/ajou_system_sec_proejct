#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "chatRoom.h"
#include "server.h"
#include <cstring>
Server::Server(int port){
    int socket_desc , client_sock;
    struct sockaddr_in server;
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    int enable = 1;
    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("bind failed. Error");
        exit(-1);
    }
    listen(socket_desc , 3);
    mSocket = socket_desc;
}
bool Server::startServer(){
    
    bool running = true;
    while(running){
        struct sockaddr_in client;
        int client_size = sizeof(struct sockaddr_in);
        int client_sock = accept(mSocket, (struct sockaddr *)&client, (socklen_t*)&client_size);
        mAcceptThreads.push_back(std::thread(&Server::handleAccept, this, client_sock));
    }
    return true;
}
void Server::handleAccept(int fd){
    Buffer buffer;


    while(1){
        buffer.length = read(fd, buffer.data, 1024);
        if(buffer.length <= 0){
            std::cout<<"read error"<<std::endl;
            return;
        }
        uint8_t cmd = buffer.data[0];
        uint8_t * cur = &buffer.data[1];
        mAcceptMutex.lock();
        switch(cmd){
            case CREATE_ROOM_REQ :
            {
                std::string room_name = (char *)cur; 
                cur += room_name.length() + 1;
                std::string nick_name = (char *)cur;
                std::cout<<"[+] LOG CREATE_ROOM_REQ : "<<room_name<<" "<<nick_name<<std::endl;
                if(mChatRoom[room_name]){
                    uint8_t error_pkt[] = { CREATE_ROOM_RSP, 0xff };
                    write(fd, error_pkt, sizeof(error_pkt));
                    break;
                }
                mChatRoom[room_name] = new chatRoom(room_name);
                mChatRoom[room_name]->enterRoom(fd, nick_name);
                uint8_t success_pkt[] = { CREATE_ROOM_RSP, 0x1 };
                write(fd, success_pkt, sizeof(success_pkt));
            } break;
            case ENTER_ROOM_REQ :
            {
                std::string room_name = (char *)cur; 
                cur += room_name.length() + 1;
                std::string nick_name = (char *)cur;
                cur += nick_name.length() + 1;
                std::string public_key = (char *)cur;
                std::cout<<"[+] LOG ENTER_ROOM_REQ : "<<room_name<<" "<<nick_name<<std::endl;
                if(!mChatRoom[room_name]){
                    uint8_t error_pkt[] = { ENTER_ROOM_RSP, 0xff };
                    write(fd, error_pkt, sizeof(error_pkt));
                    break;
                }
                else if(!mChatRoom[room_name]->enterRoom(fd, nick_name)){
                    uint8_t error_pkt[] = { ENTER_ROOM_RSP, 0xfe };
                    write(fd, error_pkt, sizeof(error_pkt));
                    break;
                }
                uint8_t success_pkt[MTU_SIZE] = { 0, };
                uint8_t * cur = success_pkt;
                *cur = ENTER_ROOM_RSP; cur++;
                *cur = 0x1; cur++;
                strcpy((char *)cur, room_name.c_str());
                cur += room_name.length(); *cur = 0; cur++;
                strcpy((char *)cur, nick_name.c_str());
                cur += nick_name.length(); *cur = 0; cur++;
                stpcpy((char *)cur, public_key.c_str());
                mChatRoom[room_name]->sendMesaage(success_pkt, cur-success_pkt+public_key.length(), fd); // broadcast
            } break;
            case SEND_MESSAGE_REQ :
            {
                std::string room_name = (char *)cur; 
                cur += room_name.length() + 1;
                std::string nick_name = (char *)cur;
                cur += nick_name.length() + 1;
                uint32_t msg_length = *(uint32_t *)cur;
                cur += sizeof(uint32_t);
                char * msg = (char *)cur;
                std::cout<<"[+] LOG SEND_MESSAGE_REQ : room_name = "<<room_name<<", nick_name = "<<nick_name<<", msg_length = "<<msg_length<<std::endl;
                if(!mChatRoom[room_name]){
                    uint8_t error_pkt[] = { SEND_MESSAGE_RSP, 0xff };
                    write(fd, error_pkt, sizeof(error_pkt));
                    break;
                }
                else if(!mChatRoom[room_name]->available(fd)){
                    uint8_t error_pkt[] = { SEND_MESSAGE_RSP, 0xfe };
                    write(fd, error_pkt, sizeof(error_pkt));
                    break;
                }
                uint8_t success_pkt[MTU_SIZE] = { 0, };
                uint8_t * send_pkt_cur = success_pkt;
                *send_pkt_cur = SEND_MESSAGE_RSP; send_pkt_cur++;
                *send_pkt_cur = 0x1; send_pkt_cur++;
                strcpy((char *)send_pkt_cur, room_name.c_str());
                send_pkt_cur += room_name.length(); *send_pkt_cur = 0; send_pkt_cur++;
                strcpy((char *)send_pkt_cur, nick_name.c_str());
                send_pkt_cur += nick_name.length(); *send_pkt_cur = 0; send_pkt_cur++;
                *(uint32_t *)send_pkt_cur = msg_length;
                send_pkt_cur += sizeof(uint32_t);
                memcpy((char *)send_pkt_cur, msg, msg_length);
                send_pkt_cur += msg_length;
                mChatRoom[room_name]->sendMesaage(success_pkt, send_pkt_cur-success_pkt, fd);
            } break;
            case QUIT_ROOM_REQ :
            {
                std::string room_name = (char *)cur; 
                cur += room_name.length() + 1;
                std::cout<<"[+] LOG QUIT_ROOM_REQ : "<<room_name<<std::endl;
                if(!mChatRoom[room_name]){
                    uint8_t error_pkt[] = { QUIT_ROOM_RSP, 0xff };
                    write(fd, error_pkt, sizeof(error_pkt));
                }
                uint8_t success_pkt[] = { QUIT_ROOM_RSP, 0x1 };
                mChatRoom[room_name]->sendMesaage(success_pkt, 2, fd); // broadcast
                mChatRoom[room_name] = NULL;
                
            } break;
            default :
            {

            } break;
        }
        mAcceptMutex.unlock();
    }
    close(fd);
}
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
int main(int argc, char *argv[]){
    if( argc < 2){
        std::cout<<"./server port"<<std::endl;
        exit(-1);
    }
    Server server(atoi(argv[1]));
    server.startServer();
    return 0;
}