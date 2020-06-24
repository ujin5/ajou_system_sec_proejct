
#ifndef _PKT_H_
#define _PKT_H_
#define MTU_SIZE 1024

#include <cstdint>
/*
    CREATE_ROOM_REQ | room name | your nick name |<
*/
#define CREATE_ROOM_REQ 0x1

/*
    ENTER_ROOM_REQ | room name | your nick name | public key |<
*/
#define ENTER_ROOM_REQ 0x2
/*
    SEND_MESSAGE_REQ | room name |  your nick name | length | message data |<
*/
#define SEND_MESSAGE_REQ 0x3
/*
    QUIT_ROOM_REQ |<
*/
#define QUIT_ROOM_REQ 0x4

#define CREATE_ROOM_RSP 0x5
#define ENTER_ROOM_RSP 0x6
#define QUIT_ROOM_RSP 0x7
#define SEND_MESSAGE_RSP 0x8
typedef struct Buffer{
    uint32_t length;
    uint8_t data[MTU_SIZE];
} Buffer;
typedef struct Message{
    uint16_t length;
    uint32_t timpstamp;
    uint8_t data[];
} Message;
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
 
void hexdump(void *mem, unsigned int len);
#endif