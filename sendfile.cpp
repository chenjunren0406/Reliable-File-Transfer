#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <iostream>
#include <errno.h>

#define BUFSIZE 2048

using namespace std;

// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
struct para{
    int sock;
    struct sockaddr_in client_addre;
    bool* record;
    bool* timeOutHappen;
    para(){};
};
//**************************************************
//get the port number
unsigned short getPortNumber(char *argv){
    char *port;
    port = argv;
    while(*port != ':') port++;
    int length = 0;
    char *curr;
    for(curr = port + 1; *curr != ' '; curr++){
        length++;
    }
    char result[length];
    int i;
    for(i = 0; i < length; ++i){
        result[i] = port[i + 1];
    }
    unsigned short server_port = atoi(result);
    return server_port;

}


void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
    | ((uint32_t) bytes[1] << 8)
    | ((uint32_t) bytes[2] << 16)
    | ((uint32_t) bytes[3] << 24);
}


/*
 * generate md5 code in (digest)
 */
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {

    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;

    // Message (to prepare)
    uint8_t *msg = NULL;

    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    //Pre-processing:
    //append "1" bit to message
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message

    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;

    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits

    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);

    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {

        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);

        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;

        // Main loop:
        for(i = 0; i<64; i++) {

            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;

        }

        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;

    }

    // cleanup
    free(msg);

    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}
//**************************************************
/**
 *  get ack number from packet
 */

unsigned int getacknumber(char *ackpacket){

    unsigned int acknumber = ntohs(*((unsigned int*)ackpacket));

    return acknumber;
}

/**
 *  get md5 from packet
 */
char* getMD5forAck(char *ackpacket){
    char* md5forAck = (char *)malloc(4 * sizeof(unsigned int));

    memcpy(md5forAck, ackpacket + sizeof(unsigned int), 4*sizeof(unsigned int));

    return md5forAck;
}
//**************************************************
// recv thread
void *thread(void *x){
    //change x from void to struct para
    para helper = *((struct para *)x);
    int recvlen = 0;
    socklen_t addr_len =sizeof(struct sockaddr_in);
  
    struct sockaddr_in client_addre = helper.client_addre;
    int sock = helper.sock;
    bool* timeOutHappen = helper.timeOutHappen;

    char buff[BUFSIZE];
    struct timeval time;
    time.tv_sec=5;
    time.tv_usec=0;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time))<0){
        perror("setsockopt error");
    }
    while(1){
        recvlen = recvfrom(sock, buff, BUFSIZE, 0, (struct sockaddr *)&client_addre, &addr_len);
       
        if (recvlen < 0) {
            if(errno==EWOULDBLOCK||errno==EAGAIN){
                /*
                 * end this thread
                 */
                 *timeOutHappen = true;


                return 0;
                
            }
            else{
                printf("recv failed\n");
            }
            continue;
        }
        else if(recvlen == 20){
            unsigned int ack = getacknumber(buff);
            char *md55 = getMD5forAck(buff);
            char checkSum[16];
            bool *record = helper.record;
        
            md5((uint8_t*)&ack,sizeof(unsigned int),(uint8_t*)checkSum);
            if(memcmp(md55, checkSum, 16) == 0){
                *(record + ack - 1) = true;
            }
            if (recvlen < 0) {
                printf("recv failed");
            }
        }
        else if(recvlen != 20){
            printf("ack corrupt\n");
        }
    }
   
}
//**************************************************
//return a packet
char* getPacket(unsigned int seqN,  char* checkSum, unsigned int dataLen, unsigned int size, char* data){

    char* packet=(char*)malloc(sizeof(unsigned int)*size);

    *((unsigned int *)packet)=htons(seqN);
    

    memcpy(packet+sizeof(unsigned int), checkSum, 4*sizeof(unsigned int));


    *((unsigned int*)(packet+sizeof(unsigned int)+4*sizeof(unsigned int)))=htons(dataLen);

    memcpy(packet+6*sizeof(unsigned int), data, dataLen);

    return packet;
}
//**************************************************
//get the datalen from given the packet
unsigned int getDataLen(char *packet){
    unsigned int dataLen=ntohs(*((unsigned int*)(packet+sizeof(unsigned int)+4*sizeof(unsigned int))));
    return dataLen;
}
//**************************************************
//Get the checksum from given packet
char * getChecksum(char* packet){

    char* checkSum=(char *)malloc(4*sizeof(unsigned int));

    memcpy(checkSum, packet+sizeof(unsigned int), 4*sizeof(unsigned int));
    return checkSum;

}
//**************************************************
//Get the sequence number from given packet
unsigned int getSequenceNumber(char* packet){
    unsigned int seqN=ntohs(*((unsigned int *)packet));
    return seqN;
}
//**************************************************
//Get the data from given packet
char *getData(char *packet){

    char* data=(char *)malloc(getDataLen(packet)*sizeof(unsigned int));

    memcpy(data, packet+6*sizeof(unsigned int), sizeof(data));
    return data;
}

//**************************************************
int readFile(FILE *fp, int startPosition, int length, char *result){
    unsigned int returned=0;
    if(fseek(fp, startPosition, SEEK_SET)==0){
        returned=fread(result, 1, length, fp);
    }
    return returned;
    
}

//*******************************
/*
* get the file name from path
*/
char* getpoint(char* head){
    int size=strlen(head);
    char* ret=head ;
    
    int cur=size--;
    while(cur>=0){
        if(head[cur]=='/' && cur<size-1) {ret=&head[cur+1];break;}
        cur--;
    }

    return ret;

}

//**************************************************
//main method
int main(int argc, char **argv)
{
    //struct in_addr ;
    struct sockaddr_in sin, client_addre;

    unsigned int packetLen=506;
    bool timeout = false;
    long assumedDataLen=2000;
    char checkSum3[16];
    char checkSum4[16];
    if(argc != 5) exit(0);

    //get the port number
    unsigned short server_port = getPortNumber(argv[2]);
    

    //get the ip address
    char *address;
    address = argv[2];
    int length = 0;
    while(*address != ':'){
        length++;
        address++;
    }
    char *ip_address = (char *)malloc(sizeof(char) * length + 1);
    memcpy(ip_address, argv[2], sizeof(char) * length);
    ip_address[length] = '\0';

    //set the sin
    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip_address);
    sin.sin_port = htons (server_port);

    //create a new socket
    int sock;
    if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
        perror("cannot create socket\n");
	    return 0;
    }
    int on=1;
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));

    //new a receive thread
    pthread_t id;


    FILE *fp;
    fp=fopen(argv[4], "rb+");

    if( fp == NULL )
    {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    long fileSize=ftell(fp);

    long packetNumber=fileSize/assumedDataLen;

    if(fileSize%assumedDataLen!=0){
        packetNumber++;
    }
    int i=0;
    bool record[packetNumber+2];
    for(i=0;i<packetNumber+2;i++){
        record[i]=false;
    }
    struct para x;
    x.record = record;
    x.client_addre = client_addre;
    x.sock = sock;
    x.timeOutHappen = &timeout;
    int th = pthread_create(&id, NULL, *thread, &x);
    if(th){
        cout<<"allocate thread failed"<<endl;
    }

    /*
     * To make sure first two get arrive
     */
    while(1){

        //char* fileNameChar=(char *)malloc(sizeof(char)*strlen(argv[4]));
        char* fileNameChar = getpoint(argv[4]);
        char checkSum1[16];
        md5((uint8_t*)fileNameChar,strlen(fileNameChar),(uint8_t*)checkSum1);
        char *fileNamePac=getPacket(1, checkSum1, strlen(fileNameChar),packetLen, fileNameChar);
        /*
         * send filename
         */
        if(sendto(sock, fileNamePac, sizeof(int)*packetLen, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0){
            perror("sendto failed1\n");
            fclose(fp);
            abort();
        }

        //char* fileSizeChar=(char *)malloc(sizeof(long));
        char* fileSizeChar=(char *)&fileSize;

        char checkSum2[16];
        
        md5((uint8_t*)fileSizeChar,sizeof(long),(uint8_t*)checkSum2);

        char *fileSizePac = getPacket(2, checkSum2, sizeof(long), packetLen, fileSizeChar);
        /*
         * send file size
         */
        if(sendto(sock, fileSizePac, sizeof(int)*packetLen, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0){
            perror("sendto failed 2\n");
            fclose(fp);
            abort();
        }
        if(record[0]&&record[1]){
            break;
        }
       // sleep(1000);
    }


    
    int j = 0;

    while(!timeout){
         bool nTheEnd=false;
        for(i=2;i<packetNumber+2;i++){
            if(!record[i]){
                nTheEnd=true;
                break;
            }
        }
        if(!nTheEnd){
            break;
        }
        for(j=0;j<packetNumber;j++){
            if(!record[j+2]){
                char *filedata=(char *)malloc(sizeof(int)*assumedDataLen);

                int returnedDataLen=readFile(fp, j*assumedDataLen, assumedDataLen, filedata);

                //generate md5 code

                memset(checkSum3,'0',16);

                
                //md5((uint8_t*)filedata,returnedDataLen,(uint8_t*)checkSum);

                char *packet=getPacket(j+3, checkSum3, returnedDataLen, packetLen , filedata);
                
                md5((uint8_t*)packet,returnedDataLen + 24,(uint8_t*)checkSum4);

                memcpy(packet + 4, checkSum4, 16);
                
                if(sendto(sock, packet, sizeof(int)*packetLen, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0){
                    perror("sendto failed3\n");
                    fclose(fp);
                    abort();
                }
                if(j+3==packetNumber+2){
                     printf("[send data] %ld (%d)\n", fileSize-returnedDataLen, returnedDataLen );
                }
                else{
                    printf("[send data] %ld (%d)\n", j*assumedDataLen, returnedDataLen );
                }
                

            }

        }


    }
    pthread_join(id,NULL);
    fclose(fp);
    printf("completed\n");
    close(sock);
    return 0;
}
