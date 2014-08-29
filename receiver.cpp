#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <iostream>
#include <errno.h>

#define BUFSIZE 2048
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
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
char *getAckPacket(unsigned int ackN, char* md5){
    
    char* packet = (char*)malloc(sizeof(int)*5);
    
    *((unsigned int *)packet)=htons(ackN);
    
    
   memcpy(packet+sizeof(unsigned int), md5, 4*sizeof(unsigned int));

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
    
    char* data=(char *)malloc(getDataLen(packet));
    
    int datalen = getDataLen(packet);
    
    memcpy(data, packet + 6*sizeof(unsigned int), datalen);

    return data;
}
/*
 *  check the data from packet is right or not
 *  input md5 code ,data and data size
 */
bool checkdata(char *md5code, char *checksum){
    
    int result = memcmp(md5code, checksum, 16);
    return result == 0?true:false;
    
}
/*
 * fix name into "xxxx.recv"
 */
char *fixname(char *name, unsigned int lengthOfName){
    
    char* newname = (char*)malloc(lengthOfName + 6);
    
    memcpy(newname,name,lengthOfName);
    
    *(newname + lengthOfName) = '.';
    *(newname + lengthOfName + 1) = 'r';
    *(newname + lengthOfName + 2) = 'e';
    *(newname + lengthOfName + 3) = 'c';
    *(newname + lengthOfName + 4) = 'v';
    *(newname + lengthOfName + 5) = '\0';
    
    return newname;
}

/*
 * check the packet valid or not
 * this will calculate md5 for ENTIRE packet to check
 */
bool checkVaildOfPackage(char *packet, unsigned int packageLength){

    char checkmd5[16];

    char md5CodeFromPacket[16];

    memcpy(md5CodeFromPacket,packet+4,16);
    
    memset(packet+4,'0',16);

    md5((uint8_t*)packet,getDataLen(packet) + 24, (uint8_t*)checkmd5);

    int result = memcmp(md5CodeFromPacket, checkmd5, 16);

    return result == 0?true:false;

}
/*
 * main function
 */
int main(int argc, char **argv)
{
    int optval = 1;
	struct sockaddr_in sin;
    /*
     * datalen of each packet
     */
    long assumedDataLen = 2000;

    int recvlen;
    int sock;
    char buf[BUFSIZE];
    char checkmd5[16];
    char md5forAck[16];
    unsigned int se,acknumber;
    char* data;
    char* checksum;
    char* ackpacket;
    bool IsDataRightOrNot = false;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    // htons(argv[2]);
    if(argc!=3){
        printf("input error\n");
        exit(0);
    }
    unsigned short server_port = atoi(argv[2]);
    sin.sin_port = htons(server_port);



    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("cannot create socket\n");
        exit(1);

    }

    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) <0)
    {
        perror ("setting TCP socket option");
        exit(1);

    }

    //************** set timeout for recvfrom
    
    struct timeval time;
    time.tv_sec=50;
    time.tv_usec=0;
    
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time))<0){
        perror("setsockopt error");
        exit(1);
    }

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind failed");
        exit(1);
    }

    struct sockaddr_in client_addre;
   
    socklen_t addr_len =sizeof(struct sockaddr_in);
    
    char* fileName;
    char* fileSizeChar;
    bool fileRelated[2]={false};
    
    
    /*
     * make file
     */
    while(1){
        recvlen = recvfrom(sock, buf, BUFSIZE, 0, (struct sockaddr *)&client_addre, &addr_len);
        //printf("received %d bytes\n", recvlen);
        if(recvlen<0){
            if(errno==EWOULDBLOCK||errno==EAGAIN){
                printf("recvfrom timeout occurs, the socket is closed\n");
                close(sock);
                exit(1);
                
            }
            else
            cout<<"recv failed"<<endl;
        }
            
        if (recvlen == assumedDataLen + 24 && getDataLen(buf) <= assumedDataLen){
            
            
            se=getSequenceNumber(buf);
            
            checksum = getChecksum(buf);
            
            
            data =getData(buf);
            
            md5((uint8_t*)data, getDataLen(buf),(uint8_t*)checkmd5);
            
            IsDataRightOrNot = checkdata(checksum,checkmd5);
            
            if(IsDataRightOrNot && se < 3){

                if(se == 1){
                    fileName=getData(buf);
                    fileRelated[0]=true;
                }
                if(se == 2){
                    fileSizeChar=getData(buf);
                    fileRelated[1]=true;
                }
                
                /*
                 * send ack back
                 */
                md5((uint8_t*)&se,sizeof(int),(uint8_t*)md5forAck);
                
                /*
                 * generate packate of ack
                 */
                ackpacket = getAckPacket(se,md5forAck);
                
                /*
                 * send ack
                 */
                if(sendto(sock, ackpacket, 5*sizeof(int), 0, (struct sockaddr *) &client_addre, sizeof(struct sockaddr)) < 0){
                    perror("sendto failed\n");
                    abort();
                }
                
            }
            else{
                printf("recv corrupt packet \n");
            }
        }
        if(fileRelated[0]&&fileRelated[1]){
            break;
            
        }
    }
    
    
    FILE *output;
    int len=strlen(fileName);
   
    char* fixedFileName=fixname(fileName, len);
    
    output=fopen(fixedFileName, "wb+");
    if( output == NULL )
    {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    unsigned int fileSize=*((unsigned int*)fileSizeChar);
    
    unsigned int stuf=0;
    char c='1';
    
    /*
     *  calculate data package number
     */
    unsigned int dataPackageNo;
    
    if(fileSize%assumedDataLen == 0)
        dataPackageNo = fileSize/assumedDataLen;
    else
        dataPackageNo = (fileSize/assumedDataLen) + 1;
    
    /*
     *  this array is use to keep record of those received data packet
     */
    bool recvdataPackage[dataPackageNo];
    /*
     * this is to indicate whether receive all package
     */
    bool recvAllPackage = false;
    
    for(unsigned int q = 0 ; q < dataPackageNo ; q++)
        recvdataPackage[q] = false;
    
    
    for(stuf=0; stuf<fileSize;stuf++){
        fputc(c, output);
    }
    
    /*
     * write file
     */
    
    while(!recvAllPackage) {
        recvlen = recvfrom(sock, buf, BUFSIZE, 0, (struct sockaddr *)&client_addre, &addr_len);
       
        if(recvlen<0){
            if(errno==EWOULDBLOCK||errno==EAGAIN){
                printf("recvfrom timeout occurs, the socket is closed\n");
                close(sock);
                exit(1);
                
            }
            else
            cout<<"recv failed"<<endl;
        }
        
        if (recvlen != assumedDataLen +24)
            printf("recv corrupt packet \n");
        
        if (recvlen == assumedDataLen + 24 && getDataLen(buf) <= assumedDataLen) {
            
            se=getSequenceNumber(buf);
        
            
            
            /*
             * get data from packet
             */
            

            data=getData(buf);
            /*
             *  get md5
             */
            checksum = getChecksum(buf);
            /*
             * calculate the md5 of data
             */
            //md5((uint8_t*)data, getDataLen(buf),(uint8_t*)checkmd5);
            /*
             * To compare it with the package one
             */
            //IsDataRightOrNot = checkdata(checksum,checkmd5);
            IsDataRightOrNot = checkVaildOfPackage(buf,recvlen);


            if(IsDataRightOrNot && se > 2 && getDataLen(buf) <= assumedDataLen){
                
                /* data is right
                 * 1.send ack back
                 * 2.store the package(not done)
                 */
                
                /*
                 *  generate ack number
                 */
                acknumber = getSequenceNumber(buf);
        
                
                unsigned int dataLen=getDataLen(buf);
                
                
                
                if(recvdataPackage[se - 3]){
                    if(se==dataPackageNo+2){
                        printf("[recv data] %d (%d) IGNORED\n", fileSize-dataLen, dataLen );
                    }
                    else{
                        printf("[recv data] %ld (%d) IGNORED\n", (se-3)*assumedDataLen, dataLen );
                    }
                }
                /*
                 * find the place to write data
                 */
                if((fseek(output, assumedDataLen*(se-3), SEEK_SET)==0) && (!recvdataPackage[se - 3])){
                    unsigned int count=0;
                    while(count<dataLen){
                        fputc(*((char*)(data+count)), output);
                        count++;
                    }
                    
                    if(se==dataPackageNo+2){
                        printf("[recv data] %d (%d) ACCEPTED\n", fileSize-dataLen, dataLen );
                    }
                    else{
                        printf("[recv data] %ld (%d) ACCEPTED\n", (se-3)*assumedDataLen, dataLen );
                    }
                    
                }
                 recvdataPackage[se - 3] = true;
                /*
                 * generate md5 code of ack number
                 */
                md5((uint8_t*)&acknumber,sizeof(int),(uint8_t*)md5forAck);
                
                /*
                 * generate packate of ack
                 */
                ackpacket = getAckPacket(acknumber,md5forAck);
                
                /*
                 * send ack
                 */
                if(sendto(sock, ackpacket, 5*sizeof(int), 0, (struct sockaddr *) &client_addre, sizeof(struct sockaddr)) < 0){
                    perror("sendto failed\n");
                    abort();
                }
            }
            
            else if((!IsDataRightOrNot) && se > 2)
                printf("recv corrupt packet \n");

            else{
                /*
                 * send ack back
                 */
                md5((uint8_t*)&se,sizeof(int),(uint8_t*)md5forAck);
                
                /*
                 * generate packate of ack
                 */
                ackpacket = getAckPacket(se,md5forAck);
                
                /*
                 * send ack
                 */
                if(sendto(sock, ackpacket, 5*sizeof(int), 0, (struct sockaddr *) &client_addre, sizeof(struct sockaddr)) < 0){
                    perror("sendto failed\n");
                    abort();
                }
            }
        }
        /*
         * To see whether recv all packet
         */
        recvAllPackage = true;
        for(unsigned int z = 0; z < dataPackageNo ; z++){
            if(!recvdataPackage[z]){
                recvAllPackage = false;
                break;
            }
        }
        
    }
    
    fclose(output);
    printf("completed\n");
    close(sock);
    return 0;
}
