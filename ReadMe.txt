Packet Formats:
Our sendfile packet format is like:
unsigned int ---------- Sequence Number
char* ----------------- checksum (md5)
unsigned int ---------- data length
char* ----------------- data

Our Ack packet format is like:
unsigned int ---------- Acknowledgement Number
char* ----------------- md5

Protocols and algorithm we use:
Our send and receive function use the UDP's sendto() and receivefrom() function. Basically, we use UDP unreliable datagram protocol.
For the algorithm part, we use the md5 to check the correctness of our packet. 

Features of our design:
To deal with the delay, drop, reorder, mangle and duplicate error during the transmission, our design has some features. 

(1) To deal with the reorder problem, we write the data into the file at the time when we receive the data.  
(2) To deal with the drop problem, we use the ack number to figure out whether we should retransmit the packet to the receiver.
(3) To deal with the duplicate problem, we use bool array to keep track with the packet we have already received. And if duplicate packet arrived again, just ignore it. 
(4) To deal with the mangle problem, we use the md5 to check the packet we receive, and if we find that the packet was mangled, we just drop it. 
(5) To deal with the delay problem, we just wait it until time out.  

Examples of how to run our code: 
First, using the command "make" to compile our code, both the receiver.cpp and the sendfile.cpp.
Then, we first run the receiver. For example, if you want to use the port number 18001, then the command should like "./receiver -p 18001".
And we should run the sendfile(we made assumption that you have file to send). for example, the file you want to send is named test.txt.
Then the command should be like "./sendfile -r 128.42.209.5:18001 -f test.txt" (if the receiver's ip is 128.42.209.5.)

Things to clarify:
(1) In our program, the first two packets contain file name and file size respectively and the program makes sure that the receiver gets the first two packets correctly.
(2) Upon receiving the first two packets, receiver will create a new file with the same file size from the file from the sender side, but different contents.
(3) Our program does not have to deal with reorder problem. The reason is every time receiver receives a packet, it will calculate the offset of the data and write the data into the corresponding position of the file.
(4) On each side, the receiver or the sender, the recvfrom() function has a timeout of 5 seconds. That is, if the recvfrom() does not receive any data in 5s, then the program will exit no matter whether the transmission is finished or not.
(5) The MAX data length of our packet is 2000.

