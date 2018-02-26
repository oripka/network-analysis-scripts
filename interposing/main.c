#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <sys/time.h>
 
int main(int argc , char *argv[])
{
    int socket_desc;
    struct sockaddr_in server;
    char *message , server_reply[2000];
    struct timeval timeout;

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }

    timeout.tv_sec = 0;
    timeout.tv_usec = 10;

    setsockopt(socket_desc, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timeout,
                sizeof(struct timeval));

    server.sin_addr.s_addr = inet_addr("79.140.41.176");
    server.sin_family = AF_INET;
    server.sin_port = htons( 80 );
 
    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("[-] Connect Error");
        return 1;
    }
   
    puts("[+] Connected");
     
    //Send some data
    message = "GET / HTTP/1.1\r\n\r\n";
    if( send(socket_desc , message , strlen(message) , 0) < 0)
    {
        puts("[-] Send failed");
        return 1;
    }
    puts("[+] Data Send");
     
    //Receive a reply from the server
    if( recv(socket_desc, server_reply , 40 , 0) < 0)
    {
        puts("[-] Receive failed");
    }
    puts("[+] Reply received\n");
    puts(server_reply);
     
    return 0;
}
