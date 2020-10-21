#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<errno.h>
#include<unistd.h>
#include<string.h>
#include<sys/types.h>                                                                                      
#include<arpa/inet.h>
#include<netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define _BACKLOG_ 100

void getFileName(char * name, int size)
{
    int fd = open("/dev/urandom", 0);
    unsigned long d;
    read(fd, &d, 8);
    close(fd);
    snprintf(name, size, "%lx", d);
}

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        printf("%s <port>\n", argv[0]);
        return 1;
    }
    
    unsigned short port = (unsigned short)atoi(argv[1]);    
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0)
    {
        perror("socket");
        return 1;
    }
    
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    
    if(bind(listenfd, (struct sockaddr*)&server_addr,sizeof(struct sockaddr_in)) < 0)
    {
        perror("bind");
        close(listenfd);
        return 1;
    }
    
    if(listen(listenfd, _BACKLOG_) < 0)
    {
        perror("listen");
        close(listenfd);
        return 1;
    }
    
    printf("start listen on %d\n", port);
    for(;;)
    {
        socklen_t len = 0;
        int client_sock = accept(listenfd, (struct sockaddr*)&client_addr, &len);
        if(client_sock < 0)
        {
            perror("accept");
            return 1;
        }
        
        char host[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, host, sizeof(host));

        printf("new connect\n");
        pid_t pid = fork();
        if(pid < 0)
        {
            perror("fork:");
            break;
        }
        else if(pid == 0) //child
        {
           close(listenfd);//关闭监听套接字
           char buf[1024] = {0};
           char name[255] = {0};
           int offset = snprintf(name, sizeof(name), "%d_", port);
           getFileName(name + offset, sizeof(name) - offset);
           strcat(name, ".cap");
           int fd = open(name, O_WRONLY|O_CREAT );
           while(1)
           {
               int recvLen = read(client_sock, buf, sizeof(buf));
               if(recvLen <= 0)
                   break;
               write(fd, buf, recvLen);
           }
           close(fd);
           close(client_sock);
           printf("writted file %s\n", name);
           return 0;
        }
    }
    close(listenfd);
    return 0;
}
