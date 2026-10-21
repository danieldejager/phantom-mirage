/*
 * Minimal honeyd subsystem for CI (issue #22): listens on 18080 via the
 * libhoneyd.so shim and answers every connection with "hello\n".
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(18080); a.sin_addr.s_addr=htonl(INADDR_ANY);
  if(bind(s,(void*)&a,sizeof a)){perror("bind");return 1;}
  if(listen(s,5)){perror("listen");return 1;}
  for(;;){int c=accept(s,0,0); if(c<0){perror("accept");return 1;} write(c,"hello\n",6); close(c);}
}
