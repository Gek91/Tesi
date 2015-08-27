#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024  /* maximum payload size*/

struct sockaddr_nl src_addr, dest_addr; //indirizzo di provenienza e di destinazione da utilizzare nel socket
struct nlmsghdr *nlh = NULL;            //struttura contenente l'header del messaggio
struct iovec iov;                       //
int sock_fd;                            //socket netlink
struct msghdr msg;                      //Messaggio

void main()
{
    //Crea un socket (dominio, tipo, protocollo)
    sock_fd = socket(PF_NETLINK, SOCK_RAW,NETLINK_TEST);    //apertura del socket netlink
    
    //Inizializzazione della struttura src_addr, per la parte user-space
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();                 //Pid del processo stesso
    src_addr.nl_groups = 0;                     //Non è in un gruppo multicast, connessione unicast
    
    //Associa l'indirizzo al socket (socket, indirizzo, grandezza struttura indirizzo)
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    
    //Inizializzazione della struttura dest_addr, per il kernel
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;                       //Kernel linux
    dest_addr.nl_groups = 0;                    //unicast
    
    //Inizializzazione dell'header
    nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    //Crea l'header del messaggio netlink
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);  //Lunghezza totale del messaggio
    nlh->nlmsg_pid = getpid();                  //Pid del processo
    nlh->nlmsg_flags = 0;
    //Payload del messaggio
    strcpy(NLMSG_DATA(nlh), "Hello you!");
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    //Invia il messaggio
    sendmsg(sock_fd, &msg, 0);
    
    
    /* Read message from kernel */
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    recvmsg(sock_fd, &msg, 0);
    printf(" Received message payload: %s\n", NLMSG_DATA(nlh));
    
    /* Close Netlink Socket */
    close(sock_fd);
}