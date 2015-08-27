#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024  /* maximum payload size*/

//Struttura del messaggio
typedef struct {
    int count;
    int prot;
}message;

struct sockaddr_nl src_addr, dest_addr; //indirizzo di provenienza e di destinazione da utilizzare nel socket
struct nlmsghdr *nlh = NULL;            //struttura contenente l'header del messaggio
struct iovec iov;                       //
int sock_fd;                            //socket netlink
struct msghdr msg;                      //Messaggio

int main()
{
    FILE *logfile; //File di log
    
    //Crea un socket (dominio, tipo, protocollo)
    sock_fd = socket(PF_NETLINK, SOCK_RAW,NETLINK_TEST);    //apertura del socket netlink
    if (sock_fd < 0)
    {
        printf("Errore nell'apertura del socket\n");
        return -1;
    }

    
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
    strcpy(NLMSG_DATA(nlh), "INIT PID");
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    //Invia il messaggio
    sendmsg(sock_fd, &msg, 0);
    
    logfile=fopen("log","w");
    if(logfile==NULL)
    {
        printf("Error opening file\n");
        return -1;
    }

    
    /* Read message from kernel */
    int i;
    for(i=0;i<100;i++)
    {
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        recvmsg(sock_fd, &msg, 0);
        message *m = (message *) NLMSG_DATA(nlh);
        printf(" Received message payload: %d , %d \n",m->prot,m->count);
        fprintf(logfile,"%d \t %d\n",m->prot,m->count);
    }
    
    
    strcpy(NLMSG_DATA(nlh), "END PID");
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sock_fd, &msg, 0);

    fclose(logfile);

    /* Close Netlink Socket */
    close(sock_fd);
    
    return 0;
}