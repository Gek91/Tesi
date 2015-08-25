#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024  /* maximum payload size*/

//Struttura del messaggio ricevuto
typedef struct
{
    int max_bwt;
    int last_udp_traffic;
    int udp_traffic;
    int num_tcp_flows;
    int udp_avg_bdw;
    int new_adv_wnd;
    int const_adv_wnd;
    struct timeval last_check;
    
    int tot_pkt_count;
    int mod_pkt_count;
    int traffic_stat_timer;
    
} SLK_DATA;

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
    printf("Inviato messaggio di sincronizzazione del socket");
    strcpy(NLMSG_DATA(nlh), "INIT PID");
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    //Invia il messaggio
    sendmsg(sock_fd, &msg, 0);
    
    
    /* Read message from kernel */
    while(1)
    {
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        recvmsg(sock_fd, &msg, 0);
        SLK_DATA *m = (SLK_DATA *) NLMSG_DATA(nlh);
        printf(" Received message payload: \t udp_traffic:%d \t num_tcp_flows:%d \t udp_avg_bdw:%d \t new_adv_wnd:%d \t tot_pkt_count:%d \t traffic_stat_timer:%d \t lastcheck:%ld.%06ld sec\n",m->udp_traffic,m->num_tcp_flows,m->udp_avg_bdw,m->new_adv_wnd,m->tot_pkt_count,m->traffic_stat_timer,m->last_check.tv_sec,m->last_check.tv_usec);
    }
    /* Close Netlink Socket */
    close(sock_fd);
}