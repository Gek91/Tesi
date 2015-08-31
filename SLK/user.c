#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

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

//Strutture necessarie per la gestione del socket e l'invio e la ricezione dei messaggi in esso
int sock_fd;                            //socket netlink
struct nlmsghdr *nlh = NULL;            //struttura contenente l'header del messaggio
struct sockaddr_nl src_addr, dest_addr; //indirizzo di provenienza e di destinazione da utilizzare nel socket
struct iovec iov;                       //
struct msghdr msg;                      //Messaggio

FILE *logfile;                          //File di log
int loop;                               //Variabile di loop
pthread_t thread;                       //Thread
pthread_mutex_t lock;                   //Mutex

//Thread che gestisce la ricezione dei messaggi dal kernel e effettua la scrittura su file delle informazioni ricevute
void *thread_func(void *arg)
{
    //Legge i messaggi dal kernel
    while(1)
    {
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        recvmsg(sock_fd, &msg, 0);
        SLK_DATA *m = (SLK_DATA *) NLMSG_DATA(nlh);
        
        //printf("%d \t %d \t %d \t %d \t %d \t %d \n",m->udp_traffic,m->num_tcp_flows,m->udp_avg_bdw,m->new_adv_wnd,m->tot_pkt_count,m->traffic_stat_timer);
        fprintf(logfile,"%d \t\t\t %d \t\t\t %d \t\t\t %d \t\t\t %d \t\t\t %d \n",m->udp_traffic,m->num_tcp_flows,m->udp_avg_bdw,m->new_adv_wnd,m->tot_pkt_count,m->traffic_stat_timer);
        pthread_mutex_lock(&lock);
        if(loop!=1)
        {
            pthread_mutex_unlock(&lock);
            break;
        }
        pthread_mutex_unlock(&lock);
    }
}


//MAIN
int main()
{
    // Variabili necessarie per la stampa dell'orario
    char buffer[26];
    time_t t;
    struct tm * now;
    
    //Crea un socket (dominio, tipo, protocollo)
    sock_fd = socket(PF_NETLINK, SOCK_RAW,NETLINK_TEST);    //apertura del socket netlink
    if (sock_fd < 0)
    {
        printf("Errore nell'apertura del socket\n");
        return -1;
    }
    printf("Socket aperto correttamente\n");
    
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
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
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
    printf("Inviato messaggio di sincronizzazione del socket\n");

    
    //Apertura file di log
    logfile=fopen("log","w");
    if(logfile==NULL)
    {
        printf("Error opening file\n");
        return -1;
    }
    //Stampa dell'ora corrente sul file
    time(&t);
    now = localtime( &t );
    strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", now);
    fprintf(logfile,"****** Start connection at ");
    fputs(buffer,logfile);
    fprintf(logfile," ******\n");
    fprintf(logfile,"udp_traffic \t\t num_tcp_flows \t\t udp_avg_bdw \t\t new_adv_wnd \t\t tot_pkt_count \t\t traffic_stat_timer \n");
    
    //Inizializzazione mutex
    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return -1;
    }
    
    loop=1;

    //Crezione pthread
    int iret1 = pthread_create(&thread, NULL, thread_func,NULL);
    if(iret1)
    {
        printf("Error opening thread");
        return -1;
    }

    //Gestisce la terminazione del salvataggio su log
    printf("Premi invio per terminare loggin\n");
    getchar();
    pthread_mutex_lock(&lock);
    printf("Interruzione ciclo\n");
    loop=0;
    pthread_mutex_unlock(&lock);
    pthread_join(thread,NULL);
    
    //Una volta terminato invia modulo kernel un messaggio per indicare che non effettua più il log dei messaggi
    strcpy(NLMSG_DATA(nlh), "END PID");
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sock_fd, &msg, 0);
    printf("Inviato messaggio di chiusura del socket\n");
    //Stampa dell'ora corrente sul file
    time(&t);
    now = localtime( &t );
    strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", now);
    fprintf(logfile,"****** Stop connection at ");
    fputs(buffer,logfile);
    fprintf(logfile," ******\n");
    
    //Elimina il mutex
    pthread_mutex_destroy(&lock);
    //Chiude il file
    fclose(logfile);
    //Chiude il socket
    close(sock_fd);
    printf("Chiusura del programma user-space correttamente avvenuta\n");
    return 0;
}