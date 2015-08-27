//Header per la programmazione kernel
#include <linux/kernel.h>
#include <linux/module.h>
//Header per la manipolazione dei pacchetti
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#include <linux/time.h> //per la gestione dei timer


#include <linux/types.h> //Necessario per usare dei tipi di dato in formato kernel


typedef struct TCPid
{
    u_int32_t ipsource;
    u_int32_t ipdest;
    u_int16_t tcpsource;
    u_int16_t tcpdest;
    struct timeval timer;
    struct TCPid* next;
} TCPid_t;


static int num_tcp_flows;

static TCPid_t* tcp_flow_list;

static struct nf_hook_ops nfho;


static void searchTCPflow(u_int32_t ipsource, u_int32_t ipdest, u_int16_t tcpsource, u_int16_t tcpdest)
{
    int iterate=1;
    if(tcp_flow_list==NULL) //se la lista è vuota inserisce in testa
    {
        tcp_flow_list=kmalloc(TCPid_t,GFP_KERNEL);
        tcp_flow_list->ipsource=ipsource;
        tcp_flow_list->ipdest=ipdest;
        tcp_flow_list->tcpsource=tcpsource;
        tcp_flow_list->tcpdest=tcpdest;
        do_gettimeofday(&tcp_flow_list->timer)
        tcp_flow_list->next=NULL;
        iterate=0;
        num_tcp_flows++;
    }
    TCPid_t* it=tcp_flow_list;
    while(iterate)
    {
        if(ipsource==it->ipsource && ipdest==it->ipdest && tcpsource==it->tcpsource && tcpdest==it->tcpdest )
        {
            do_gettimeofday(&it->timer); //percorso diretto
            iterate=0;
        }
        if(ipsource==it->ipdest && ipdest==it->ipsource && tcpsource==it->tcpdest && tcpdest==it->tcpsource)
        {
            do_gettimeofday(&it->timer); //percorso inverso
            iterate=0;
        }
        if(it->next==0)// se è l'ultimo inserisce in coda
        {
            iterate=0;
            TCPid_t* nxt=kmalloc(sizeof(TCPid_t),GFP_KERNEL);
            nxt->ipsource=ipsource;
            nxt->ipdest=ipdest;
            nxt->tcpsource=tcpsource;
            nxt->tcpdest=tcpdest;
            do_gettimeofday(&nxt->timer)
            nxt->next=NULL;
            it->next=nxt;
            num_tcp_flows++;
        }
        it=it->next; //elemento successivo
    }
}


unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
 
    struct iphdr *ip  = NULL;
    struct tcphdr *tcp = NULL;

    
    if (!skb)  //se non c'è nessun socket buffer
        return NF_DROP;

    ip=ip_hdr(skb); //prende l'header IP dal buffer skb

    if (ip->protocol==6)
    {
        tcp=tcp_hdr(skb); //prende l'header TCP dal buffer skb
        
        if(tcp->ack==1) // se è un messaggio di ack controlla se il flusso è instanziato, se non lo è lo istanzia
        {
            searchTCPflow(ntohs(ip->saddr),ntohs(ip->daddr),ntohs(tcp->source),ntos(tcp->dest));
        }
   
        //printk(KERN_INFO "ip source: %pI4  \t ip dest: %pI4  \t port source: %d \t port dest: %d \n",&(ip->saddr),&(ip->daddr),ntohs(tcp->source),ntohs(tcp->dest));
        //printk(KERN_INFO "doff: %d \t res1: %d \t cwr: %d \t ece: %d \t urg: %d \t ack:%d \t psh: %d \t rst:%d \t syn:%d \t fin:%d \n",tcp->doff,tcp->res1,tcp->cwr,tcp->ece,tcp->urg,tcp->ack,tcp->psh,tcp->rst,tcp->syn, tcp->fin);
    }
    
    return NF_ACCEPT; //accetta tutti i pacchetti, possono continuare la loro transazione
}


static int __init mod_init(void)
{
    nfho.hook = hook_func; //definisce la funzione da richiamare nell'hook
    nfho.hooknum =NF_INET_PRE_ROUTING ; //Indica in che punto del protocollo è in ascolto l'hook
    nfho.pf = PF_INET; //definisce la famiglia di protocolli da usare
    nfho.priority = NF_IP_PRI_FIRST; //indica la priorità dell'hook
    
    tcp_flow_list=NULL;
    num_tcp_flows=0;
    
    
    nf_register_hook(&nfho); //registra in ascolto l'hook
    printk(KERN_INFO "Modulo TCPconn caricato\n");
    return 0;
}

static void __exit mod_exit(void)
{
    
    nf_unregister_hook(&nfho); //rilascia l'hook
    printk(KERN_INFO "Modulo TCPconn rimosso\n");
}

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);