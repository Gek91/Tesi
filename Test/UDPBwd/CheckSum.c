//Header per la programmazione kernel
#include <linux/kernel.h>
#include <linux/module.h>
//Header per la manipolazione dei pacchetti
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#define SLUS_TRAFFIC_STAT_TIMER_UP 3000
#define SLUS_TRAFFIC_STAT_TIMER_DOWN 1500

static struct nf_hook_ops nfho;

static int udp_traffic;
static int udp_avg_bdw;
static int last_udp_traffic;
static int tot_pkt_count;
struct timeval last_check;
static int traffic_stat_timer;




unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip  = NULL;
    struct udphdr *udp = NULL;
    
    if (!skb)  //se non c'è nessun socket buffer
        return NF_DROP;
    
    tot_pkt_count++; //aggiorna il contatore dei pacchetti
    int res = tot_pkt_count % traffic_stat_timer; //controlla se occorre eseguire SAP-LAW

    ip=ip_hdr(skb);

    if (ip->protocol==17)
    {
        udp=udp_hdr(skb);
        
        udp_traffic += ( ntohs( (u_int16_t) ip->tot_len) + 14 );
    }
    
    if( res == 0 )
    {
        struct timeval t;
        long dt = 0, dts = 0, dtm = 0;
        do_gettimeofday(&t); //prende l'ora attuale
        dts = ((t.tv_sec - last_check.tv_sec) * 1000 ); //converto in millisecondi
        dtm = ((t.tv_usec - last_check.tv_usec) / 1000); // /1000 poiché salvato in microsecondi e voglio millisecondi
        dt = dts + dtm; //dt è in millisecondi

        last_check.tv_sec = t.tv_sec;
        last_check.tv_usec = t.tv_usec;
        
        
        if ((dt > SLUS_TRAFFIC_STAT_TIMER_UP) && (traffic_stat_timer > 1)) //Se il tempo è troppo
        {
            traffic_stat_timer >>= 1;	// Divide per 2
        }
        else if (dt < SLUS_TRAFFIC_STAT_TIMER_DOWN) //Se il tempo non è abbastanza
        {
            traffic_stat_timer <<= 1;	// Moltiplica per 2
        }

        
        unsigned long actual_udp_bdw=0;
        if (dt > 0)
        {
            actual_udp_bdw = (unsigned long)(udp_traffic - last_udp_traffic)  / dt; //Byte/ms->Kbyte/s
        }
        // Modifica della banda UDP in base a necessità dinamiche
        if (last_udp_traffic <= 0) //se è la prima volta che è modificato o se c'è stato poco traffico
        {
            udp_avg_bdw = actual_udp_bdw;
        }
        else
        {
            udp_avg_bdw = actual_udp_bdw + (int)(actual_udp_bdw / 10); //per gestire la casistica di flussi TCP già instanziati, aumenta la banda UDP del 10% in modo che se il TCP occupasse tutta la banda restante i flussi UDP riceverebbero un ammontare di banda aggiuntivo che nel caso gli occorra occuperanno aumentando anche la banda disponibile al prossimo ricalcolo.
        }
        last_udp_traffic = udp_traffic; //Aggiorno il valore di last_udp_traffic con quello attuale

        printk(KERN_INFO "BWD :  %d \n", udp_avg_bdw);

    }
    
    
    return NF_ACCEPT; //accetta tutti i pacchetti, possono continuare la loro transazione
}

static int __init mod_init(void)
{
    nfho.hook = hook_func; //definisce la funzione da richiamare nell'hook
    nfho.hooknum =NF_INET_PRE_ROUTING ; //Indica in che punto del protocollo è in ascolto l'hook
    nfho.pf = PF_INET; //definisce la famiglia di protocolli da usare
    nfho.priority = NF_IP_PRI_FIRST; //indica la priorità dell'hook
    
    udp_traffic=0;
    udp_avg_bdw=0;
    last_udp_traffic=0;
    tot_pkt_count=0;
    do_gettimeofday(&last_check);   //inizializzazione timer
    traffic_stat_timer = 1; //Ogni quanti pacchetti eseguire la formula, modificato dinamicamente

    
    nf_register_hook(&nfho); //registra in ascolto l'hook
    printk(KERN_INFO "Modulo UDPBwd caricato\n");
    return 0;
}

static void __exit mod_exit(void)
{
    
    nf_unregister_hook(&nfho); //rilascia l'hook
    printk(KERN_INFO "Modulo UDPBwd rimosso\n");
}

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);