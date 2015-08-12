
//Header per la programmazione kernel
#include <linux/kernel.h>
#include <linux/module.h>
//Header per la manipolazione dei pacchetti
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#include <linux/moduleparam.h> //Necessario per la lettura di parametri in ingresso al programma

#include <linux/errno.h> //Definisce alcuni codici di errore

#include <linux/time.h> //per la gestione dei timer

#include <linux/spinlock.h> //per la definizione degli spinlock

//TO DO: passaggio max bandwidth da esterno, gestione errori, controllare header ethernet, controllare se dopo l'esecuzione della magic formula la divisione per 20 è adatta

///////////////////////////////////////////////////////////////////////////////////////////////////////
//Dati del programma

//Struttura dati Netfilter per la definizione di un hook
static struct nf_hook_ops nfho;
//Strutture dati per la manipolazione dei pacchetti
struct iphdr *ip  = NULL;
struct udphdr *udp = NULL;
struct tcphdr *tcp = NULL;

static int parameter=0; //parametro in ingresso dal programma


/*********************************************************************************************************
 VARIABILI DEL PROGRAMMA UTILI A SLK:
 max_bwt: Max bandwidth usata per la formula del programma, passata esternamente
 last_udp_traffic: Valore del traffico UPD in KByte l'ultima volta che è stato verificato
 udp_traffic: Valore del traffico UDP totale in KByte
 num_tcp_flows: numero di flussi TCP attualmente passanti
 udp_avg_bdw: bandwidth media in KByte utilizzata per il calcolo della formula
 new_adv_wnd: valore dell'advertised window di TCP calcolata con SAP-LAW
 last_check: indica quando è stata calcolata per l'ultima volta la bandwidth UPD
 
 tot_pkt_count : Contatore numero totale di pacchetti
 traffic_stat_timer : Definisce ogni quanti pacchetti eseguire la formula
 **********************************************************************************************************/
static int max_bwt;
static int last_upd_traffic;
static int udp_traffic;
static int num_tcp_flows;
static int udp_avg_bdw;
static int new_adv_wnd;
struct timeval last_check;

static int tot_pkt_count;
static int traffic_stat_timer;
/*********************************************************************************************************
 SEMAFORI E MUTEX
 lock_udp_traffic: spinlock per l'accesso alla variabile udp_traffic
 *********************************************************************************************************/
static spinlock_t lock_udp_traffic;

////////////////////////////////////////////////////////////////////////////////////////////////////////////

//definisce che riceverà in ingresso un parametro quando il programma è eseguito
module_param(parameter, int, 0 ); //prende in ingresso il parametro, il suo tipo e i permessi
MODULE_PARM_DESC(parameter, "Parametro in ingresso"); //descrittore del parametro

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Hook utilizzato da Netfilter

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    tot_pkt_count++;
    if (!skb)  //se non c'è nessun socket buffer
        return NF_ACCEPT;
    
    ip=ip_hdr(skb); //prende dal socket buffer l'header ip e lo salva nella struttura adatta
    //printk(KERN_INFO "Header IP \t source: %pI4 \t destination: %pI4 \t lenght:%u byte \n",&(ip->saddr),&(ip->daddr),ip->tot_len); //%pI4 permette la stampa dell'indirizzo in formato leggibile, occorre passargli il reference alla variabile
    
    if(ip->protocol == 17) //se è UDP
    {
        udp=udp_hdr(skb);
        
        spin_lock(&lock_udp_traffic); //blocco ulteriori accessi alla risorsa
        udp_traffic += (ip->tot_len + 14); //aggiungo al traffico UDP la grandezza di questo pacchetto, comprende oltre al pacchetto UDP anche l'header IP e l'header ethernet (14)
        spin_unlock(&lock_udp_traffic); //libero la risorsa
        
        //printk(KERN_INFO "Pacchetto UDP \t source:%u \t destination:%u \t lenght:%u byte \n",udp->source,udp->dest, udp->len);
    }
    
    /*if(ip->protocol == 6) //se è TCP
    {
        tcp=tcp_hdr(skb);
        printk(KERN_INFO "Pacchetto TCP \t source:%d \t destination:%d\n",tcp->source,tcp->dest);
    }*/
    
    if(tot_pkt_count % traffic_stat_timer == 0)
    {
        //TCP FLOW NUM, TO DO
        
        //UDP BANDWIDTH; TO DO
        
        //Calcolo della Magic Formula della SAP-LAW
        new_adv_wnd = ( max_bwt - udp_avg_bdw ) / num_tcp_flows;
        if( new_adv_wnd > 65535 ) //TCP advertised windows ha valori da 0 a 65535
            new_adv_wnd = 65535;
        else
            if(new_adv_wnd < 0 ) //Evita che la advertised windows sia un valore nullo
                new_adv_wnd = (int)(max_bwt / 20); //CONTROLLARE SE IL VALORE 20 è ADATTO
    }
    
    return NF_ACCEPT; //accetta tutto
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Funzione di inizializzazione del modulo, __init indica che è utilizzata solo per quello

static int __init mod_init(void)
{
    printk(KERN_INFO "Inizializzazione modulo SLK: SAP-LAW KERNEL \n");
    
    //Definisce i valori della struttura dati che implementa l'hook
    nfho.hook = hook_func; //definisce la funzione da richiamare nell'hook
    nfho.hooknum =NF_INET_PRE_ROUTING ; //Indica in che punto del protocollo è in ascolto l'hook
    nfho.pf = PF_INET; //definisce la famiglia di protocolli da usare
    nfho.priority = NF_IP_PRI_FIRST; //indica la priorità dell'hook
    printk(KERN_INFO "Inizializzzione Kernel hook completata \n");
    
    //Inizializzazione variabili del programma
    //max_bwt;
    last_upd_traffic = 0;
    udp_traffic = 0;  //traffico UDP
    num_tcp_flows = 0;    //numero flussi TCP
    udp_avg_bdw = 0;  //Bandwidht UDP
    new_adv_wnd = 0;  //Advertised windows
    do_gettimeofday(&last_check);   //inizializzazione timer
    
    tot_pkt_count = 0; //contatore pacchetti
    traffic_stat_timer = 1; //Ogni quanti pacchetti eseguire la formula, modificato dinamicamente
    printk(KERN_INFO "Inizializzazione variabili completata \n");
    
    //Inizializzazione semafori e spinlock
    spin_lock_init(&lock_udp_traffic);  //spinlock udp_traffic
    
    printk(KERN_INFO "Inizializzazione semafori e spinlock completata \n");

    
    nf_register_hook(&nfho); //registra in ascolto l'hook
    printk(KERN_INFO "Inizializzazione SLK completata, modulo caricato correttamente \n");
    
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Funzione di terminazione del modulo, __exit definisce che è utilizzata solo per quello

static void __exit mod_exit(void)
{
    nf_unregister_hook(&nfho); //rilascia l'hook
    printk(KERN_INFO,"Totale pacchetti ricevuti:%d", tot_pkt_count );
    printk(KERN_INFO "Rimozione del modulo SKL: SAP-LAW KERNEL \n");
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);

//Definiscono delle informazioni riguardati in modulo
MODULE_AUTHOR("Giacomo Pandini");
MODULE_DESCRIPTION("SLK, Sap-Law Kerel");
MODULE_LICENSE("Take away pizza");



