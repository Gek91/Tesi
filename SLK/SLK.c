
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

#include <linux/types.h> //Necessario per usare dei tipi di dato in formato kernel

#include <linux/slab.h> //necessario per la kmalloc
#include <linux/gfp.h> //flag della kmalloc , DA VERIFICARE

#include <linux/string.h> //per la memcpy


#define SLUS_TRAFFIC_STAT_TIMER_UP 3000
#define SLUS_TRAFFIC_STAT_TIMER_DOWN 1500

//TO DO: passaggio max bandwidth da esterno, gestione errori(anche negli spinlock), controllare header ethernet, controllare se dopo l'esecuzione della magic formula la divisione per 20 è adatta, controllare se il controllo tot_pkt_count == 1 non serve,

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
 const_adv_wnd: variabile che contiene un eventuale valore fisso della adverstised windows impostato dall'utente
 last_check: indica quando è stata calcolata per l'ultima volta la bandwidth UPD
 
 tot_pkt_count : Contatore numero totale di pacchetti
 traffic_stat_timer : Definisce ogni quanti pacchetti eseguire la formula
 **********************************************************************************************************/
static int max_bwt;
static int last_udp_traffic;
static int udp_traffic;
static int num_tcp_flows;
static int udp_avg_bdw;
static int new_adv_wnd;
static int const_adv_wnd;
struct timeval last_check;

static int tot_pkt_count;
static int mod_pkt_count;
static int traffic_stat_timer;
/*********************************************************************************************************
 SEMAFORI E MUTEX
 lock_udp_traffic: spinlock per l'accesso alla variabile udp_traffic
 lock_last_udp_traffic: spinlock per l'accesso alla variabile last_udp_traffic
 lock_num_tcp_flows: spinlock per l'accesso alla variabile lock_num_tcp_flows
 lock_udp_avg_bdw: spinlock per l'accesso alla variabile udp_avg_traffic
 rwlock_new_adv_wnd: rw spinlock per l'accesso alla variabile new_adv_wnd
 lock_last_check : spinlock per l'accesso alla variabile last_check
 
 lock_tot_pkt_count: spinlock per l'accesso alla variabile tot_pkt_count
 lock_mod_pkt_count: spinlock per l'accesso alla variabile mod_pkt_count
 rwlock_traffic_stat_timer : rw spinlock per l'accesso alla variabile last_check
 *********************************************************************************************************/
static spinlock_t lock_udp_traffic;
static spinlock_t lock_last_udp_traffic;
static spinlock_t lock_num_tcp_flows;
static spinlock_t lock_udp_avg_bdw;
static rwlock_t rwlock_new_adv_wnd;
static spinlock_t lock_last_check;

static spinlock_t lock_tot_pkt_count;
static spinlock_t lock_mod_pkt_count;
static rwlock_t rwlock_traffic_stat_timer;
////////////////////////////////////////////////////////////////////////////////////////////////////////////

//definisce che riceverà in ingresso un parametro quando il programma è eseguito
module_param(parameter, int, 0 ); //prende in ingresso il parametro, il suo tipo e i permessi
MODULE_PARM_DESC(parameter, "Parametro in ingresso"); //descrittore del parametro

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Funzioni del programma

////////////////////////////////Hook utilizzato da Netfilter/////////////////////////////////////////////////

/************************************************************************************************************
 slus_calc_chksum_buf()
 Calcola il checksum sul buffer passato in ingresso. Ritorna il valore calcolato
 - packet:Puntatore al buffer cotenente lo pseudoheader TCP e tutto il segmento TCP del messaggio
 - packlen:Lunghezza in byte del buffer contenente i dati su cui eseguire il checksum
 ************************************************************************************************************/
static u_int16_t slus_calc_chksum_buf(u_int16_t *packet, int packlen) {
    unsigned long sum = 0;
    
    while (packlen > 1) {
        sum += *(packet++);
        packlen -= 2;
    }
    
    if (packlen > 0) {
        sum += *(unsigned char *)packet;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    return (u_int16_t) ~sum;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    int res; //Variabile ausiliaria usata per controllare se occorre aggiornare i parametri con SAP-LAW
    spin_lock(&lock_tot_pkt_count); // Prenota le risorse tot_pkt_count e Traffic_stat_timer
    read_lock(&rwlock_traffic_stat_timer);
    tot_pkt_count++; //aggionra il contatore dei pacchetti
    res = tot_pkt_count % traffic_stat_timer; //controlla se occorre eseguire SAP-LAW
    read_unlock(&rwlock_traffic_stat_timer);
    spin_unlock(&lock_tot_pkt_count); //Libera le risorse utilizzate

    if (!skb)  //se non c'è nessun socket buffer
        return NF_DROP;
    
    ip=ip_hdr(skb); //prende l'header IP
    
    //printk(KERN_INFO "Header IP \t source: %pI4 \t destination: %pI4 \t lenght:%u byte \n",&(ip->saddr),&(ip->daddr),ip->tot_len); //%pI4 permette la stampa dell'indirizzo in formato leggibile, occorre passargli il reference alla variabile
    
    switch (ip->protocol) //Controllo sul protocollo di trasporto
    {
        case 17: //UDP
            udp=udp_hdr(skb); //prende l'header UPD
            
            spin_lock(&lock_udp_traffic); //blocco ulteriori accessi alla risorsa udp_traffic
            udp_traffic += (ip->tot_len + 14); //aggiungo al traffico UDP la grandezza di questo pacchetto, comprende oltre al pacchetto UDP anche l'header IP e l'header ethernet (14)
            spin_unlock(&lock_udp_traffic); //libero la risorsa
            
            //printk(KERN_INFO "Pacchetto UDP \t source:%u \t destination:%u \t lenght:%u byte \n",udp->source,udp->dest, udp->len);
            break;
            
        case 6: //TCP
            tcp=tcp_hdr(skb); //prende l'header TCP
            int mod=0; //utile a definire se il pacchetto viene modificato
            if (const_adv_wnd < 0)// se non è impostato un valore fisso di advertised window
            {
                read_lock(&rwlock_new_adv_wnd); //Riserva in lettura la risorsa new_adv_wnd
                if( tcp->window > (u_int16_t)new_adv_wnd ) //imposta il valore minore tra quello attuale e quello calcolato
                {
                    tcp->window = (u_int16_t) new_adv_wnd;
                    mod++;
                }
                read_unlock(&rwlock_new_adv_wnd); // Rilascia la risorsa new_adv_wnd
            }
            else
            {
                tcp->window = (u_int16_t) const_adv_wnd; //imposta il valore fisso definito dall'utente
                mod++;
            }
            
            if (mod)// se il pacchetto viene modificato
            {
                //RESET CHECKSUM
                u_int16_t tcp_tot_len = ip->tot_len - 20; //calcola lunghezza segmento TCP
                u8 *buf=kmalloc(12 + tcp_tot_len,GFP_KERNEL);
                
                (void *)memcpy(buf, &(ip->saddr), sizeof(u_int32_t));	// Pseudo header src address
                (void *)memcpy(&(buf[4]), &(ip->daddr), sizeof(u_int32_t));	// Pseudo header dst address
                buf[8] = 0;							// Pseudo header reserved location
                buf[9] = ip->protocol;			// Pseudo header protocol version (6 for TCP)
                buf[10]=(u_int16_t)((tcp_tot_len) & 0xFF00) >> 8;	// Pseudo header total TCP length (left byte)
                buf[11]=(u_int16_t)((tcp_tot_len) & 0x00FF);		// Pseudo header total TCP length (rigth byte)
                
                tcp->check = 0;
                
                (void *)memcpy(buf + 12, tcp, tcp_tot_len);
                tcp->check = slus_calc_chksum_buf((u_int16_t *)buf, 12 + tcp_tot_len); //Ricalcolo del checksum
                
                spin_lock(&lock_mod_pkt_count);
                mod_pkt_count++; //aumenta il contore dei pacchetti modificati
                spin_unlock(&lock_mod_pkt_count);
            }
            
            //printk(KERN_INFO "Pacchetto TCP \t source:%d \t destination:%d\n",tcp->source,tcp->dest);
            break;
            
        default:
            break;
    }
    
    //CONTROLLARRE SE NON SERVE IL CONTROLLO tot_pkt_count == 1 PRESENTE NELL'ALTRO PROGRAMMA
    if( res == 0 && const_adv_wnd < 0) //Occorre eseguire la SAP-LAW
    {
        //TCP FLOW NUM, TO DO
        
        struct timeval t;
        long dt = 0, dts = 0, dtm = 0; //variabili di supporto per il calcolo del passare del tempo
        unsigned long actual_udp_bdw = 0; //variabile di supporto per il calcolo della bandwidth UDP attuale
        //Calcolo differenza temporale
        do_gettimeofday(&t); //prende l'ora attuale
        spin_lock(&lock_last_check); //accesso in lettura a last_check
        dts = ((t.tv_sec - last_check.tv_sec) * 1000 ); //converto in millisecondi
        dtm = ((t.tv_usec - last_check.tv_usec) / 1000); // /1000 poiché salvato in microsecondi e voglio millisecondi
        dt = dts + dtm; //dt è in millisecondi
        
        //Aggiorno il valore di last_check
        last_check.tv_sec = t.tv_sec;
        last_check.tv_usec = t.tv_usec;
        spin_unlock(&lock_last_check); //libera la risorsa last_check
        
        // Aggiorna il valore di traffic_stat_timer
        write_lock(&rwlock_traffic_stat_timer); //Prenota la risorsa traffic_stat_timer in scrittura
        if ((dt > SLUS_TRAFFIC_STAT_TIMER_UP) && (traffic_stat_timer > 1)) //Se il tempo è troppo
        {
            traffic_stat_timer >>= 1;	// Divide per 2
        }
        else if (dt < SLUS_TRAFFIC_STAT_TIMER_DOWN) //Se il tempo non è abbastanza
        {
            traffic_stat_timer <<= 1;	// Moltiplica per 2
        }
        write_unlock(&rwlock_traffic_stat_timer); // libera la risorsa
        
        spin_lock(&lock_udp_avg_bdw);   //Riserva la risorsa udp_avg_bdw
        spin_lock(&lock_udp_traffic); // Riserva le risorse per il calcolo della nuova bandwidth UDP
        spin_lock(&lock_last_udp_traffic);
        //Calcolo della bandwidth UDP
        if (dt > 0)
        {
            actual_udp_bdw = (unsigned long)((udp_traffic - last_udp_traffic) * 1000UL) / dt;
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
        spin_unlock(&lock_last_udp_traffic); //Libero le risorse usate per il calcolo della banda UDP
        spin_unlock(&lock_udp_traffic);
    
        spin_lock(&lock_num_tcp_flows); //Riserva la risorsa num_tcp_flows
        write_lock(&rwlock_new_adv_wnd); //Riserva il scrittura la risorsa new_adv_wnd
        //Calcolo della Magic Formula della SAP-LAW
        new_adv_wnd = ( max_bwt - udp_avg_bdw ) / num_tcp_flows;
        
        if( new_adv_wnd > 65535 ) //TCP advertised windows ha valori da 0 a 65535
            new_adv_wnd = 65535;
        else
            if(new_adv_wnd < 0 ) //Evita che la advertised windows sia un valore nullo
                new_adv_wnd = (int)(max_bwt / 20); //CONTROLLARE SE IL VALORE 20 è ADATTO
        write_unlock(&rwlock_new_adv_wnd); //Rilascia la risorsa new_adv_wnd
        spin_unlock(&lock_num_tcp_flows); //Rilascia la risorsa num_tcp_flows
        spin_unlock(&lock_udp_avg_bdw); //rilascio della risorsa udp_avg_bwd
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
    last_udp_traffic = 0;
    udp_traffic = 0;  //traffico UDP
    num_tcp_flows = 0;    //numero flussi TCP
    udp_avg_bdw = 0;  //Bandwidht UDP
    new_adv_wnd = 0;  //Advertised windows
    const_adv_wnd = -1;
    do_gettimeofday(&last_check);   //inizializzazione timer
    tot_pkt_count = 0; //contatore pacchetti
    traffic_stat_timer = 1; //Ogni quanti pacchetti eseguire la formula, modificato dinamicamente
    printk(KERN_INFO "Inizializzazione variabili completata \n");
    
    //Inizializzazione semafori e spinlock
    spin_lock_init(&lock_udp_traffic);  //spinlock udp_traffic
    spin_lock_init(&lock_last_udp_traffic);  //spinlock last_udp_traffic
    spin_lock_init(&lock_num_tcp_flows); //spinlock num_tcp_flows
    spin_lock_init(&lock_udp_avg_bdw); //spinlock udp_avf_bwd
    rwlock_init(&rwlock_new_adv_wnd); //rw spinlock new_adv_wnd
    spin_lock_init(&lock_last_check); //spinlock last_check
    spin_lock_init(&lock_tot_pkt_count); //spinlock tot_pkt_count
    spin_lock_init(&lock_mod_pkt_count); //spinlock mod_pkt_count
    rwlock_init(&rwlock_traffic_stat_timer); //rw spinlock traffic_stat_timer
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
    printk(KERN_INFO "Totale pacchetti ricevuti:%d", tot_pkt_count );
    printk(KERN_INFO "Rimozione del modulo SKL: SAP-LAW KERNEL \n");
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);

//Definiscono delle informazioni riguardati in modulo
MODULE_AUTHOR("Giacomo Pandini");
MODULE_DESCRIPTION("SLK, Sap-Law Kernel");
MODULE_LICENSE("Take away pizza");

