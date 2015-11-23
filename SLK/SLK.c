
#include "SLK.h"

//TO DO: GESTIONE FLUSSI TCP Più INTELLIGENTE Test da fare
//Conteggio pacchetti
//conteggio totale traffico udp
//conteggio flussi TCP
//controllo banda udp corrente
//controllo magic formula

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////Hook utilizzato da Netfilter/////////////////////////////////////////////////

/************************************************************************************************************
 slk_check_update_SL()
 Aumenta il contatore dei pacchetti ricevuti. Controlla se occorre aggiornare i parametri di gestione del traffico richiamando la formula di SAP-LAW. Ritorna 0 se occorre aggiornarli, un altro numero altrimenti
 ************************************************************************************************************/
static int slk_check_update_SL(void)
{
    int res; //Variabile ausiliaria usata per controllare se occorre aggiornare i parametri con SAP-LAW
    spin_lock(&lock_tot_pkt_count); // Prenota le risorse tot_pkt_count e traffic_stat_timer
    read_lock(&rwlock_traffic_stat_timer);
    slk_info->tot_pkt_count++; //aggiorna il contatore dei pacchetti
    res = slk_info->tot_pkt_count % slk_info->traffic_stat_timer; //controlla se occorre eseguire SAP-LAW
    read_unlock(&rwlock_traffic_stat_timer);
    spin_unlock(&lock_tot_pkt_count); //Libera le risorse utilizzate
    return res;
}

/************************************************************************************************************
 slk_udp_handle()
 Gestisce le operazioni da eseguire nel caso il pacchetto contenga un segmento UDP. Aggiorna il contatore del traffico UDP.
 - ip: puntatore alla struttura che contiene l'header ip
 - udp: puntatore alla struttura che contiene l'header udp
 ************************************************************************************************************/
static void slk_udp_handle(struct iphdr *ip, struct udphdr *udp)
{
    spin_lock(&lock_udp_traffic); //blocco ulteriori accessi alla risorsa udp_traffic
    slk_info->udp_traffic += ( ntohs( (u_int16_t) ip->tot_len) + 14 ); //aggiungo al traffico UDP la grandezza di questo pacchetto, comprende oltre al pacchetto UDP anche l'header IP e l'header ethernet (14)
    spin_unlock(&lock_udp_traffic); //libero la risorsa
}

/*************************************************************************************************************
 searchTCPflow()
 Controlla se il flusso passato in ingresso attraverso i 4 valori che lo identificano è già presente nella lista dei flussi TCP attivi. Se non lo è lo inserisce nella lista aumentando il contatore dei flussi TCP
 - ipsource: indirizzo IP di provenienza
 - ipdest: indirizzo IP di destinazione
 - tcpsource: porta di provenienza
 - tcpdest: porta di destinazione
 *************************************************************************************************************/
static void searchTCPflow(u_int32_t ipsource, u_int32_t ipdest, u_int16_t tcpsource, u_int16_t tcpdest)
{
    int iterate=1; //Variabile utilizzata per continuare o fermare il ciclo while
    TCPid_t* it;
    TCPid_t* nxt;
    spin_lock(&lock_tcp_flow_list); //riserva la risorsa tcp_flow_list
    if(tcp_flow_list==NULL) //se la lista è vuota inserisce in testa
    {
        //crea il nuovo elemento
        tcp_flow_list=kmalloc(sizeof(TCPid_t),GFP_KERNEL);
        tcp_flow_list->ipsource=ipsource;
        tcp_flow_list->ipdest=ipdest;
        tcp_flow_list->tcpsource=tcpsource;
        tcp_flow_list->tcpdest=tcpdest;
        do_gettimeofday(&tcp_flow_list->timer);
        tcp_flow_list->next=NULL;
        iterate=0;
        spin_lock(&lock_num_tcp_flows);
        slk_info->num_tcp_flows++; //aumenta il numero dei flussi TCP presenti
        spin_unlock(&lock_num_tcp_flows);
    }
    it=tcp_flow_list;
    while(iterate) //se non è vuota cerca l'elemento nella lista
    {
        if(ipsource==it->ipsource && ipdest==it->ipdest && tcpsource==it->tcpsource && tcpdest==it->tcpdest )
        { //se lo trova aggiorna il valore di timer
            do_gettimeofday(&it->timer); //percorso diretto
            iterate=0;
        }
        if(ipsource==it->ipdest && ipdest==it->ipsource && tcpsource==it->tcpdest && tcpdest==it->tcpsource)
        { //se lo trova aggiorna il valore di timer
            do_gettimeofday(&it->timer); //percorso inverso
            iterate=0;
        }
        if(it->next==0)//Se non lo trova lo aggiunge al termine della lista
        {
            //crea il nuovo elemento
            nxt=kmalloc(sizeof(TCPid_t),GFP_KERNEL);
            nxt->ipsource=ipsource;
            nxt->ipdest=ipdest;
            nxt->tcpsource=tcpsource;
            nxt->tcpdest=tcpdest;
            do_gettimeofday(&nxt->timer);
            nxt->next=NULL;
            it->next=nxt;
            iterate=0;
            spin_lock(&lock_num_tcp_flows);
            slk_info->num_tcp_flows++; //aumenta il numero dei flussi TCP presenti
            spin_unlock(&lock_num_tcp_flows);
        }
        it=it->next; //elemento successivo
    }
    spin_unlock(&lock_tcp_flow_list); //libera la risorsa tcp_flow_list
}

/************************************************************************************************************
 slk_calc_check()
 Esegue il calcolo del checksum per il pacchetto tcp passato in ingresso. Ricalcola anche il checksum IP per il messaggio
 - ip: puntatore alla struttura che contiene l'header ip
 - tcp: puntatore alla struttura che contiene l'header tcp
 - slk: puntatore alla struttura che contiene l'intero buffer contenente il messaggio
 ************************************************************************************************************/
static void slk_calc_check(struct iphdr *ip, struct tcphdr *tcp,struct sk_buff *skb)
{
    //RESET CHECKSUM
    u_int16_t tcplen = (skb->len - (ip->ihl << 2)); //Calcola la lunghezza del segmento TCP
    tcp->check = 0; //Imposta a 0 il valore del checksum per il suo ricalcolo
    tcp->check = tcp_v4_check(tcplen,ip->saddr,ip->daddr, csum_partial((char *)tcp, tcplen, 0)); //Esegue il ricalcolo del checksum TCP
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    ip->check = 0; //Imposta a 0 il valore del checksum ip per il suo calcolo
    ip->check = ip_fast_csum((u8 *)ip, ip->ihl); //Esegue il ricalcolo del checksum IP
}

/************************************************************************************************************
 slk_tcp_handle()
 Gestisce le operazioni da eseguire nel caso il pacchetto contenga un segmento TCP. Modifica il valore della advertised windows in relazione ai parametri impostati dalla SAP-LAW. Aggiorna poi il checksum del pacchetto.
 - ip: puntatore alla struttura che contiene l'header ip
 - skb: puntatore alla struttura che contiene l'intero buffer contenente il messaggio
 ************************************************************************************************************/
static void slk_tcp_handle(struct iphdr *ip, struct sk_buff *skb)
{
    struct tcphdr *tcp = NULL;
    int mod=0; //utile a definire se il pacchetto viene modificato
    tcp=tcp_hdr(skb); //prende l'header TCP dal buffer skb
    if (slk_info->const_adv_wnd < 0)// se non è impostato un valore fisso di advertised window
    {
        searchTCPflow(ntohs(ip->saddr),ntohs(ip->daddr),ntohs(tcp->source),ntohs(tcp->dest)); //controlla la presenza del flusso relativo al pacchetto, se non esiste lo inserisce
        
        read_lock(&rwlock_new_adv_wnd); //Riserva in lettura la risorsa new_adv_wnd
        if( ntohs (tcp->window) > (u_int16_t)slk_info->new_adv_wnd ) //imposta il valore minore tra quello attuale e quello calcolato con SAP-LAW
        {
            tcp->window = htons ((u_int16_t) slk_info->new_adv_wnd);
            mod++;
        }
        read_unlock(&rwlock_new_adv_wnd); // Rilascia la risorsa new_adv_wnd
    }
    else //Se il valore fisso è impostato
    {
        tcp->window =htons ( (u_int16_t) slk_info->const_adv_wnd); //imposta il valore fisso definito dall'utente
        mod++;
    }
    
    if (mod)// se il pacchetto viene modificato
    {
        slk_calc_check(ip,tcp,skb); //calcola il nuovo valore del checksum del pacchetto modificato
        
        spin_lock(&lock_mod_pkt_count);
        slk_info->mod_pkt_count++; //aumenta il contatore dei pacchetti modificati
        spin_unlock(&lock_mod_pkt_count);
    }
}

/************************************************************************************************************
 slk_calc_df()
 Calcola la differenza temporale tra l'ultimo check e l'ora attuale, aggiorna poi il valore di ultimo check. Ritorna questa differenza
 - t: struttura timeval contenente l'ora attuale, utilizzata per confrontare il suo valore con il precedente valore in cui si è eseguita l'operazione
 ************************************************************************************************************/
static long slk_calc_df(struct timeval t)
{
    long dt = 0, dts = 0, dtm = 0; //variabili di supporto per il calcolo del passare del tempo
    //Calcolo differenza temporale
    spin_lock(&lock_last_check); //accesso in lettura a last_check
    dts = ((t.tv_sec - slk_info->last_check.tv_sec) * 1000 ); //converto in millisecondi
    dtm = ((t.tv_usec - slk_info->last_check.tv_usec) / 1000); // /1000 poiché salvato in microsecondi e voglio millisecondi
    dt = dts + dtm; //dt è in millisecondi
    
    //Aggiorno il valore di last_check
    slk_info->last_check.tv_sec = t.tv_sec;
    slk_info->last_check.tv_usec = t.tv_usec;
    spin_unlock(&lock_last_check); //libera la risorsa last_check
    return dt;
}

/************************************************************************************************************
 slk_update_tst()
 Aggiorna il valore di traffic_stat_timer in relazione al tempo calcolato dt
 - dt: differenza di tempo tra l'ora attuale e l'ultimo check in ms
 ************************************************************************************************************/
static void slk_update_tst(long dt)
{
    // Aggiorna il valore di traffic_stat_timer
    write_lock(&rwlock_traffic_stat_timer); //Prenota la risorsa traffic_stat_timer in scrittura
    if ((dt > SLK_TRAFFIC_STAT_TIMER_UP) && (slk_info->traffic_stat_timer > 1)) //Se il tempo è troppo
    {
        slk_info->traffic_stat_timer >>= 1;	// Divide per 2
    }
    else if (dt < SLK_TRAFFIC_STAT_TIMER_DOWN) //Se il tempo non è abbastanza
    {
        slk_info->traffic_stat_timer <<= 1;	// Moltiplica per 2
    }
    write_unlock(&rwlock_traffic_stat_timer); // libera la risorsa
}

/************************************************************************************************************
 time_check_tcp_flows()
 Confronta il valore temporale corrente passato in ingresso con i valori temporali relativi a tutti i flussi TCP presenti nella lista che contiene quelli attivi al momento. Se trova un valore di differenza tra i due valori superiore alla soglia impostata per il KeepAlive elimina il flusso decrementando il contatore
 t: struttura timeval contenete il valore temporale da confrontare con i valori relativi al timeout dei flussi TCP
 ************************************************************************************************************/
static void time_check_tcp_flows(struct timeval t)
{
    long dt = 0, dts = 0, dtm = 0; //variabili di supporto per il calcolo del passare del tempo
    TCPid_t* it;
    TCPid_t* prev;
    spin_lock(&lock_tcp_flow_list); //prenota la risorsa tcp_flow_list
    it=tcp_flow_list; //puntatori utilizzati per scorrere la lista dei flussi TCP
    prev=NULL;
    
    while(it!=NULL) //Elimino i flussi TCP che hanno passato il timeout keepalive
    {
        //Calcolo differenza temporale tra il valore attuale e il valore di timer dell'elemento analizzato
        dts = ((t.tv_sec - it->timer.tv_sec) * 1000 ); //converto in millisecondi
        dtm = ((t.tv_usec - it->timer.tv_usec) / 1000); //1000 poiché salvato in microsecondi e voglio millisecondi
        dt = dts + dtm; //dt è in millisecondi
        if(dt>SLK_TCP_KEEPALIVE_TIMER) //se il timer ha passato il valore di keepalive
        {
            if(prev==NULL) // se è il primo elemento della lista
            {
                tcp_flow_list=tcp_flow_list->next; //sposto il puntatore della testa della lista
                kfree(it); //libero l'elemento
                spin_lock(&lock_num_tcp_flows);
                slk_info->num_tcp_flows--; //diminuisce il numero dei flussi TCP presenti
                spin_unlock(&lock_num_tcp_flows);
                it=tcp_flow_list; //continuo a scorrere la lista
            }
            else //se non è il primo elemento della lista
            {
                prev->next=it->next; //aggiorno il puntatore next dell'elemento precedente
                kfree(it); //libero l'elemento
                spin_lock(&lock_num_tcp_flows);
                slk_info->num_tcp_flows--; //diminuisce il numero dei flussi TCP presenti
                spin_unlock(&lock_num_tcp_flows);
                it=prev->next; //continuo a scorrere la lista
            }
        }
        else //se il timer non ha passato il valore di keepalive
        {
            prev=it; //aggiorno il valore di prev
            it=prev->next; //continuo a scorrere la lista
        }
    }
    spin_unlock(&lock_tcp_flow_list); //libera la risorsa tcp_flow_list
}

/************************************************************************************************************
 slk_udp_bdw_update()
 Calcola il valore della banda UDP passante nell'ultimo intervallo, il valore dell'intervallo è passato in ingresso. Aggiorna il valore di udp_avg_bdw anche in relazione a necessità dinamiche (evitare che i flussi TCP occupino tutta la rete)
 - dt: valore dell'intervallo passato in ingresso in ms
 ************************************************************************************************************/
static void slk_udp_bdw_update(long dt)
{
    unsigned long actual_udp_bdw=0; //variabile di supporto per il calcolo della bandwidth UDP attuale
    spin_lock(&lock_udp_traffic); // Riserva le risorse per il calcolo della nuova bandwidth UDP
    spin_lock(&lock_last_udp_traffic);
    //Calcolo della bandwidth UDP
    if (dt > 0)
    {
        actual_udp_bdw = (unsigned long)((slk_info->udp_traffic - slk_info->last_udp_traffic) * 1000UL) / dt; //Byte/s
    }
    // Modifica della banda UDP in base a necessità dinamiche
    if (slk_info->last_udp_traffic <= 0) //se è la prima volta che è modificato o se c'è stato poco traffico
    {
        slk_info->udp_avg_bdw = actual_udp_bdw;
    }
    else
    {
        slk_info->udp_avg_bdw = actual_udp_bdw + (int)(actual_udp_bdw / 10); //per gestire la casistica di flussi TCP già instanziati, aumenta la banda UDP del 10% in modo che se il TCP occupasse tutta la banda restante i flussi UDP riceverebbero un ammontare di banda aggiuntivo che nel caso gli occorra occuperanno aumentando anche la banda disponibile al prossimo ricalcolo.
    }
    slk_info->last_udp_traffic = slk_info->udp_traffic; //Aggiorno il valore di last_udp_traffic con quello attuale
    spin_unlock(&lock_last_udp_traffic); //Libero le risorse usate per il calcolo della banda UDP
    spin_unlock(&lock_udp_traffic);
}

/************************************************************************************************************
 slk_magic_formula()
 Calcola attraverso la formula il valore della advertised window (new_adv_wnd)
 ************************************************************************************************************/
static void slk_magic_formula(void)
{
    spin_lock(&lock_num_tcp_flows); //Riserva la risorsa num_tcp_flows
    write_lock(&rwlock_new_adv_wnd); //Riserva il scrittura la risorsa new_adv_wnd
    //Calcolo della Magic Formula della SAP-LAW
    if(slk_info->num_tcp_flows!=0) //se il numero dei flussi TCP è diverso da 0
    {
        slk_info->new_adv_wnd = ( slk_info->max_bwt - slk_info->udp_avg_bdw ) / slk_info->num_tcp_flows;
    }
    else
        slk_info->new_adv_wnd=0;
    if( slk_info->new_adv_wnd > 65535 ) //TCP advertised windows ha valori da 0 a 65535
        slk_info->new_adv_wnd = 65535;
    else
        if(slk_info->new_adv_wnd < 0 ) //Evita che la advertised windows sia un valore nullo
            slk_info->new_adv_wnd = (int)(slk_info->max_bwt / 20); //CONTROLLARE SE IL VALORE 20 è ADATTO
    write_unlock(&rwlock_new_adv_wnd); //Rilascia la risorsa new_adv_wnd
    spin_unlock(&lock_num_tcp_flows); //Rilascia la risorsa num_tcp_flows
}

/************************************************************************************************************
 log_loginfo()
 Crea ed invia il messaggio contenente i dati da salvare sul log attraverso il socket netlink
 ************************************************************************************************************/
static void log_loginfo(void)
{
    
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out; //Buffer messaggio di uscita
    int msg_size;
    int res;
    
    /*spin_lock(&lock_udp_traffic);
     spin_lock(&lock_last_udp_traffic);
     spin_lock(&lock_num_tcp_flows);
     spin_lock(&lock_udp_avg_bdw);
     read_lock(&rwlock_new_adv_wnd);
     spin_lock(&lock_last_check);
     spin_lock(&lock_tot_pkt_count);
     spin_lock(&lock_mod_pkt_count);
     read_lock(&rwlock_traffic_stat_timer);*/
    
    msg_size = sizeof(SLK_DATA); //Grandezza del messaggio
    skb_out = nlmsg_new(msg_size, 0); //Crea il messaggio
    if (!skb_out)
    {
        printk(KERN_ALERT "Failed to allocate new skb\n");
        return;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; //Messaggio unicast
    memcpy(nlmsg_data(nlh), slk_info, msg_size);
    
    /*read_unlock(&rwlock_traffic_stat_timer);
     spin_unlock(&lock_mod_pkt_count);
     spin_unlock(&lock_tot_pkt_count);
     spin_unlock(&lock_last_check);
     read_unlock(&rwlock_new_adv_wnd);
     spin_unlock(&lock_udp_avg_bdw);
     spin_unlock(&lock_num_tcp_flows);
     spin_unlock(&lock_last_udp_traffic);
     spin_unlock(&lock_udp_traffic);*/
    
    res = nlmsg_unicast(nl_sk, skb_out, pid); //Invia il messaggio nel socket
    if (res < 0)
        printk(KERN_ALERT "Error while sending to user \n");
}

/************************************************************************************************************
 hook_func()
 Funzione di hook da utilizzare nel Framework Netfilter. Viene richiamata ogni volta che un pacchetto arriva sull'hook specificato dal modulo. Gestisce l'analisi dei pacchetti in base al protocollo di trasporto. I pacchetti UDP li utilizza per il calcolo della banda passante UDP. I pacchet TCP modifca l'advertised window per ottenere un comportamento diverso del TCP nella rete. Esegue costanti aggiornamenti dei parametri che gestiscono i meccanismi precedentemente illustarti.
 ************************************************************************************************************/
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    
    //Strutture dati per la manipolazione dei pacchetti
    struct iphdr *ip  = NULL;
    struct udphdr *udp = NULL;
    
    int res; //variabile ausiliaria
    
    if (!skb)  //se non c'è nessun socket buffer
        return NF_DROP;
    
    res=slk_check_update_SL(); //aggiorna il contatore dei pacchetti e controlla se occorre aggiornare i parametri di gestione del traffico
#ifdef DEBUG //DEBUG
    printk(KERN_INFO "*****DEBUG***** tot_pkt_count: %d \n",slk_info->tot_pkt_count);
#endif
    
    ip=ip_hdr(skb); //prende l'header IP dal buffer skb
#ifdef DEBUG //DEBUG
    printk(KERN_INFO "*****DEBUG***** Header IP \t source: %pI4 \t destination: %pI4\t lenght:%u byte \n",&(ip->saddr),&(ip->daddr),ntohs(ip->tot_len)); //%pI4 permette la stampa dell'indirizzo in formato leggibile, occorre passargli il reference alla variabile
#endif
    
    switch (ip->protocol) //Controllo sul protocollo di trasporto
    {
        case 17: //UDP
            udp=udp_hdr(skb); //prende l'header UPD dal buffer skb
            slk_udp_handle(ip,udp);
#ifdef DEBUG //DEBUG
            printk(KERN_INFO "*****DEBUG***** Pacchetto UDP \t source:%u \t destination:%u \t lenght:%u byte\n",ntohs(udp->source),ntohs(udp->dest), ntohs(udp->len));
            printk(KERN_INFO "*****DEBUG***** udp_traffic: %d \n",slk_info->udp_traffic);
#endif
            break;
            
        case 6: //TCP
            slk_tcp_handle(ip,skb);
#ifdef DEBUG //DEBUG
            printk(KERN_INFO "*****DEBUG***** Pacchetto TCP \t source:%d \t destination:%d \n",ntohs(tcp->source),ntohs(tcp->dest));
            printk(KERN_INFO "*****DEBUG***** mod_pkt_count: %d \n",slk_info->mod_pkt_count);
#endif
            break;
            
        default:
            break;
    }
    
    if( (res == 0 || slk_info->tot_pkt_count == 1) && slk_info->const_adv_wnd < 0) //Occorre eseguire la SAP-LAW per aggiornare i parametri di esecuzione
    {
        struct timeval t;
        long dt; //Differenza temporale dall'ultimo check
        do_gettimeofday(&t); //prende l'ora attuale
        dt=slk_calc_df(t); //calcola la differenza temporale tra l'ultimo check e l'ora attuale aggiornando l'ultimo check
        slk_update_tst(dt); //aggiorna il valore di traffic_stat_timer in relazione a dt
        time_check_tcp_flows(t); //Controlla ed elimina eventuali flussi TCP scaduti o oltre soglia temporale
#ifdef DEBUG //DEBUG
        printk(KERN_INFO "*****DEBUG***** traffic_stat_timer: %d pkt \t dt : %ld ms \t num_tcp_flows: %d \n",slk_info->traffic_stat_timer,dt,slk_info->num_tcp_flows);
#endif
        
        spin_lock(&lock_udp_avg_bdw);   //Riserva la risorsa udp_avg_bdw
        slk_udp_bdw_update(dt); //aggiorna il valore della banda UDP passante al momento
        slk_magic_formula(); //Esegue il calcolo della dimensione della advertised window
        spin_unlock(&lock_udp_avg_bdw); //rilascio della risorsa udp_avg_bdw
#ifdef DEBUG //DEBUG
        printk(KERN_INFO "*****DEBUG***** udp_avg_bdw: %d \t new_adv_wnd : %d \n",slk_info->udp_avg_bdw,slk_info->new_adv_wnd);
#endif
        
#ifdef LOG
        read_lock(&rwlock_pid);
        if(pid!=-1) //Se è stato inizializzato il pid del processo di log invio messaggi di log
        {
            log_loginfo();
        }
        read_unlock(&rwlock_pid);
#endif
        
    }
    return NF_ACCEPT; //accetta tutti i pacchetti, possono continuare la loro transazione
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////Funzione di inizializzazione del modulo////////////////////////////////////

/************************************************************************************************************
 slk_init_hook()
 Definisce i valori della struttura dati che implementa l'hook
 ************************************************************************************************************/
static void slk_init_hook(void)
{
    nfho.hook = hook_func; //definisce la funzione da richiamare nell'hook
    nfho.hooknum =NF_INET_FORWARD ; //Indica in che punto del protocollo è in ascolto l'hook
    nfho.pf = PF_INET; //definisce la famiglia di protocolli da usare
    nfho.priority = NF_IP_PRI_FIRST; //indica la priorità dell'hook
    printk(KERN_INFO "Inizializzzione Kernel hook completata \n");
}

/************************************************************************************************************
 slk_init_data()
 Inizializza i dati necessari all'esecuzione del programma
 ************************************************************************************************************/
static void slk_init_data(void)
{
    slk_info=kmalloc(sizeof(SLK_DATA),GFP_KERNEL); //alloca la memoria per slk_info
    
    slk_info->max_bwt=1000*1024; //byte/s
    slk_info->last_udp_traffic = 0; //Valore del traffico UDP all'ultima lettura
    slk_info->udp_traffic = 0;  //traffico UDP
    slk_info->num_tcp_flows = 0;    //numero flussi TCP
    slk_info->udp_avg_bdw = 0;  //Bandwidht UDP
    slk_info->new_adv_wnd = 0;  //Advertised windows
    slk_info->const_adv_wnd = -1; //parametro contenente il valore della advertised windows se è impostato come fisso
    do_gettimeofday(&slk_info->last_check);   //inizializzazione timer
    slk_info->tot_pkt_count = 0; //contatore pacchetti
    slk_info->mod_pkt_count = 0;
    slk_info->traffic_stat_timer = 1; //Ogni quanti pacchetti eseguire la formula, modificato dinamicamente
    
    nl_sk=NULL;
    
    pid=-1;
    
    //Parametri in ingresso
    if(up_bwt>0)
        slk_info->max_bwt=up_bwt *1024; //Byte al secondo
    
    if(adv_wnd>0)
        slk_info->const_adv_wnd=adv_wnd; //Byte
    
    printk(KERN_INFO "Inizializzazione variabili completata \n");
}

/************************************************************************************************************
 slk_init_spinlock()
 Inizializza gli spinlock utilizzati nel programma
 ************************************************************************************************************/
static void slk_init_spinlock(void)
{
    spin_lock_init(&lock_udp_traffic);  //spinlock udp_traffic
    spin_lock_init(&lock_last_udp_traffic);  //spinlock last_udp_traffic
    spin_lock_init(&lock_num_tcp_flows); //spinlock num_tcp_flows
    spin_lock_init(&lock_udp_avg_bdw); //spinlock udp_avf_bdw
    rwlock_init(&rwlock_new_adv_wnd); //rw spinlock new_adv_wnd
    spin_lock_init(&lock_last_check); //spinlock last_check
    spin_lock_init(&lock_tot_pkt_count); //spinlock tot_pkt_count
    spin_lock_init(&lock_mod_pkt_count); //spinlock mod_pkt_count
    rwlock_init(&rwlock_traffic_stat_timer); //rw spinlock traffic_stat_timer
    spin_lock_init(&lock_tcp_flow_list); //spinlock tcp_flow_list
    rwlock_init(&rwlock_pid); // rw spinlock pid
    printk(KERN_INFO "Inizializzazione spinlock completata \n");
}

/************************************************************************************************************
 log_recv_msg()
 Inizializza il pid del processo che esegue il log di alcune informazioni del modulo
 ************************************************************************************************************/
static void log_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    
    nlh = (struct nlmsghdr *)skb->data; //Riceve il messaggio
#ifdef DEBUG
    printk(KERN_INFO "Messaggio da user-space :%s\n", (char *)nlmsg_data(nlh));
#endif
    write_lock(&rwlock_pid);
    if(pid==-1)
        pid = nlh->nlmsg_pid; // Pid del processo che ha inviato il messaggio, inizializzazione completata
    else
        pid=-1; //terminazione salvataggio sul log
    write_unlock(&rwlock_pid);
}

/************************************************************************************************************
 mod_init()
 Inizializza il programma richiamando le varie funzioni di inizializzazione e registrando l'hook in ascolto e il socket di comunicazione con il processo di log nell'user space
 ************************************************************************************************************/
static int __init mod_init(void)
{
#ifdef LOG
    //Struttura necessaria per la creazione del socket
    struct netlink_kernel_cfg cfg = {
        .input = log_recv_msg,
    };
#endif
    
    
    printk(KERN_INFO "Inizializzazione modulo SLK: SAP-LAW KERNEL \n");
    
    slk_init_hook();    //Definisce i valori della struttura dati che implementa l'hook
    slk_init_data();    //inizializzazione delle variabili del programma
    slk_init_spinlock();    //Inizializzazione semafori e spinlock
    
#ifdef LOG
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg); //Crea il socket netlink
    if (!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }
#endif
    
    nf_register_hook(&nfho); //registra in ascolto l'hook
    
    printk(KERN_INFO "Inizializzazione SLK completata, modulo caricato correttamente \n");
    printk(KERN_INFO "max_bwt= %d , const_adv_wnd= %d  \n",slk_info->max_bwt, slk_info->const_adv_wnd );
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////Funzione di terminazione del modulo, ///////////////////////////////////////////

/************************************************************************************************************
 free_TCP_flow_list()
 Libera la lista utilizzata per salvare l'informazione relativa ai flussi TCP attivi, la funzione è ricorsiva, ogni volta libera la memoria relativa all'elemento passato in ingresso. La chiamata ricorsiva continua fino a trovare l'ultimo elemento, da quello le chiamate ritornano indietro liberando tutta la lista
 - list_elem: elemento passato in ingresso che sarà liberato in questa chiamata
 ************************************************************************************************************/
TCPid_t* free_TCP_flow_list(TCPid_t* list_elem)
{
    if(list_elem==NULL)
        return NULL;
    list_elem->next=free_TCP_flow_list(list_elem->next);
    kfree(list_elem);
    return NULL;
}

/************************************************************************************************************
 mod_exit()
 Libera le strutture dati utilizzate dal modulo e rilascia hook e socket. Termina quindi l'esecuzione del modulo
 ************************************************************************************************************/
static void __exit mod_exit(void)
{
    free_TCP_flow_list(tcp_flow_list); //Libera la memoria utilizzata per la gestione della lista dei flussi TCP attivi
    
    nf_unregister_hook(&nfho); //rilascia l'hook
    netlink_kernel_release(nl_sk); //Rilascia il socket
    printk(KERN_INFO "Totale pacchetti ricevuti: %d\n", slk_info->tot_pkt_count );
    printk(KERN_INFO "Totale traffico UDP(): %d byte\n",slk_info->udp_traffic);
    printk(KERN_INFO "Totale pacchetti modificati : %d \n", slk_info->mod_pkt_count);
    printk(KERN_INFO "Rimozione del modulo SKL: SAP-LAW KERNEL \n");
    
    kfree(slk_info); //libera la memoria allocata per slk_info
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);

//Definiscono delle informazioni riguardati in modulo
MODULE_AUTHOR("Giacomo Pandini");
MODULE_DESCRIPTION("SLK, Sap-Law Kernel");
MODULE_LICENSE("GPL");

