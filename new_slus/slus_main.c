/*
 *	slus_main.c: main source of the SAP-LAW user space application.
 *				 It house the main structure of the application:
 *				 	- application initializer
 *				 	- queue handler
 *				 	- program exit
 *
 *	<2009, Matteo Brunati, saplaw@matteobrunati.net>
 *
 *	This file is published under the GNU GPL version 3 license, or any later
 *	version.
 *
 *	TODO: inserisci note agiuntive
 *
 */

// TODO: per codici di ritorno inserisci macro BEGIN, END, ecc.
// TODO: gestisci iptables lanciando comandi dal main
// TODO: scelta della gestione di iptables da parametro command line

// #define SLUS_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>							// For NF_ACCEPT
#include <getopt.h>										// For getopt()
#include <ctype.h>										// For isprint()
#include <time.h>										// For ctime()
#include <string.h>										// For memset()
#include <sys/time.h>									// For gettimeofday()
//#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "slus.h"

////////////////////////////////////////////////////////////////////////////////////
/*
 * Calculate the checksum of a buffer of data.
 * This function is taken from sendip program. Thanks to its author for the
 * open source code.
 */
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

////////////////////////////////////////////////////////////////////////////////////
/*
 * Calculate and set TCP header checksum.
 * Part of code is taken from NETWIB - Network library by Laurent Constantin.
 */
static int slus_reset_chksum(const slus_byte *pktHdr, const int len) {
    struct iphdr *p_iphdr = (struct iphdr *)pktHdr;
    struct tcphdr *p_tcphdr = (struct tcphdr *)(pktHdr + sizeof(struct iphdr));
    
    slus_byte *buf = NULL;
    u_int16_t tcp_tot_len = len - 20;		// The IP header is 20 bytes long
    
    buf = malloc(len);
    if (buf == NULL) {
        fprintf(stderr, "ERROR: cannot allocate memory\n");
        return EXIT_FAILURE;
    }
    (void *)memset(buf, 0, len);
    
    /* Pseudo header initialization */
    (void *)memcpy(buf, &(p_iphdr->saddr), sizeof(u_int32_t));	// Pseudo header src address
    (void *)memcpy(&(buf[4]), &(p_iphdr->daddr), sizeof(u_int32_t));	// Pseudo header dst address
    buf[8] = 0;							// Pseudo header reserved location
    buf[9] = p_iphdr->protocol;			// Pseudo header protocol version (6 for TCP)
    buf[10]=(u_int16_t)((tcp_tot_len) & 0xFF00) >> 8;	// Pseudo header total TCP length (left byte)
    buf[11]=(u_int16_t)((tcp_tot_len) & 0x00FF);		// Pseudo header total TCP length (rigth byte)
    
    // TCP packet initialization
    p_tcphdr->check = 0;
    
    (void *)memcpy(buf + 12, p_tcphdr, tcp_tot_len);
    p_tcphdr->check = slus_calc_chksum_buf((u_int16_t *)buf, 12 + tcp_tot_len);
    if (buf != NULL) free(buf);
    
    return EXIT_SUCCESS;
}
////////////////////////////////////////////////////////////////////////////////////

static void search_TCP_flow(u_int32_t ipsource, u_int32_t ipdest, u_int16_t tcpsource, u_int16_t tcpdest)
{
    int iterate=1; //Variabile utilizzata per continuare o fermare il ciclo while
    TCPid_t* it;
    TCPid_t* nxt;
    
    if(tcp_flow_list==NULL) //se la lista è vuota inserisce in testa
    {
        //crea il nuovo elemento
        tcp_flow_list=(TCPid_t *)malloc(sizeof(TCPid_t));
        tcp_flow_list->ipsource=ipsource;
        tcp_flow_list->ipdest=ipdest;
        tcp_flow_list->tcpsource=tcpsource;
        tcp_flow_list->tcpdest=tcpdest;
        gettimeofday(&tcp_flow_list->timer,NULL);
        tcp_flow_list->next=NULL;
        iterate=0;
        slus_info->num_tcp_flows++; //aumenta il numero dei flussi TCP presenti
    }
    it=tcp_flow_list;
    while(iterate) //se non è vuota cerca l'elemento nella lista
    {
        if(ipsource==it->ipsource && ipdest==it->ipdest && tcpsource==it->tcpsource && tcpdest==it->tcpdest )
        { //se lo trova aggiorna il valore di timer
            gettimeofday(&it->timer,NULL); //percorso diretto
            iterate=0;
        }
        if(ipsource==it->ipdest && ipdest==it->ipsource && tcpsource==it->tcpdest && tcpdest==it->tcpsource)
        { //se lo trova aggiorna il valore di timer
            gettimeofday(&it->timer,NULL); //percorso inverso
            iterate=0;
        }
        if(it->next==0)//Se non lo trova lo aggiunge al termine della lista
        {
            //crea il nuovo elemento
            nxt=(TCPid_t *)malloc(sizeof(TCPid_t));
            nxt->ipsource=ipsource;
            nxt->ipdest=ipdest;
            nxt->tcpsource=tcpsource;
            nxt->tcpdest=tcpdest;
            gettimeofday(&nxt->timer,NULL);
            nxt->next=NULL;
            it->next=nxt;
            iterate=0;
            slus_info->num_tcp_flows++; //aumenta il numero dei flussi TCP presenti
        }
        it=it->next; //elemento successivo
    }
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Modifies packet's TCP window with new calculated advertised window. Returns packet id.
 */
static int slus_mod_tcp_pktHdr(slus_byte *pktHdr, const int length, u_int32_t ipsource, u_int32_t ipdest) {
    struct tcphdr *p_tcphdr = (struct tcphdr *)(pktHdr + sizeof(struct iphdr));
    
    if ((slus_stat->tot_pkt_count % slus_stat->traffic_stat_timer) == 0 ||
        (slus_stat->tot_pkt_count == 1)) {	// ##### DEBUG ######
        //		dbg_printf("SYN%i\tACK%i\tFIN%i\tRST%i\tURG%i\tPSH%i\to_wnd=%i ",
        //				p_tcphdr->syn, p_tcphdr->ack, p_tcphdr->fin, p_tcphdr->rst,
        //				p_tcphdr->urg, p_tcphdr->psh, p_tcphdr->window);
        dbg_printf("ack_num=%u\tsrc_port=%u\tdst_port=%u\to_chk=%u\to_wnd=%u\t",
                   ntohl(p_tcphdr->ack_seq),
                   ntohs(p_tcphdr->source),
                   ntohs(p_tcphdr->dest),
                   ntohs(p_tcphdr->check),
                   ntohs(p_tcphdr->window));
        //		p_tcphdr->window = (u_int16_t)65535;
        //		p_tcphdr->window = (u_int16_t)0;
        //		dbg_printf("n_wnd=%i\n", p_tcphdr->window);
    }
    
    if (slus_info->const_adv_wnd < 0) {
        ///*****
        search_TCP_flow(ntohs(ipsource), ntohs(ipdest), ntohs(p_tcphdr->source), ntohs(p_tcphdr->dest));
        ///*****
        if (ntohs(p_tcphdr->window) > (u_int16_t)slus_info->new_adv_wnd) {
            p_tcphdr->window = htons((u_int16_t)slus_info->new_adv_wnd);
        }
    }
    else {
        p_tcphdr->window = htons((u_int16_t)slus_info->const_adv_wnd);
    }
    //	dbg_printf("\tset wnd: %5u\n", p_tcphdr->window);
    
    // Recalculate and set the new header checksum
    if (slus_reset_chksum(pktHdr, length)) {
        fprintf(stderr, "ERROR: something went wrong calculating TCP packet's checksum\n");
        return EXIT_FAILURE;
    }
    if ((slus_stat->tot_pkt_count % slus_stat->traffic_stat_timer) == 0 ||
        (slus_stat->tot_pkt_count == 1)) {	// ##### DEBUG ######
        dbg_printf("n_chk=%u\tn_wnd=%u\n", ntohs(p_tcphdr->check), ntohs(p_tcphdr->window));
    }
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 *  Call back function, used every time a packet is read from the queue
 */
static int slus_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data) {
    
    int id = 0, len = 0;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    slus_byte *pktHdr = NULL;
    struct iphdr *p_iphdr = NULL;
    struct tcphdr *p_tcphdr = NULL;
    
    // Retrieves packet's id
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    else {
        fprintf(stderr, "ERROR: Can't read packet's netfilter header");
        return EXIT_FAILURE;
    }
    
    // Retrieves packet's TCP header
    len = nfq_get_payload(nfa, (char **)&pktHdr);
    if (len < 0) {
        fprintf(stderr, "ERROR: Can't retrieve packet's %i informations\n", id);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);;
    }
    
    p_iphdr = (struct iphdr *)pktHdr;
    
    switch (p_iphdr->protocol) {
        case 6:		// TCP packet
            // Retrieve traffic informations for the formula calculation
            //		slus_info->tcp_traffic += (len - 20); /* 20 byte of the packet length are for the IP header. */
            p_tcphdr = (struct tcphdr *)(pktHdr + sizeof(struct iphdr));  // ##### DEBUG
            if (slus_mod_tcp_pktHdr(pktHdr, len, p_iphdr->saddr,p_iphdr->daddr)) {
                //		if ((p_tcphdr->ack != 0) && slus_mod_tcp_pktHdr(pktHdr, len)) {  // ##### DEBUG
                fprintf(stderr, "ERROR: something went wrong modifying TCP packet"
                        " header\n");
                return EXIT_FAILURE;
            }
            slus_stat->mod_pkt_count++;
            break;
        case 17:	// UDP packet
            // Retrieve traffic informations: len includes UDP data & header and IP
            // header, 14 is the Ethernet header length
            slus_info->udp_traffic += (len + 14); // Packet length includes 20 byte of IP header.
            break;
        default:
            fprintf(stderr, "ERROR: cannot handle packets which are not TCP or UDP\n");
            break;
    }
    
    //	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)len, pktHdr);
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Print command line program usage
 */
static void slus_print_usage(const char *prg_name) {
    printf("\nSAP-LAWus: Smart Access Point with Limited Advertised Window user"
           "space solution\n"
           "Version: %s\n\n"
           "Usage: %s [OPTIONS]\n"
           "OPTIONS are:\n"
           //			"\t-c file_name\t\t Use a config file different from"
           "\t[-a adv_wnd]||[-b bandwidth]\n"
           "\t\t The first parameter sets the advertised windows to adv_wnd constant value.\n"
           "\t\t The second parameter set the maximum bandwith available for the\n"
           "\t\t magic formula calculation (the bandwidth is in KByte/s)\n"
           "\t[-s stat_length]\t\t Define the length of packets statistics buffer,"
           "so it defines also every how many packets statistics are written."
           " Default is %u\n"
           "\t[-f stat_file]\t\t Define statistics' log file name. Default is '%s'\n"
           "\t[-d]\t\t\t Daemonize SAP-LAWus\n"
           "\t[-h]\t\t\t Print this help\n\n"
           "SAP-LAW user space has been developped for a Laurea Degree Thesis by Matteo "
           "Brunati,\nfrom the original studies of Prof. Claudio E. Palazzi.\n",
           prg_name, SLUS_VERSION, SLUS_STAT_LENGTH, SLUS_STAT_FILE_NAME);
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Parse command line parameters input
 */
static int slus_parse_input(int argc, char **argv) {
    int opt = 0,
    bdw_ok = 0;
    
    while ((opt = getopt(argc, argv, "c:a:b:s:f:dh")) != -1) {
        switch (opt) {
            case 'c':
                slus_info->conf_file = optarg;
                break;
            case 'a':
                slus_info->const_adv_wnd = atoi(optarg);
                bdw_ok++;
                break;
            case 'b':
                slus_info->max_bwt = atoi(optarg) * 1024;
                bdw_ok++;
                break;
            case 's':
                slus_stat->stat_length = atoi(optarg);
                break;
            case 'f':
                slus_stat->stat_file_name = optarg;
                break;
            case 'd':
                slus_info->daemon = 1;
                break;
            case 'h':
                slus_print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            case '?':
                if (optopt == 'c') {
                    fprintf (stderr, "ERROR: Option -%c requires an argument.\n",
                             optopt);
                }
                else {
                    if (isprint (optopt)) {
                        fprintf (stderr, "ERROR: Unknown option `-%c'.\n", optopt);
                    }
                    else {
                        fprintf (stderr, "ERROR: Unknown option character `\\x%x'.\n",
                                 optopt);
                    }
                }
                slus_print_usage(argv[0]);
                return EXIT_FAILURE;
            default: /* '?' */
                slus_print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    if (bdw_ok != 1) {
        fprintf(stderr, "ERROR: bandwidth parameter or advertised window value needed.\n");
        slus_print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Return the input date without \n in the end
 */
static char *slus_trunc_date(const char *date) {
    size_t len = 0;
    char *ret_date = NULL;
    
    len = sizeof(char) * (strlen(date) - 1);
    ret_date = malloc(len);
    if (ret_date == NULL) {
        fprintf(stderr, "ERROR: cannot allocate memory\n");
        return NULL;
    }
    (void *)memccpy(ret_date, date, '\n', len);
    
    return ret_date;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Write packets statistics to file
 */
static int slus_write_stats() {
    FILE *stat_file_handle = NULL;
    time_t tmp_time = 0;
    
    stat_file_handle = fopen(slus_stat->stat_file_name, "a");  // Open in append mode
    if (stat_file_handle == NULL) {
        fprintf(stderr, "ERROR: Can't open statistics' file\n");
        return EXIT_FAILURE;
    }
    
    tmp_time = time(NULL);
    fprintf(stat_file_handle, "[%s]\t%d\t%d\t%d\t%d\t%d\n",
            slus_trunc_date(ctime(&tmp_time)),
            slus_stat->tot_pkt_count,
            slus_stat->mod_pkt_count,
            slus_stat->chksum_err_count,
            slus_info->num_tcp_flows,
            slus_info->udp_traffic);
    
    if ((stat_file_handle != NULL) && fclose(stat_file_handle)) {
        fprintf(stderr, "ERROR: Can't close statistics' file\n");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Get the TCP flows number and set it for the formula calculation
 */
static int slus_set_tcp_flows_num(struct timeval t)
{
    long dt = 0, dts = 0, dtm = 0; //variabili di supporto per il calcolo del passare del tempo
    TCPid_t* it;
    TCPid_t* prev;
    it=tcp_flow_list; //puntatori utilizzati per scorrere la lista dei flussi TCP
    prev=NULL;
    
    while(it!=NULL) //Elimino i flussi TCP che hanno passato il timeout keepalive
    {
        //Calcolo differenza temporale tra il valore attuale e il valore di timer dell'elemento analizzato
        dts = ((t.tv_sec - it->timer.tv_sec) * 1000 ); //converto in millisecondi
        dtm = ((t.tv_usec - it->timer.tv_usec) / 1000); //1000 poiché salvato in microsecondi e voglio millisecondi
        dt = dts + dtm; //dt è in millisecondi
        if(dt>SLUS_TCP_KEEPALIVE_TIMER) //se il timer ha passato il valore di keepalive
        {
            if(prev==NULL) // se è il primo elemento della lista
            {
                tcp_flow_list=tcp_flow_list->next; //sposto il puntatore della testa della lista
                free(it); //libero l'elemento
                slus_info->num_tcp_flows--; //diminuisce il numero dei flussi TCP presenti
                it=tcp_flow_list; //continuo a scorrere la lista
            }
            else //se non è il primo elemento della lista
            {
                prev->next=it->next; //aggiorno il puntatore next dell'elemento precedente
                free(it); //libero l'elemento
                slus_info->num_tcp_flows--; //diminuisce il numero dei flussi TCP presenti
                it=prev->next; //continuo a scorrere la lista
            }
        }
        else //se il timer non ha passato il valore di keepalive
        {
            prev=it; //aggiorno il valore di prev
            it=prev->next; //continuo a scorrere la lista
        }
    }
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Calculate the actual UDP average bandwidth in Kbyte/s and set it accordingly
 * to the dynamic needs
 */
static int slus_calc_udp_bdw() {
    unsigned long actual_udp_bdw = 0;
    struct timeval t;
    long dt = 0, dts = 0, dtm = 0;
    
    if (gettimeofday(&t, NULL)) {
        fprintf(stderr, "ERROR: cannot retrieve time.\n");
        return EXIT_FAILURE;
    }
    dts = ((t.tv_sec - slus_info->last_check.tv_sec) * 1000 );
    dtm = ((t.tv_usec - slus_info->last_check.tv_usec) / 1000);
    dt = dts + dtm;		// dt is in milliseconds
    //	dbg_printf("dt = %6i\t", dt);
    
    // The bandwidth is kept in byte
    if (dt > 0) {
        actual_udp_bdw = (unsigned long)((slus_info->udp_traffic - slus_info->last_udp_traffic) * 1000UL) / dt;
    }
    
    // Modify UDP bandwidth based on dynamic needs.
    if (slus_info->last_udp_traffic <= 0) { // For the first time or when there was few traffic
        slus_info->udp_avg_bdw = actual_udp_bdw;
    }
    else {
        slus_info->udp_avg_bdw = actual_udp_bdw + (int)(actual_udp_bdw / 10);
        //		slus_info->udp_avg_bdw = actual_udp_bdw;
    }
    
    
    // Set next traffic statistics calculation timer
    if ((dt > SLUS_TRAFFIC_STAT_TIMER_UP) && (slus_stat->traffic_stat_timer > 1)) {	// Too much time since the last calculation
        slus_stat->traffic_stat_timer >>= 1;	// Divide by 2
    }
    else if (dt < SLUS_TRAFFIC_STAT_TIMER_DOWN) {	// Not enough time since the last calculation
        slus_stat->traffic_stat_timer <<= 1;	// Multiply by 2
    }
    
    dbg_printf("next pkt count timer = %i\t", slus_stat->traffic_stat_timer);
    dbg_printf("calc UDP bdw: %lu\t", actual_udp_bdw);
    //	dbg_printf("dUDP dbw: %i\t", db);
    dbg_printf("now UDP avg bdw: %i(Byte/s)\t", slus_info->udp_avg_bdw);
    
    slus_info->last_check.tv_sec = t.tv_sec;
    slus_info->last_check.tv_usec = t.tv_usec;
    slus_info->last_udp_traffic = slus_info->udp_traffic;
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Init iptables with SAP-LAW rules chains
 */
static int slus_init_iptables() {
    //	char *cmd_tcp = "iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -p tcp -m tcp --tcp-flags ALL ACK -j NFQUEUE --queue-num 2 && "
    //					"iptables -t mangle -I INPUT 1 -p tcp -m tcp --tcp-flags ALL ACK -j NFQUEUE --queue-num 2",
#if !defined(OPENWRT)	// Modify when NFQUEUE support in OpenWRT
    char *cmd_init_iptables = "iptables -t mangle -F && "
    "iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -p tcp --tcp-flags ALL ACK -j NFQUEUE --queue-num 2 && "
    "iptables -t mangle -I INPUT 1 -p tcp -m tcp --tcp-flags ALL ACK -j NFQUEUE --queue-num 2 && "
    "iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -p udp -j NFQUEUE --queue-num 2";
#else
    // The iptables bin path is needed in order to execute SAP-LAW correctly from
    // a remote ssh connection (done for the testbed)
    /*char *cmd_init_iptables = "/usr/sbin/iptables -t mangle -F && "
    "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -p tcp --tcp-flags ALL ACK -j QUEUE && "
    "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -p udp -j QUEUE";*/
    char *cmd_init_iptables = "/usr/sbin/iptables -t mangle -F && "
     "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -p tcp --tcp-flags ALL ACK -j NFQUEUE --queue-num 2 && "
     "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -p udp -j NFQUEUE --queue-num 2";
#endif
    
    if (system(cmd_init_iptables) < 0) {
        fprintf(stderr, "ERROR: cannot init iptables with command: %s\n", cmd_init_iptables);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Flush iptables from SAP-LAW rules chains
 */
static int slus_flush_iptables() {
    char *cmd_flush_chain = "iptables -t mangle -F";
    
    if (system(cmd_flush_chain) < 0) {
        fprintf(stderr, "ERROR: cannot flush iptables with command: %s\n",
                cmd_flush_chain);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Init slus data structures
 */
static int slus_init_struct() {
    slus_info = NULL;
    slus_info = (SLUS_DATA *) malloc(sizeof(SLUS_DATA));
    if (slus_info == NULL) {
        fprintf(stderr, "ERROR: cannot allocate memory\n");
        return EXIT_FAILURE;
    }
    slus_info = memset(slus_info, 0, sizeof(SLUS_DATA));
    if (gettimeofday(&(slus_info->last_check), NULL) != 0) {
        fprintf(stderr, "ERROR: cannot get time\n");
        return EXIT_FAILURE;
    }
    slus_info->const_adv_wnd = -1;
    
    slus_stat = NULL;
    slus_stat = malloc(sizeof(SLUS_STAT));
    if (slus_stat == NULL) {
        fprintf(stderr, "ERROR: cannot allocate memory\n");
        return EXIT_FAILURE;
    }
    slus_stat = memset(slus_stat, 0, sizeof(SLUS_STAT));
    slus_stat->stat_length = SLUS_STAT_LENGTH;
    slus_stat->stat_file_name = SLUS_STAT_FILE_NAME;
    slus_stat->traffic_stat_timer = 1;	// Will be adjusted by adaptive algorithm
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * linbetfilter_queue setup
 */
static int slus_setup_lib(struct nfq_handle **h) {
    dbg_printf("Opening library handle\n");
    *h = nfq_open();
    if (!(*h)) {
        fprintf(stderr, "ERROR: Error during nfq_open()\n");
        return EXIT_FAILURE;
    }
    dbg_printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(*h, AF_INET) < 0) {
        fprintf(stderr, "ERROR: Error during nfq_unbind_pf()\n");
        return EXIT_FAILURE;
    }
    dbg_printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(*h, AF_INET) < 0) {
        fprintf(stderr, "ERROR: Error during nfq_bind_pf()\n");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Queue handling
 */
static int slus_init_queue(struct nfq_handle *h, struct nfq_q_handle **qh) {
    dbg_printf("Binding this socket to queue %d\n", SLUS_QUEUE_NUM);
    *qh = nfq_create_queue(h, SLUS_QUEUE_NUM, &slus_cb, NULL);
    if (!(*qh)) {
        fprintf(stderr, "ERROR: Error during nfq_create_queue()\n");
        return EXIT_FAILURE;
    }
#if defined(OPENWRT)
    if (nfq_set_queue_maxlen(*qh, SLUS_PKT_QUEUE_LEN)) {
        fprintf(stderr, "ERROR: Can't set packets queue length\n");
        return EXIT_FAILURE;
    }
#endif
    // Setting to NFQNL_COPY_META will copy only packet's header,
    // NFQNL_COPY_PACKET will copy all the packet
    dbg_printf("Setting copy_packet mode\n");
    if (nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "ERROR: Can't set packet_copy mode\n");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Handle packets
 */
static int slus_handle_pkts(struct nfq_handle *h) {
    int fd = 0,
    rv = 0;
    
#if !defined(OPENWRT)
    char buf[4096] __attribute__ ((aligned));
#else
    char buf[SLUS_PKT_QUEUE_LEN] __attribute__ ((aligned));
#endif
    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        slus_stat->tot_pkt_count++;
        // Retrieve traffic informations for the formula calculation, if needed
        if ((slus_info->const_adv_wnd < 0) &&
            ((slus_stat->tot_pkt_count % slus_stat->traffic_stat_timer) == 0 || (slus_stat->tot_pkt_count == 1)))
        {
            struct timeval t;
            gettimeofday(&t,NULL); //prende l'ora attuale
            if (slus_set_tcp_flows_num(t)) {
                fprintf(stderr, "ERROR: something went wrong reading TCP flows'"
                        " statistics\n");
            }
            if (slus_calc_udp_bdw()) {
                fprintf(stderr, "ERROR: Can't set UDP average Bandwidth\n");
            }
            // Magic formula: advWnd = ((maxBdw - UDPtraffic) / numTCPFlows)
            if(slus_info->num_tcp_flows!=0)
            {
                slus_info->new_adv_wnd = (slus_info->max_bwt - slus_info->udp_avg_bdw) / slus_info->num_tcp_flows;
                dbg_printf("(%i - %i) / %i = %i\n",
                           slus_info->max_bwt, slus_info->udp_avg_bdw, slus_info->num_tcp_flows, slus_info->new_adv_wnd);
            }
            else
                slus_info->new_adv_wnd=0;
            if (slus_info->new_adv_wnd > 65535) {
                // The TCP window parameter is from 0 to 65535
                slus_info->new_adv_wnd = 65535;
            }
            else {
                if (slus_info->new_adv_wnd < 0) {
                    // The TCP window parameter is from 0 to 65535
                    slus_info->new_adv_wnd = (int)(slus_info->max_bwt / 20);
                }
            }
        }
        
        if (nfq_handle_packet(h, buf, rv)) {
            fprintf(stderr, "ERROR: Can't handle packet %d\n",
                    slus_stat->tot_pkt_count);
        }
        /*
         else {
         slus_stat->mod_pkt_count++;
         }
         */
        
        // Write statistics when packets' number is multiple of stat->stat_buffer_length
        // TODO: vedi se fare un thread
        if ((slus_stat->tot_pkt_count % slus_stat->stat_length) == 0) {
            slus_write_stats();
        }
    }
    perror("Stopped reading queue with error");
    
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * Exit in a correct way
 */
static int slus_prepare_exit(struct nfq_handle **h, struct nfq_q_handle **qh) {
    slus_write_stats();
    
    dbg_printf("Unbinding from queue\n");
    nfq_destroy_queue(*qh);
    dbg_printf("Closing library handle\n");
    nfq_close(*h);
    if (slus_flush_iptables()) {
        fprintf(stderr, "ERROR: cannot flush iptables\n");
        return EXIT_FAILURE;
    }
    if (slus_info != NULL) free(slus_info);
    if (slus_stat != NULL) free(slus_stat);
    
    dbg_printf("Bye bye!\n");
    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////
/*
 * SAP-LAW user space - Main function
 */
int main(int argc, char **argv) {
    struct nfq_handle *h = NULL;
    struct nfq_q_handle *qh = NULL;
    pid_t pid = 0;
    
    //	printf("sizeof(iphdr) = %i", sizeof(struct iphdr));
    //	exit(EXIT_SUCCESS);
    
    if (slus_init_struct()) {
        fprintf(stderr, "ERROR: cannot init internal data structures\n");
        exit(EXIT_FAILURE);
    }
    if (slus_parse_input(argc, argv)) {
        fprintf(stderr, "ERROR: incorrect input parameters\n");
        exit(EXIT_FAILURE);
    }
    if (slus_init_iptables()) {
        fprintf(stderr, "ERROR: cannot init iptables\n");
        exit(EXIT_FAILURE);
    }
    if (slus_setup_lib(&h)) {
        fprintf(stderr, "ERROR: cannot setup libnetiflter_queue\n");
        exit(EXIT_FAILURE);
    }
    if (slus_init_queue(h, &qh)) {
        fprintf(stderr, "ERROR: cannot init netfilter userspace queue\n");
        exit(EXIT_FAILURE);
    }
    
    if (slus_info->daemon > 0) {
        pid = fork();
        if (pid == 0) {
            if (slus_handle_pkts(h)) {
                fprintf(stderr, "ERROR: error handling packets\n");
                exit(EXIT_FAILURE);
            }
        }
        else {
            printf("\nSAP-LAW process pid: %u\n", pid);
            exit(EXIT_SUCCESS);
        }
    }
    else {
        if (slus_handle_pkts(h)) {
            fprintf(stderr, "ERROR: error handling packets\n");
            exit(EXIT_FAILURE);
        }
    }
    
    if (slus_prepare_exit(&h, &qh)) {
        fprintf(stderr, "ERROR: cannot exit in a good way\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
