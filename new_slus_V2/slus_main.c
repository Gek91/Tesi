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
 */

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
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "slus.h"

/************************************************************************************************************
 slus_calc_chksum_buf()
 Calculate the checksum of a buffer of data.
 - packet : packet buffer
 - packlen : packet lenght in byte
 ************************************************************************************************************/
static u_int16_t slus_calc_chksum_buf(u_int16_t *packet, int packlen)
{
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

/************************************************************************************************************
 slus_reset_chksum()
 Calculate and set TCP header checksum.
 - pktHdr: pointer to TCP packet header
 - len: packet lenght in byte
 ************************************************************************************************************/
static int slus_reset_chksum(const slus_byte *pktHdr, const int len)
{
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

/*************************************************************************************************************
 search_TCP_flow()
 Check if flow passed at the function, identify with 4 value, is already in the list of the active TCP flows. If it isn't add it and update the active TCP counter. Return the head of the list
 - num_tcp_flows : active TCP counter
 - tcp_flow_list : linked list on which the search is made
 - ipsource: IP source address of the flow
 - ipdest: IP destination address of the flow
 - tcpsource: source port of the flow
 - tcpdest: destination port of the flow
 *************************************************************************************************************/
static TCPid_t* search_TCP_flow(TCPid_t *tcp_flow_list, int *num_tcp_flows,u_int32_t ipsource, u_int32_t ipdest, u_int16_t tcpsource, u_int16_t tcpdest)
{
    TCPid_t* it;
    TCPid_t* nxt;
    
    if(tcp_flow_list==NULL) //if the list is empty, inserts the head
    {
        //Creates a new element of the list
        tcp_flow_list=(TCPid_t *)malloc(sizeof(TCPid_t));
        tcp_flow_list->ipsource=ipsource;
        tcp_flow_list->ipdest=ipdest;
        tcp_flow_list->tcpsource=tcpsource;
        tcp_flow_list->tcpdest=tcpdest;
        gettimeofday(&tcp_flow_list->timer,NULL);
        tcp_flow_list->next=NULL;
        (*num_tcp_flows)++; //update the TCP flows counter
        return tcp_flow_list;
    }
    it=tcp_flow_list;
    while(1) //if the list is not empty, search the element
    {
        //If the flow is in the list update his keepalive timer
        if(ipsource==it->ipsource && ipdest==it->ipdest && tcpsource==it->tcpsource && tcpdest==it->tcpdest )
        {
            gettimeofday(&it->timer,NULL);
            return tcp_flow_list;
        }
        if(ipsource==it->ipdest && ipdest==it->ipsource && tcpsource==it->tcpdest && tcpdest==it->tcpsource)
        {
            gettimeofday(&it->timer,NULL);
            return tcp_flow_list;
        }
        // if the flow is not in the list, adds it to the list creating a new element
        if(it->next==0)
        {
            nxt=(TCPid_t *)malloc(sizeof(TCPid_t));
            nxt->ipsource=ipsource;
            nxt->ipdest=ipdest;
            nxt->tcpsource=tcpsource;
            nxt->tcpdest=tcpdest;
            gettimeofday(&nxt->timer,NULL);
            nxt->next=NULL;
            it->next=nxt;
            (*num_tcp_flows)++; //update the TCP flows counter
            return tcp_flow_list;
        }
        it=it->next; //next element
    }
}

/************************************************************************************************************
 slus_mod_tcp_pktHdr()
 Modifies packet's TCP window with new calculated advertised window.
 - tcp_flow_list : linked list containing the active TCP flows
 - num_tcp_flows : actual TCP flows counter
 - adv_wnd : other interface new_adv_wnd
 - const_adv_wnd : constant advertised windows value, if <0 not used
 - pktHdr : pointer to packet header
 - length : packet lenght in byte
 - ipsource : IP source address of the flow
 - ipdest : IP destination address of the flow
 ************************************************************************************************************/
static TCPid_t* slus_mod_tcp_pktHdr(TCPid_t *tcp_flow_list ,int* num_tcp_flows,int* adv_wnd, int* const_adv_wnd, slus_byte *pktHdr, const int length, u_int32_t ipsource, u_int32_t ipdest)
{
    struct tcphdr *p_tcphdr = (struct tcphdr *)(pktHdr + sizeof(struct iphdr)); //takes TCP header
    
    if (*const_adv_wnd < 0) // if a constant value for the advertised window is not used
    {
        tcp_flow_list=search_TCP_flow(tcp_flow_list,num_tcp_flows ,ntohs(ipsource), ntohs(ipdest), ntohs(p_tcphdr->source), ntohs(p_tcphdr->dest)); //Check if the flow is already in the list, if it isn't add it
        if (ntohs(p_tcphdr->window) > (u_int16_t)(*adv_wnd)) // Use the lower value for the advertised window
        {
            p_tcphdr->window = htons((u_int16_t)(*adv_wnd));
        }
    }
    else // If a constant value for the advertised windows is used
    {
        p_tcphdr->window = htons((u_int16_t)(*const_adv_wnd));
    }
    
    // Recalculate and set the new header checksum
    if (slus_reset_chksum(pktHdr, length))
    {
        fprintf(stderr, "ERROR: something went wrong calculating TCP packet's checksum\n");
    }
    dbg_printf("n_chk=%u\tn_wnd=%u\n", ntohs(p_tcphdr->check), ntohs(p_tcphdr->window));
    
    return tcp_flow_list;
}

/************************************************************************************************************
 slus_set_tcp_flows_num()
 Compares the time value passed as input with the time value of every TCP flow structure in the linked list of the active TCP flows. If the difference is higher than the keepalive value removes the flow and updates the active TCP flow counter.
 - num_tcp_flows : Active TCP flow counter
 - tcp_flow_list : linked list of the active TCP flows
 - t : timeval struct that contains the time value to compare
 ************************************************************************************************************/
static TCPid_t* slus_set_tcp_flows_num(TCPid_t* tcp_flow_list, int *num_tcp_flows, struct timeval t)
{
    long dt = 0, dts = 0, dtm = 0; //Variables for the time calculation
    TCPid_t* it;
    TCPid_t* prev;
    it=tcp_flow_list;
    prev=NULL;
    
    while(it!=NULL) //Browses all the list
    {
        //Calculates the time difference between t and the time value of the list element
        dts = ((t.tv_sec - it->timer.tv_sec) * 1000 ); //seconds -> milliseconds
        dtm = ((t.tv_usec - it->timer.tv_usec) / 1000); //microseconds -> milliseconds
        dt = dts + dtm; //milliseconds
        if(dt>SLUS_TCP_KEEPALIVE_TIMER) //if the value is higher than keepalive
        {
            if(prev==NULL) // if is the head of the list
            {
                tcp_flow_list=tcp_flow_list->next; //change che pointer to the head of the list
                free(it);
                (*num_tcp_flows)--; //update the active TCP flow counter
                it=tcp_flow_list;
            }
            else
            {
                prev->next=it->next; //update the previous element pointer
                free(it);
                (*num_tcp_flows)--; //update the active TCP flow counter
                it=prev->next;
            }
        }
        else
        {
            prev=it;
            it=prev->next;
        }
    }
    return tcp_flow_list;
}

/************************************************************************************************************
 slus_calc_udp_bdw()
 Calculate the actual UDP average bandwidth in Kbyte/s and set it accordingly to the dynamic needs
 - udp_traffic : pointer to udp_traffic value, contain the counter of UDP bytes receved
 - last_udp_traffic : pointer to the value of udp_traffic last time the fuction was executed
 - udp_avg_bdw : pointer to udp_avg_bdw value, the function update its value
 - last_check : timeval struct, contains the last calculation time
 - traffic_stat_timer : pointer to traffic_stat_timer value
 ************************************************************************************************************/
static int slus_calc_udp_bdw(int *udp_traffic, int *last_udp_traffic, int *udp_avg_bdw, struct timeval* last_check, int* traffic_stat_timer)
{
    unsigned long actual_udp_bdw = 0;
    struct timeval t;
    long dt = 0, dts = 0, dtm = 0;
    
    if (gettimeofday(&t, NULL))
    {
        fprintf(stderr, "ERROR: cannot retrieve time.\n");
        return EXIT_FAILURE;
    }
    dts = ((t.tv_sec - (*last_check).tv_sec) * 1000 );
    dtm = ((t.tv_usec - (*last_check).tv_usec) / 1000);
    dt = dts + dtm;		// dt is in milliseconds
    
    // The bandwidth is kept in byte
    if (dt > 0) {
        actual_udp_bdw = (unsigned long)((*udp_traffic - *last_udp_traffic) * 1000UL) / dt;
    }
    
    // Modify UDP bandwidth based on dynamic needs.
    if (*last_udp_traffic <= 0)
    { // For the first time or when there was few traffic
        *udp_avg_bdw = actual_udp_bdw;
    }
    else
    {
        *udp_avg_bdw = actual_udp_bdw + (int)(actual_udp_bdw / 10);
    }
    
    // Set next traffic statistics calculation timer
    if ((dt > SLUS_TRAFFIC_STAT_TIMER_UP) && (*traffic_stat_timer > 1)) {	// Too much time since the last calculation
        (*traffic_stat_timer) >>= 1;	// Divide by 2
    }
    else if (dt < SLUS_TRAFFIC_STAT_TIMER_DOWN) {	// Not enough time since the last calculation
        (*traffic_stat_timer) <<= 1;	// Multiply by 2
    }
    
    (*last_check).tv_sec = t.tv_sec;
    (*last_check).tv_usec = t.tv_usec;
    *last_udp_traffic = *udp_traffic;
    return EXIT_SUCCESS;
}

/************************************************************************************************************
 slus_cb()
 Call back function, used every time a packet is read from the queue
 ************************************************************************************************************/
static int slus_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data)
{
    SLUS_DATA* slus_info = (SLUS_DATA*) data;
    int id = 0, len = 0;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    slus_byte *pktHdr = NULL;
    struct iphdr *p_iphdr = NULL;
    struct tcphdr *p_tcphdr = NULL;
    
    // Retrieves packet's id
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }
    else
    {
        fprintf(stderr, "ERROR: Can't read packet's netfilter header");
        return EXIT_FAILURE;
    }
    
    // Retrieves packet's TCP header
    len = nfq_get_payload(nfa, (unsigned char **)&pktHdr);
    if (len < 0) {
        fprintf(stderr, "ERROR: Can't retrieve packet's %i informations\n", id);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);;
    }
    
    p_iphdr = (struct iphdr *)pktHdr;
    
    slus_info->tot_pkt_count++;
    
    switch (p_iphdr->protocol) {
            case 6:		// TCP packet
            // Retrieve traffic informations for the formula calculation
            //		slus_info->tcp_traffic += (len - 20);  20 byte of the packet length are for the IP header.
            p_tcphdr = (struct tcphdr *)(pktHdr + sizeof(struct iphdr));  // ##### DEBUG
            pthread_mutex_lock(slus_info->other_wnd_mtx);
            slus_info->tcp_flow_list=slus_mod_tcp_pktHdr(slus_info->tcp_flow_list, &slus_info->num_tcp_flows, slus_info->adv_wnd, &slus_info->const_adv_wnd ,pktHdr ,len, p_iphdr->saddr,p_iphdr->daddr);
            pthread_mutex_unlock(slus_info->other_wnd_mtx);
            slus_info->mod_pkt_count++;
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
    
    // Retrieve traffic informations for the formula calculation, if needed
    if ((slus_info->const_adv_wnd < 0) && ((slus_info->tot_pkt_count % slus_info->traffic_stat_timer) == 0 || (slus_info->tot_pkt_count == 1)))
    {
        struct timeval t;
        gettimeofday(&t,NULL);
        slus_info->tcp_flow_list=slus_set_tcp_flows_num(slus_info->tcp_flow_list,&slus_info->num_tcp_flows,t);
        
        if (slus_calc_udp_bdw(&slus_info->udp_traffic,&slus_info->last_udp_traffic,&slus_info->udp_avg_bdw,&slus_info->last_check,&slus_info->traffic_stat_timer))
        {
            fprintf(stderr, "ERROR: Can't set UDP average Bandwidth\n");
        }
        // Magic formula: advWnd = ((maxBdw - UDPtraffic) / numTCPFlows)
        pthread_mutex_lock(&slus_info->wnd_mtx);
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
            int minval=(int)(slus_info->max_bwt / 2000);
            if(slus_info->new_adv_wnd < minval)
            slus_info->new_adv_wnd = minval;
        }
        pthread_mutex_unlock(&slus_info->wnd_mtx);
    }
    
    //	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)len, pktHdr);
}

/************************************************************************************************************
 slus_print_usage()
 Print command line program usage
 ************************************************************************************************************/
static void slus_print_usage(const char *prg_name) {
    printf("\nSAP-LAWus: Smart Access Point with Limited Advertised Window user"
           "space solution\n"
           "Version: %s\n\n"
           "Usage: %s [OPTIONS]\n"
           "OPTIONS are:\n"
           "\t[-a adv_wnd]||[-b bandwidth]\n"
           "\t\t The first parameter sets the advertised windows to adv_wnd constant value.\n"
           "\t\t The second parameter set the maximum bandwith available for the\n"
           "\t\t magic formula calculation (the bandwidth is in KByte/s)\n"
           "\t[-s stat_length]\t\t Define the length of packets statistics buffer,"
           "so it defines also every how many packets statistics are written."
           " Default is %u\n"
           "\t[-f stat_file]\t\t Define statistics' log file name. Default is '%s'\n"
           "\t[-h]\t\t\t Print this help\n\n"
           "SAP-LAW user space has been developped for a Laurea Degree Thesis by Matteo "
           "Brunati,\nfrom the original studies of Prof. Claudio E. Palazzi.\n",
           prg_name, SLUS_VERSION);
}

/************************************************************************************************************
 slus_parse_input()
 Parse command line parameters input
 ************************************************************************************************************/
static int slus_parse_input(int argc, char **argv) {
    int opt = 0,
    bdw_ok = 0;
    
    while ((opt = getopt(argc, argv, "c:a:b:s:f:dh")) != -1) {
        switch (opt) {
                break;
                case 'a':
                slus_info_lan->const_adv_wnd = atoi(optarg);
                slus_info_wifi->const_adv_wnd = atoi(optarg);
                bdw_ok++;
                break;
                case 'b':
                slus_info_lan->max_bwt = atoi(optarg) * 1024;
                slus_info_wifi->max_bwt = atoi(optarg) * 1024;
                bdw_ok++;
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

/************************************************************************************************************
 slus_init_iptables()
 Init iptables with SAP-LAW rules chains. Uses two NFQUEUE queues, one each interface
 ************************************************************************************************************/
static int slus_init_iptables()
{
    // The iptables bin path is needed in order to execute SAP-LAW correctly from
    // a remote ssh connection (done for the testbed)
    char *cmd_init_iptables = "/usr/sbin/iptables -t mangle -F && "
    "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -i "SLUS_QUEUE_INT_LAN" -p tcp --tcp-flags ALL ACK -j NFQUEUE --queue-num 1 && " //TCP LAN
    "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -i "SLUS_QUEUE_INT_LAN" -p udp -j NFQUEUE --queue-num 1 && " //UDP LAN
    "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -i "SLUS_QUEUE_INT_WIFI" -p tcp --tcp-flags ALL ACK -j NFQUEUE --queue-num 2 && " //TCP WIFI
    "/usr/sbin/iptables -t mangle -I "SLUS_IPT_CHAIN" 1 -i "SLUS_QUEUE_INT_WIFI" -p udp -j NFQUEUE --queue-num 2 "; //UDP WIFI
    if (system(cmd_init_iptables) < 0) {
        fprintf(stderr, "ERROR: cannot init iptables with command: %s\n", cmd_init_iptables);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/************************************************************************************************************
 slus_flush_iptables()
 Flush iptables from SAP-LAW rules chains
 ************************************************************************************************************/
static int slus_flush_iptables() {
    char *cmd_flush_chain = "iptables -t mangle -F";
    
    if (system(cmd_flush_chain) < 0) {
        fprintf(stderr, "ERROR: cannot flush iptables with command: %s\n",
                cmd_flush_chain);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/************************************************************************************************************
 slus_init_struct()
 Init slus data structures
 ************************************************************************************************************/
static int slus_init_struct()
{
    slus_info_wifi = NULL;
    slus_info_wifi = (SLUS_DATA *) malloc(sizeof(SLUS_DATA));
    if (slus_info_wifi == NULL) {
        fprintf(stderr, "ERROR: cannot allocate memory\n");
        return EXIT_FAILURE;
    }
    slus_info_lan = NULL;
    slus_info_lan = (SLUS_DATA *) malloc(sizeof(SLUS_DATA));
    if (slus_info_lan == NULL) {
        fprintf(stderr, "ERROR: cannot allocate memory\n");
        return EXIT_FAILURE;
    }
    //LAN
    slus_info_lan->max_bwt = 0;
    slus_info_lan->last_udp_traffic = 0;
    slus_info_lan->udp_traffic = 0;
    slus_info_lan->num_tcp_flows = 0;
    slus_info_lan->udp_avg_bdw = 0;
    slus_info_lan->new_adv_wnd = 0;
    slus_info_lan->const_adv_wnd = -1;
    if (gettimeofday(&(slus_info_lan->last_check), NULL) != 0) {
        fprintf(stderr, "ERROR: cannot get time\n");
        return EXIT_FAILURE;
    }
    if (pthread_mutex_init(&slus_info_lan->wnd_mtx, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
    slus_info_lan->tcp_flow_list=NULL;
    slus_info_lan->other_wnd_mtx = &(slus_info_wifi->wnd_mtx);
    slus_info_lan->adv_wnd = &(slus_info_wifi->new_adv_wnd);
    slus_info_lan->mod_pkt_count = 0;
    slus_info_lan->tot_pkt_count = 0;
    slus_info_lan->traffic_stat_timer = 1;	// Will be adjusted by adaptive algorithm
    slus_info_lan->interface=1;
    
    //WIFI
    
    slus_info_wifi->max_bwt = 0;
    slus_info_wifi->last_udp_traffic = 0;
    slus_info_wifi->udp_traffic = 0;
    slus_info_wifi->num_tcp_flows = 0;
    slus_info_wifi->udp_avg_bdw = 0;
    slus_info_wifi->new_adv_wnd = 0;
    slus_info_wifi->const_adv_wnd = -1;
    if (gettimeofday(&(slus_info_wifi->last_check), NULL) != 0) {
        fprintf(stderr, "ERROR: cannot get time\n");
        return EXIT_FAILURE;
    }
    if (pthread_mutex_init(&slus_info_wifi->wnd_mtx, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
    slus_info_wifi->tcp_flow_list=NULL;
    slus_info_wifi->other_wnd_mtx = &(slus_info_lan->wnd_mtx);
    slus_info_wifi->adv_wnd = &(slus_info_lan->new_adv_wnd);
    slus_info_wifi->mod_pkt_count = 0;
    slus_info_wifi->tot_pkt_count = 0;
    slus_info_wifi->traffic_stat_timer = 1;	// Will be adjusted by adaptive algorithm
    slus_info_wifi->interface=0;
    
    dbg_printf("Data structure Inizialized\n");
    return EXIT_SUCCESS;
}

/************************************************************************************************************
 slus_setup_lib()
 linbetfilter_queue setup
 - h : neftilter handler
 ************************************************************************************************************/
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

/************************************************************************************************************
 slus_init_queue()
 Queue handling
 - h
 - qh
 - queue_num : queue identification number
 - slus_info : data structure used in the algorithm calculation
 ************************************************************************************************************/
static int slus_init_queue(struct nfq_handle *h, struct nfq_q_handle **qh, u_int16_t queue_num, SLUS_DATA* slus_info)
{
    dbg_printf("Binding this socket to queue %d\n", queue_num);
    *qh = nfq_create_queue(h, queue_num, &slus_cb, slus_info); //creates the queue and binds the callback to its. Pass to the callback the slus_info structure
    if (!(*qh))
    {
        fprintf(stderr, "ERROR: Error during nfq_create_queue()\n");
        return EXIT_FAILURE;
    }
    if (nfq_set_queue_maxlen(*qh, SLUS_PKT_QUEUE_LEN)) {
        fprintf(stderr, "ERROR: Can't set packets queue length\n");
        return EXIT_FAILURE;
    }
    // Setting to NFQNL_COPY_META will copy only packet's header,
    // NFQNL_COPY_PACKET will copy all the packet
    dbg_printf("Setting copy_packet mode\n");
    if (nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "ERROR: Can't set packet_copy mode\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/************************************************************************************************************
 slus_handle_pkts()
 Handle packets
 - h : neftilter handler
 ************************************************************************************************************/
static int slus_handle_pkts(struct nfq_handle *h)
{
    int fd = 0;
    int rv = 0;
    char buf[4096] __attribute__ ((aligned));
    fd = nfq_fd(h); //takes nfqueue handler file descriptor
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) // receves the message from the socket
    {
        if (nfq_handle_packet(h, buf, rv)) //calls the callback bind to the queue
        {
            fprintf(stderr, "ERROR: Can't handle packet\n");
        }
    }
    perror("Stopped reading queue with error");
    
    return EXIT_SUCCESS;
}

/************************************************************************************************************
 slus_handle_pkts()
 Handle packets
 - h : neftilter handler
 ************************************************************************************************************/
TCPid_t* free_TCP_flow_list(TCPid_t* list_elem)
{
    if(list_elem==NULL)
    return NULL;
    list_elem->next=free_TCP_flow_list(list_elem->next);
    free(list_elem);
    return NULL;
}

/************************************************************************************************************
 slus_prepare_exit()
 Free all the data structures
 - h_lan : neftilter handler
 - h_wifi :
 - qh_lan :
 - qh_wifi :
 ************************************************************************************************************/
static int slus_prepare_exit(struct nfq_handle **h_lan, struct nfq_handle **h_wifi, struct nfq_q_handle **qh_lan ,struct nfq_q_handle **qh_wifi)
{
    dbg_printf("Unbinding from queue\n");
    nfq_destroy_queue(*qh_lan);
    nfq_destroy_queue(*qh_wifi);
    dbg_printf("Closing library handle\n");
    nfq_close(*h_lan);
    nfq_close(*h_wifi);
    if (slus_flush_iptables())
    {
        fprintf(stderr, "ERROR: cannot flush iptables\n");
        return EXIT_FAILURE;
    }
    if (slus_info_lan != NULL)
    {
        slus_info_lan->tcp_flow_list=free_TCP_flow_list(slus_info_lan->tcp_flow_list);
        free(slus_info_lan);
    }
    if (slus_info_wifi != NULL)
    {
        slus_info_wifi->tcp_flow_list=free_TCP_flow_list(slus_info_wifi->tcp_flow_list);
        free(slus_info_wifi);
    }
    
    dbg_printf("Bye bye!\n");
    return EXIT_SUCCESS;
}

/************************************************************************************************************
 thread_func()
 WIFI interface execution using a thread
 - h :
 ************************************************************************************************************/
void* thread_func (void* h)
{
    struct nfq_handle *h_wifi = (struct nfq_handle*) h;
    slus_handle_pkts(h_wifi); //Calls the packet handler function
    return NULL;
}

/************************************************************************************************************
 main()
 AP-LAW user space - Main function
 ************************************************************************************************************/
int main(int argc, char **argv) {
    struct nfq_handle *h_lan = NULL;
    struct nfq_handle *h_wifi = NULL;
    
    struct nfq_q_handle *qh_lan = NULL;
    struct nfq_q_handle *qh_wifi = NULL;
    
    pid_t pid = 0;
    
    if (slus_init_struct()) { //initilizes the data structures
        fprintf(stderr, "ERROR: cannot init internal data structures\n");
        exit(EXIT_FAILURE);
    }
    if (slus_parse_input(argc, argv)) { //parse the user input
        fprintf(stderr, "ERROR: incorrect input parameters\n");
        exit(EXIT_FAILURE);
    }
    if (slus_init_iptables()) { //initializes iptables
        fprintf(stderr, "ERROR: cannot init iptables\n");
        exit(EXIT_FAILURE);
    }
    if (slus_setup_lib(&h_lan)) { //setup netfilter library for LAN interface
        fprintf(stderr, "ERROR: cannot setup libnetiflter_queue lan\n");
        exit(EXIT_FAILURE);
    }
    if (slus_setup_lib(&h_wifi)) { //setup netfilter library for WIFI interface
        fprintf(stderr, "ERROR: cannot setup libnetiflter_queue wifi\n");
        exit(EXIT_FAILURE);
    }
    if (slus_init_queue(h_lan, &qh_lan,SLUS_QUEUE_NUM_LAN,slus_info_lan)) { //Initilizes queue for LAN interface
        fprintf(stderr, "ERROR: cannot init netfilter userspace queue\n");
        exit(EXIT_FAILURE);
    }
    if (slus_init_queue(h_wifi, &qh_wifi,SLUS_QUEUE_NUM_WIFI,slus_info_wifi)) { //Initilizes queue for WIFI interface
        fprintf(stderr, "ERROR: cannot init netfilter userspace queue\n");
        exit(EXIT_FAILURE);
    }
    
    if(pthread_create(&child,NULL,&thread_func,(void*) h_wifi) != 0) //Creates a thread for WIFI execution
    {
        fprintf(stderr, "ERROR: error handling packets\n");
        exit(EXIT_FAILURE);
    }
    slus_handle_pkts(h_lan); //LAN exection
    
    if(slus_prepare_exit(&h_lan,&h_wifi,&qh_lan, &qh_wifi)) //Free all the data structures
    {
        fprintf(stderr, "ERROR: cannot exit in a good way\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
