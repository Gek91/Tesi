//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* SLK.c
 * SAP-LAW Kernel module main functions
 * Giacomo Pandini , 2015
 * Version 2.0
 */
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


#include "SLK.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////NETFILTER HOOK/////////////////////////////////////////////////

/************************************************************************************************************
 slk_check_update_SL()
 Increase the packet counter. Checks if needed update the traffic control parameters. If needed return 0, the SAP-LAW will be executed.
 - tot_pkt_count : pointer to the total packet counter
 - traffic_stat_timer : pointer to traffic_stat_timer
 ************************************************************************************************************/
static int slk_check_update_SL(int* tot_pkt_count, int* traffic_stat_timer)
{
    int res;
    (*tot_pkt_count)++; //Update packet counter
    res = *tot_pkt_count % *traffic_stat_timer; //checks if needed execute the SAP-LAW. Only if the rest of the division is 0
    return res;
}

/************************************************************************************************************
 slk_udp_handle()
 Called if arrives a UDP packet. Update the upd_traffic counter adding the size of the packet
 - udp_traffic: pointer to udp_traffic variable
 - ip: pointer to the IP header struct
 ************************************************************************************************************/
static void slk_udp_handle(int* udp_traffic, struct iphdr *ip)
{
    *udp_traffic += ( ntohs( (u_int16_t) ip->tot_len) + 14 ); // Add to the UDP traffic the size of the packet and the size of the ethernet header (14)
}

/*************************************************************************************************************
 searchTCPflow()
 Check if flow passed at the function, identify with 4 value, is already in the list of the active TCP flows. If it isn't add it and update the active TCP counter. Return the head of the list
 - num_tcp_flows : active TCP counter
 - tcp_flow_list : linked list on which the search is made
 - ipsource: IP source address of the flow
 - ipdest: IP destination address of the flow
 - tcpsource: source port of the flow
 - tcpdest: destination port of the flow
 *************************************************************************************************************/
static TCPid_t* searchTCPflow(int* num_tcp_flows, TCPid_t* tcp_flow_list, u_int32_t ipsource, u_int32_t ipdest, u_int16_t tcpsource, u_int16_t tcpdest)
{
    TCPid_t* it;
    TCPid_t* nxt;
    if(tcp_flow_list==NULL) //if the list is empty, inserts the head
    {
        //Creates a new element of the list
        tcp_flow_list=kmalloc(sizeof(TCPid_t),GFP_KERNEL);
        tcp_flow_list->ipsource=ipsource;
        tcp_flow_list->ipdest=ipdest;
        tcp_flow_list->tcpsource=tcpsource;
        tcp_flow_list->tcpdest=tcpdest;
        do_gettimeofday(&tcp_flow_list->timer);
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
            do_gettimeofday(&it->timer);
            return tcp_flow_list;
        }
        if(ipsource==it->ipdest && ipdest==it->ipsource && tcpsource==it->tcpdest && tcpdest==it->tcpsource)
        {
            do_gettimeofday(&it->timer);
            return tcp_flow_list;
        }
        // if the flow is not in the list, adds it to the list creating a new element
        if(it->next==0)
        {
            nxt=kmalloc(sizeof(TCPid_t),GFP_KERNEL);
            nxt->ipsource=ipsource;
            nxt->ipdest=ipdest;
            nxt->tcpsource=tcpsource;
            nxt->tcpdest=tcpdest;
            do_gettimeofday(&nxt->timer);
            nxt->next=NULL;
            it->next=nxt;
            (*num_tcp_flows)++; //update the TCP flows counter
            return tcp_flow_list;
        }
        it=it->next; //next element
    }
}

/************************************************************************************************************
 slk_calc_check()
 Calcuates the checksum of the packet passed to the function.
 - ip: pointer to the header ip struct
 - tcp: pointer to the header tcp struct
 - slk: pointer to the buffer containing the packet
 ************************************************************************************************************/
static void slk_calc_check(struct iphdr *ip, struct tcphdr *tcp,struct sk_buff *skb)
{
    // Checksum reset
    u_int16_t tcplen = (skb->len - (ip->ihl << 2)); // Calculate the TCP segment lenght
    tcp->check = 0;
    tcp->check = tcp_v4_check(tcplen,ip->saddr,ip->daddr, csum_partial((char *)tcp, tcplen, 0)); //Recalucates TCP checksum
    skb->ip_summed = CHECKSUM_NONE; // stop offloading
    ip->check = 0;
    ip->check = ip_fast_csum((u8 *)ip, ip->ihl); // Recalculate IP checksum
}

/************************************************************************************************************
 slk_tcp_handle()
 Called if arrives a TCP packet. Modifies the advertised windows value if the new_adv_wnd value is lower than the actual value. Update the packet checksum.
 - const_adv_wnd : constant advertised windows value, if <0 not used
 - num_tcp_flows : actual TCP flows counter
 - new_adv_wnd : value of the advertised windows dynamically calculated 
 - mod_pkt_count : modified packet counter
 - tcp_flow_list : linked list containing the active TCP flows
 - ip : pointer to the header ip struct
 - skb : pointer to the buffer containing the packet
 ************************************************************************************************************/
static TCPid_t* slk_tcp_handle(int* const_adv_wnd, int* num_tcp_flows, int* new_adv_wnd, int* mod_pkt_count, TCPid_t* tcp_flow_list, struct iphdr *ip, struct sk_buff *skb)
{
    struct tcphdr *tcp = NULL;
    int mod=0;
    tcp=tcp_hdr(skb); //Take the TCP Header
    if (*const_adv_wnd < 0)// if a constant value for the advertised window is not used
    {
        tcp_flow_list=searchTCPflow(num_tcp_flows, tcp_flow_list, ntohs(ip->saddr),ntohs(ip->daddr),ntohs(tcp->source),ntohs(tcp->dest)); //Check if the flow is already in the list, if it isn't add it
        #ifdef DEBUG //DEBUG
        printk(KERN_INFO "*****DEBUG***** Packet Window: %d \t SLK Window: %d\n ",tcp->window,(u_int16_t)*new_adv_wnd);
        #endif
        if( ntohs (tcp->window) > (u_int16_t) *new_adv_wnd ) // Use the lower value for the advertised window
        {
            tcp->window = htons ((u_int16_t) *new_adv_wnd);
            mod++;
        }
    }
    else // If a constant value for the advertised windows is used
    {
        tcp->window =htons ( (u_int16_t) *const_adv_wnd);
        mod++;
    }
    
    if (mod)// If the packet it has been modified
    {
        slk_calc_check(ip,tcp,skb); //Recalculates the checksum
        (*mod_pkt_count)++;
    }
    return tcp_flow_list;
}

/************************************************************************************************************
 slk_calc_df()
 Calculates the time difference between the last check an the actual time. Update last check and return the calculated value.
 - last_check : timeval struct, contains the last calculation time
 - t: timeval struct, contains the current time
 ************************************************************************************************************/
static long slk_calc_df(struct timeval* last_check, struct timeval t)
{
    long dt = 0, dts = 0, dtm = 0; //Variables for the time calculation
    //Calculate the time difference
    dts = ((t.tv_sec - (*last_check).tv_sec) * 1000 ); //seconds -> milliseconds
    dtm = ((t.tv_usec - (*last_check).tv_usec) / 1000); //microsecond -> milliseconds
    dt = dts + dtm; //milliseconds
    
    // Update last_check value
    (*last_check).tv_sec = t.tv_sec;
    (*last_check).tv_usec = t.tv_usec;
    return dt; // Return the time difference
}


/************************************************************************************************************
 slk_update_tst()
 Update traffic_stat_timer value according on the dt value
 - traffic_stat_timer : pointer to traffic_stat_timer value
 - dt : time difference
 ************************************************************************************************************/
static void slk_update_tst(int* traffic_stat_timer, long dt)
{
    if ((dt > SLK_TRAFFIC_STAT_TIMER_UP) && (*traffic_stat_timer > 1)) //too much time
    {
        *traffic_stat_timer >>= 1;	// /2
    }
    else if (dt < SLK_TRAFFIC_STAT_TIMER_DOWN) // too little
    {
        *traffic_stat_timer <<= 1;	// *2
    }
}

/************************************************************************************************************
 time_check_tcp_flows()
 Compares the time value passed as input with the time value of every TCP flow structure in the linked list of the active TCP flows. If the difference is higher than the keepalive value removes the flow and updates the active TCP flow counter.
 - num_tcp_flows : Active TCP flow counter
 - tcp_flow_list : linked list of the active TCP flows
 - t : timeval struct that contains the time value to compare
 ************************************************************************************************************/
static TCPid_t* time_check_tcp_flows(int* num_tcp_flows, TCPid_t* tcp_flow_list, struct timeval t)
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
        if(dt>SLK_TCP_KEEPALIVE_TIMER) //if the value is higher than keepalive
        {
            if(prev==NULL) // if is the head of the list
            {
                tcp_flow_list=tcp_flow_list->next; //change che pointer to the head of the list
                kfree(it);
                (*num_tcp_flows)--; //update the active TCP flow counter
                it=tcp_flow_list;
            }
            else
            {
                prev->next=it->next; //update the previous element pointer
                kfree(it);
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
    return tcp_flow_list; //return the head of the list
}

/************************************************************************************************************
 slk_udp_bdw_update()
 Calculates the average udp bandwidth of the last time interval.
 - udp_traffic : pointer to udp_traffic value, contain the counter of UDP bytes receved
 - last_udp_traffic : pointer to the value of udp_traffic last time the fuction was executed
 - udp_avg_bdw : pointer to udp_avg_bdw value, the function update its value
 - dt : time interval used to perform che calculation
 ************************************************************************************************************/
static void slk_udp_bdw_update(int* udp_traffic, int* last_udp_traffic,int* udp_avg_bdw, long dt)
{
    unsigned long actual_udp_bdw=0;
    //Calculates the average bandwidth in the interval
    if (dt > 0)
    {
        actual_udp_bdw = (unsigned long)((*udp_traffic - *last_udp_traffic) * 1000UL) / dt; //Byte/s
    }
    // Modifies the value to have better results
    if (*last_udp_traffic <= 0) //if there was little traffic
    {
        *udp_avg_bdw = actual_udp_bdw;
    }
    else
    {
        *udp_avg_bdw = actual_udp_bdw + (int)(actual_udp_bdw / 10); //Increase the UDP bandwidth of 10%, in case there was TCP flow that take all the bandwidht.
    }
    *last_udp_traffic = *udp_traffic; //Update last_udp_traffic value
}

/************************************************************************************************************
 slk_magic_formula()
 Performs the magik formula calculation
 - num_tcp_flows : pointer to num_tcp_flows value, number of active TCP flows
 - new_adv_wnd : pointer to new_adv_wnd, the function update its value
 - max_bwt : pointer to max_bwt, max bandwidth in the link
 - udp_avg_bdw : pointer to udp_avg_bdw, value of the UDP bandwidth in the link
 ************************************************************************************************************/
static void slk_magic_formula(int* num_tcp_flows,int* new_adv_wnd,int* max_bwt, int* udp_avg_bdw)
{
    //Magik Formula SAP-LAW
    if(*num_tcp_flows != 0) //if there are more than 0 TCP flow
    {
        *new_adv_wnd = ( *max_bwt - *udp_avg_bdw ) / *num_tcp_flows; //Magik Formula
        #ifdef DEBUG //DEBUG
        printk(KERN_INFO "*****DEBUG***** max_bwt: %d udp_avg_bdw : %d num_tcp_flow: %d =  new_adv_wnd : %d\n", *max_bwt,*udp_avg_bdw, *num_tcp_flows, *new_adv_wnd);
        #endif
    }
    else
        *new_adv_wnd=0;
    if( *new_adv_wnd > 65535 ) //TCP advertised windows value: between 0 - 65535
        *new_adv_wnd = 65535;
    else
    {
        int minval=(int)(*max_bwt / 2000);
        if(*new_adv_wnd < minval ) //Advertised windows min value
            *new_adv_wnd = minval;
    }
}

/************************************************************************************************************
 slk_main_exe()
 Execute the program on an interface. Distinguishes the packets according to their trasport protocol. 
 The UDP packets are used to calculate che UDP bandwidth in the link.
 The TCP packet are used to know the number of TCP flows in the link.
 Give this two value and the value of the max bandwidth in the link the program calculates dynamically the value of the advertised windows to obtain more fairness between the type of trasport protocol packets.
 Uses this value to modify the TCP packet advertised windows. The parameter for the calculation are dynamically update.
 - slk_info : data struct containing all the data to manage an interface
 - tcp_flow_list : data struct containing the linked list of active TCP flows
 - skb : data buffer containing the packet receved
 - new_adv_wnd : pointer to new_adv_wnd valued of the other interface
 
 ************************************************************************************************************/

static TCPid_t* slk_main_exe(SLK_DATA* slk_info, TCPid_t* tcp_flow_list, struct sk_buff *skb, int* new_adv_wnd)
{
    struct iphdr *ip  = NULL;
    struct udphdr *udp = NULL;
    int res;
    
    res=slk_check_update_SL(&slk_info->tot_pkt_count,&slk_info->traffic_stat_timer); //Update the total packet counter and check if is needed update the parameters of traffic
    
    #ifdef DEBUG //DEBUG
    printk(KERN_INFO "*****DEBUG***** tot_pkt_count: %d \n",slk_info->tot_pkt_count);
    #endif
    ip=ip_hdr(skb); //Take the IP header from skb buffer
    #ifdef DEBUG //DEBUG
    printk(KERN_INFO "*****DEBUG***** Header IP \t source: %pI4 \t destination: %pI4\t lenght:%u byte \n",&(ip->saddr),&(ip->daddr),ntohs(ip->tot_len)); //
    #endif
    switch (ip->protocol) //Protocol Check
    {
        case 17: //UDP
            udp=udp_hdr(skb); //Take the UDP header from the skb buffer
            slk_udp_handle(&slk_info->udp_traffic,ip); //Handles an UDP packet
            #ifdef DEBUG //DEBUG
            printk(KERN_INFO "*****DEBUG***** Pacchetto UDP \t source:%u \t destination:%u \t lenght:%u byte\n",ntohs(udp->source),ntohs(udp->dest), ntohs(udp->len));
            printk(KERN_INFO "*****DEBUG***** udp_traffic: %d \n",slk_info->udp_traffic);
            #endif
            break;
        case 6: //TCP
            tcp_flow_list=slk_tcp_handle(&slk_info->const_adv_wnd, &slk_info->num_tcp_flows, new_adv_wnd, &slk_info->mod_pkt_count,tcp_flow_list,ip,skb); //Handles a TCP packet
            #ifdef DEBUG //DEBUG
            printk(KERN_INFO "*****DEBUG***** Pacchetto TCP \t source:%d \t destination:%d \n",ntohs(tcp->source),ntohs(tcp->dest));
            printk(KERN_INFO "*****DEBUG***** mod_pkt_count: %d \n",slk_info->mod_pkt_count);
            #endif
            break;
        default:
            break;
    }
    
    if( (res == 0 || slk_info->tot_pkt_count == 1) && slk_info->const_adv_wnd < 0) //Executes the SAP-LAW for update the parameters
    {
        struct timeval t;
        long dt;
        do_gettimeofday(&t);
        dt=slk_calc_df(&slk_info->last_check,t); //Calculates the time difference between the last check and the actual time
        slk_update_tst(&slk_info->traffic_stat_timer, dt); //Update traffic_stat_timer value
        tcp_flow_list=time_check_tcp_flows(&slk_info->num_tcp_flows, tcp_flow_list, t); //Updates the list and the number of active TCP flows
        #ifdef DEBUG //DEBUG
        printk(KERN_INFO "*****DEBUG***** traffic_stat_timer: %d pkt \t dt : %ld ms \t num_tcp_flows: %d \n",slk_info->traffic_stat_timer,dt,slk_info->num_tcp_flows);
        #endif
        slk_udp_bdw_update(&slk_info->udp_traffic, &slk_info->last_udp_traffic, &slk_info->udp_avg_bdw, dt); //Updates the avg_udp_bwd value
        slk_magic_formula(&slk_info->num_tcp_flows, &slk_info->new_adv_wnd, &slk_info->max_bwt, &slk_info->udp_avg_bdw); //Executes the magik formula
        #ifdef DEBUG //DEBUG
        printk(KERN_INFO "*****DEBUG***** udp_avg_bdw: %d \t new_adv_wnd : %d \n",slk_info->udp_avg_bdw,slk_info->new_adv_wnd);
        #endif
    }
    return tcp_flow_list;
}

/************************************************************************************************************
 hook_func()
 Netfilter Framework hook function. Called when a packet arrives on the specified hook of the module. For each interface call the main function for the management of the packets.
 ************************************************************************************************************/
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    if (!skb)  //No socket buffer
        return NF_DROP; // drop the message
    
    if(strcmp(in->name,LAN) == 0) // packet from LAN interface
    {
        spin_lock(&lock_lan);
        tcp_flow_list_lan=slk_main_exe(slk_info_lan, tcp_flow_list_lan,skb,&slk_info_wifi->new_adv_wnd); //Execute le main function
        spin_unlock(&lock_lan);
    }
    else
    {
        if(strcmp(in->name,WIFI) == 0) // Packet from WIFI interface
        {
            spin_lock(&lock_wifi);
            tcp_flow_list_wifi=slk_main_exe(slk_info_wifi, tcp_flow_list_wifi,skb,&slk_info_lan->new_adv_wnd); //Execute the main function
            spin_unlock(&lock_wifi);
        }
    }
    return NF_ACCEPT; //accetta tutti i pacchetti, possono continuare la loro transazione
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////Module init function//////////////////////////////////////////////

/************************************************************************************************************
 slk_init_hook()
 Define the data structure value for the hook
 ************************************************************************************************************/
static void slk_init_hook(void)
{
    nfho.hook = hook_func; //Function called in the hook
    nfho.hooknum = NETFILTER_HOOK_POS; //hook listening point in the protocol stack
    nfho.pf = PF_INET; //Protocol family
    nfho.priority = NF_IP_PRI_FIRST; //Hook priority
    printk(KERN_INFO "Kernel hook initialization complete \n");
}

/************************************************************************************************************
 slk_init_data()
 Initializes the data structure of the program
 ************************************************************************************************************/
static void slk_init_data(void)
{
    //Memory allocation
    slk_info_lan=kmalloc(sizeof(SLK_DATA),GFP_KERNEL);
    slk_info_wifi=kmalloc(sizeof(SLK_DATA),GFP_KERNEL);
    
    //LAN
    slk_info_lan->max_bwt=1000*1024; //byte/s
    slk_info_lan->last_udp_traffic = 0;
    slk_info_lan->udp_traffic = 0;
    slk_info_lan->num_tcp_flows = 0;
    slk_info_lan->udp_avg_bdw = 0;
    slk_info_lan->new_adv_wnd = 0;
    slk_info_lan->const_adv_wnd = -1;
    do_gettimeofday(&slk_info_lan->last_check);
    slk_info_lan->tot_pkt_count = 0;
    slk_info_lan->mod_pkt_count = 0;
    slk_info_lan->traffic_stat_timer = 1; 
    
    //WIFI
    slk_info_wifi->max_bwt=1000*1024; //byte/s
    slk_info_wifi->last_udp_traffic = 0;
    slk_info_wifi->udp_traffic = 0;
    slk_info_wifi->num_tcp_flows = 0;
    slk_info_wifi->udp_avg_bdw = 0;
    slk_info_wifi->new_adv_wnd = 0;
    slk_info_wifi->const_adv_wnd = -1;
    do_gettimeofday(&slk_info_wifi->last_check);
    slk_info_wifi->tot_pkt_count = 0;
    slk_info_wifi->mod_pkt_count = 0;
    slk_info_wifi->traffic_stat_timer = 1;
    
    //Spinlock
    spin_lock_init(&lock_lan);
    spin_lock_init(&lock_wifi);
    
    //Input parameter
    if(up_bwt>0)
    {
        slk_info_lan->max_bwt=up_bwt *1024; //Byte/s
        slk_info_wifi->max_bwt=up_bwt *1024; //Byte/s
    }
    
    if(adv_wnd>0)
    {
        slk_info_lan->const_adv_wnd=adv_wnd; //Byte
        slk_info_wifi->const_adv_wnd=adv_wnd; //Byte
    }
    
    printk(KERN_INFO "Variables inizialization complete \n");
}

/************************************************************************************************************
 mod_init()
 Inizializes the program calling the inizializzation functions and registring the hook
 ************************************************************************************************************/
static int __init mod_init(void)
{
    printk(KERN_INFO "Inizialization SLK: SAP-LAW KERNEL module\n");
    
    slk_init_hook();    //Inizializes the hook values
    slk_init_data();    //Inizializes the data values
    
    nf_register_hook(&nfho); //Registers the hook
    
    printk(KERN_INFO "Inizalization SLK complete, module loaded correctly \n");
    printk(KERN_INFO "LAN max_bwt= %d , const_adv_wnd= %d  \n",slk_info_lan->max_bwt, slk_info_lan->const_adv_wnd );
    printk(KERN_INFO "WIFI max_bwt= %d , const_adv_wnd= %d  \n",slk_info_wifi->max_bwt, slk_info_wifi->const_adv_wnd );
    
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////Module termination function ///////////////////////////////////////////

/************************************************************************************************************
 free_TCP_flow_list()
 Free the memory used by the linked list of the TCP flows.
 - list_elem: input list element
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
 Free the memory used for the data structure of the module and release the hook. Ends the module execution
 ************************************************************************************************************/
static void __exit mod_exit(void)
{
    //Delete the two linked list of the TCP flows
    tcp_flow_list_lan=free_TCP_flow_list(tcp_flow_list_lan);
    tcp_flow_list_wifi=free_TCP_flow_list(tcp_flow_list_wifi);
    
    nf_unregister_hook(&nfho); //release the hook
    printk(KERN_INFO "LAN");
    printk(KERN_INFO "Total packet receved : %d\n", slk_info_lan->tot_pkt_count );
    printk(KERN_INFO "Total UDP traffic : %d byte\n",slk_info_lan->udp_traffic);
    printk(KERN_INFO "Total packet Modified : %d \n", slk_info_lan->mod_pkt_count);
    
    printk(KERN_INFO "WIFI");
    printk(KERN_INFO "Total packet receved : %d\n", slk_info_wifi->tot_pkt_count );
    printk(KERN_INFO "Total UDP traffic : %d byte\n",slk_info_wifi->udp_traffic);
    printk(KERN_INFO "Total packet Modified : %d \n", slk_info_wifi->mod_pkt_count);
    printk(KERN_INFO "SKL: SAP-LAW KERNEL module removed\n");
    
    //Free the memory for the data structures
    kfree(slk_info_lan);
    kfree(slk_info_wifi);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Difines the inizialization and termination functions
module_init(mod_init);
module_exit(mod_exit);

//Defines module infos
MODULE_AUTHOR("Giacomo Pandini");
MODULE_DESCRIPTION("SLK, Sap-Law Kernel");
MODULE_LICENSE("GPL");

