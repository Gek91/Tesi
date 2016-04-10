//////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* SLK.h
 * SAP-LAW Kernel module header file
 * Giacomo Pandini , 2015
 * Version 2.0
 *
 */
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef SLK_H_
#define SLK_H_

//Headers for kernel function
#include <linux/kernel.h>
#include <linux/module.h>
//Header for packet mangling
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/moduleparam.h>      //Input parameter for the program
#include <linux/errno.h>            //Error codes
#include <linux/time.h>             //Timer management
#include <linux/spinlock.h>         //Spinlock
#include <linux/types.h>            //Kernel data type
#include <linux/slab.h>             //necessario per la kmalloc
#include <linux/gfp.h>              //flag della kmalloc , DA VERIFICARE

#include <net/ip.h>
#include <net/tcp.h>

//Flag
//#define DEBUG 1

//Interfaces on the device
#define LAN "br-lan"
#define WIFI "br-wifi"

//Netfilter Kernel hook position
#define NETFILTER_HOOK_POS NF_INET_FORWARD

//Time bounds used in the SAP-LAW calculation
#define SLK_TRAFFIC_STAT_TIMER_UP 3000 //Upperbound
#define SLK_TRAFFIC_STAT_TIMER_DOWN 1500 //Lowerbound
#define SLK_TCP_KEEPALIVE_TIMER 75000 //TCP KeepAlive timer, used in TCP flows' structure counting

/*********************************************************************************************************
 SLK VARIABLES:
 * Struct SLK_DATA
 The structure contains all the variables needed for execute the program and calculate the SAP-LAW for one interface.
 - max_bwt : Max bandwidth, used in the magik formula, passed from the user
 - last_udp_traffic : udp_traffic value saved during last SAP-LAW calculation
 - udp_traffic : Total UDP traffic in Byte
 - num_tcp_flows : Number of actual TCP flows
 - udp_avg_bdw : Average bandwidth in byte/s, used in the SAP-LAW calculation
 - new_adv_wnd : TCP advertised window value calculated in magik formula
 - const_adv_wnd : Fixed TCP adverstised windows, choosed by the user
 - last_check : timeval struct, time value of the last upd_avg_bdw calculation
 - tot_pkt_count : Total packet counter
 - mod_pkt_count : Modified packet counter
 - traffic_stat_timer : It defines after how many packet execute the magik formula, dynamically updated
 
 * Struct TCPid_t
 The structure defines a linked list used for calculate the actual number of TCP flows. Each list element identifies univocally one TCP flow with 4 values.
 - ipsource : IP source adress
 - ipdest : IP destination adress
 - tcpsource : Source port
 - tcpdest : Destination port
 - timer : Keepalive timer
 - next : Pointer to the next element of the list, NULL if the last element
 
 **********************************************************************************************************/

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

typedef struct TCPid
{
    u_int32_t ipsource;
    u_int32_t ipdest;
    u_int16_t tcpsource;
    u_int16_t tcpdest;
    struct timeval timer;
    struct TCPid* next;
} TCPid_t;

// Lan interface data
static SLK_DATA *slk_info_lan;
static TCPid_t* tcp_flow_list_lan;
// Wifi interface data
static SLK_DATA *slk_info_wifi;
static TCPid_t* tcp_flow_list_wifi;

// Netfilter data struct for define an hook
static struct nf_hook_ops nfho;

//Spinlock
static spinlock_t lock_lan;
static spinlock_t lock_wifi;

////////////////////////////////////////////////////////////////////////////////////////////////////////////
static int up_bwt=-1;
static int adv_wnd=-1;

//Input parameters, defines the name of the parameters, their type and the permits
module_param(up_bwt, int, 0 ); //max bandwidth
MODULE_PARM_DESC(up_bwt, "Input parameter max_bwt");

module_param(adv_wnd, int, 0 ); //constant advertised window
MODULE_PARM_DESC(adv_wnd, "Input parameter const_adv_wnd");


#endif

