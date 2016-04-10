/*
 *	slus_main.h: 
 *  SAP-LAW user space header file
 *
 *	<2009, Matteo Brunati, saplaw@matteobrunati.net>
 *
 *	This file is published under the GNU GPL version 3 license, or any later
 *	version.
 *
 *  Corrected and improved by Giacomo Pandini, 2015
 *  V 2.0
 */

#ifndef SLUS_H_
#define SLUS_H_

#include <sys/types.h>
#include <pthread.h>

#define SLUS_TRAFFIC_STAT_TIMER_UP 3000					// Max delay time from the last calculation
#define SLUS_TRAFFIC_STAT_TIMER_DOWN 1500				// Minimum delay time from the last calculation
#define SLUS_TCP_KEEPALIVE_TIMER 75000                  // TCP Keepalive value
#define SLUS_CONF_FILE "/etc/slus/slus.conf"			// Slus config file
#define SLUS_VERSION "alpha V2"							// Slus version

//FLAGS
#define DEBUG 1										// Debug level

#if defined(DEBUG)
	#define dbg_printf printf
#else
	#define dbg_printf
#endif

#define SLUS_PKT_QUEUE_LEN 8192					// Maximum packets queue length
#define SLUS_QUEUE_NUM_LAN 1					// Default queue number LAN
#define SLUS_QUEUE_NUM_WIFI 2					// Default queue number WIFI
#define SLUS_QUEUE_INT_LAN "br-lan"             // LAN interface name
#define SLUS_QUEUE_INT_WIFI "br-wifi"           // WIFI interface name
#define SLUS_IPT_CHAIN	"FORWARD"				// SAP-LAW iptables chain name


typedef unsigned char slus_byte;

/*
 * Used for tracking the number of TCP flow active
 */
typedef struct TCPid
{
    u_int32_t ipsource;     // IP source adress
    u_int32_t ipdest;       // IP destination adress
    u_int16_t tcpsource;    // Source port
    u_int16_t tcpdest;      // Destination part
    struct timeval timer;   // Validity timer
    struct TCPid* next;     // Pointer to next element of the list
} TCPid_t;

/*
 * Contains program input and data
 */
typedef struct {
	int max_bwt,			// Max bandwidth, needed for the magic formula
		last_udp_traffic,	// Last UDP traffic in KByte
		udp_traffic,		// UDP traffic in KByte
		num_tcp_flows,		// Number of TCP flows
		udp_avg_bdw,		// UDP average bandwidth in KByte/s
		new_adv_wnd,		// The new advertised window, calculated with SAP-LAW algorithm
		const_adv_wnd;		// Constant advertised window value
	struct timeval last_check;	// Last udp bandwidth calculation
    pthread_mutex_t wnd_mtx;            // Access mutex, used for access new_advertised_window
    pthread_mutex_t* other_wnd_mtx;     // Other interfece access mutex
    TCPid_t *tcp_flow_list;     // Pointer to active TCP flows linked list
    int* adv_wnd;               // Pointer to other interface new_advertise_window
    int mod_pkt_count;			// Modified packets counter
    int tot_pkt_count;			// Total packets counter
    int traffic_stat_timer;		// Define after how many packets read traffic stats
    int interface;
} SLUS_DATA;

pthread_t child; //Thread used for execute the program using two interface

// Data pointer for the two interface
SLUS_DATA *slus_info_lan;
SLUS_DATA *slus_info_wifi;

#endif /* SLUS_H_ */
