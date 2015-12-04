/*
 *	slus_main.h: TODO
 *
 *	<2009, Matteo Brunati, saplaw@matteobrunati.net>
 *
 *	This file is published under the GNU GPL version 3 license, or any later
 *	version.
 *
 *	TODO: inserisci note agiuntive
 *
 */

#ifndef SLUS_H_
#define SLUS_H_

#include <sys/types.h>


#define SLUS_STAT_LENGTH 1024							/* Default number of packets after which statistics are written */
#define SLUS_STAT_FILE_NAME  "SAP-LAWstats.log"			/* Default statistics file name */
#define SLUS_TRAFFIC_STAT_TIMER_UP 3000					/* Max delay time from the last calculation */
#define SLUS_TRAFFIC_STAT_TIMER_DOWN 1500				/* Minimum delay time from the last calculation */
#define SLUS_TCP_KEEPALIVE_TIMER 75000
#define SLUS_CONF_FILE "/etc/slus/slus.conf"			/* Slus config file */
#define SLUS_VERSION "alpha"							/* Slus version */

#define DEBUG 1											/* Debug level */
//#define OPENWRT										/* When compiling for OpenWRT */

#if defined(DEBUG)
	#define dbg_printf printf
#else
	#define dbg_printf
#endif

#if !defined(OPENWRT)
	#define SLUS_QUEUE_NUM 2						/* Default queue number */
	//#define SLUS_IPT_CHAIN	"INPUT"				/* SAP-LAW iptables chain name */
	#define SLUS_IPT_CHAIN	"OUTPUT"				/* SAP-LAW iptables chain name */
	//#define SLUS_IPT_CHAIN	"FORWARD"			/* SAP-LAW iptables chain name */
#else
	#define SLUS_PKT_QUEUE_LEN 8192					/* Maximum packets queue length */
	#define SLUS_QUEUE_NUM 0						/* Default queue number */
	#define SLUS_IPT_CHAIN	"FORWARD"				/* SAP-LAW iptables chain name */
#endif


typedef unsigned char slus_byte;

/*
 * Contains program input and data
 */
typedef struct {
	int max_bwt,			// Max bandwidth, needed for the magic formula
		last_udp_traffic,	// Last UDP traffic in KByte
//		tcp_traffic,		// TCP traffic in KByte
		udp_traffic,		// UDP traffic in KByte
		num_tcp_flows,		// Number of TCP flows
		daemon,				// Says if the application should run as a daemon
		udp_avg_bdw,		// UDP average bandwidth in KByte/s
		new_adv_wnd,		// The new advertised window, calculated with SAP-LAW algorithm
		const_adv_wnd;		// Constant advertised window value
	struct timeval last_check;	// Last udp bandwidth calculation
	char* conf_file;		// Slus config file
} SLUS_DATA;

/*
 * Contains packets statistics
 */
typedef struct {
	char *stat_file_name;		// Statistics file name
	int stat_length;		// Statistic's buffer length
	int mod_pkt_count;			// Modified packets counter
	int tot_pkt_count;			// Total packets counter
	int chksum_err_count;		// Checksum error counter
	int traffic_stat_timer;		// Define after how many packets read traffic stats
} SLUS_STAT;

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

TCPid_t *tcp_flow_list;

SLUS_DATA *slus_info;
SLUS_STAT *slus_stat;

#endif /* SLUS_H_ */
