#ifndef SLK_H_
#define SLK_H_

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

//Debug flag
#define DEBUG 0

//Valori di tempo che aiutano a modificare il valore che definisce ogni quanti pacchetti eseguire il calcolo della SAP-LAW
#define SLK_TRAFFIC_STAT_TIMER_UP 3000 //Upperbound
#define SLK_TRAFFIC_STAT_TIMER_DOWN 1500 //Lowerbound

#define SLK_TCP_KEEPALIVE_TIMER 75000 //definisce il limite del timer KeepAlive, oltre quel valore il flusso TCP viene eliminato dalla memoria

/*********************************************************************************************************
 VARIABILI DEL PROGRAMMA UTILI A SLK:
 * Struct SLK_DATA
 * Struttura che contiene tutte le variabili utili all'esecuzione del programma e al calcolo della SAP-LAW
 max_bwt : Max bandwidth usata per la formula del programma, passata esternamente
 last_udp_traffic : Valore del traffico UPD in Byte l'ultima volta che è stato verificato
 udp_traffic : Valore del traffico UDP totale in Byte
 num_tcp_flows : numero di flussi TCP attualmente passanti
 udp_avg_bdw : bandwidth media in KB/s utilizzata per il calcolo della formula
 new_adv_wnd : valore dell'advertised window di TCP calcolata con SAP-LAW
 const_adv_wnd : variabile che contiene un eventuale valore fisso della adverstised windows impostato dall'utente
 last_check : indica quando è stata calcolata per l'ultima volta la bandwidth UPD
 
 tot_pkt_count : Contatore numero totale di pacchetti
 traffic_stat_timer : Definisce ogni quanti pacchetti eseguire la formula
 
 * Struct TCPid_t
 * Struttura che definisce la lista concatenata che contiene i flussi TCP presenti al momento. Ogni elemento definisce un flusso TCP attraverso 4 valori che lo identificano univocamente
 ipsource : indirizzo IP di provenienza
 ipdest : indirizzo IP di destinazione
 tcpsource : porta di provenienza
 tcpdest : porta di destinazione
 timer : timer di keepalive
 next : puntatore al successivo elemento della lista dei flussi, NULL se è l'ultimo elemento
 
 tcp_flow_list : lista concatenata contenente i flussi TCP correntemente attivi
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

static SLK_DATA *slk_info;
static TCPid_t* tcp_flow_list;

//Struttura dati Netfilter per la definizione di un hook
static struct nf_hook_ops nfho;

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
 
 lock_tcp_flow_list : spinlock per l'accesso alla variabile tcp_flow_list
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

static spinlock_t lock_tcp_flow_list;

////////////////////////////////////////////////////////////////////////////////////////////////////////////
static int up_bwt=-1;
static int adv_wnd=-1;

//definisce che riceverà in ingresso un parametro quando il programma è eseguito
module_param(up_bwt, int, 0 ); //prende in ingresso il parametro, il suo tipo e i permessi
MODULE_PARM_DESC(up_bwt, "Parametro in ingresso max_bwt"); //descrittore del parametro

//definisce che riceverà in ingresso un parametro quando il programma è eseguito
module_param(adv_wnd, int, 0 ); //prende in ingresso il parametro, il suo tipo e i permessi
MODULE_PARM_DESC(adv_wnd, "Parametro in ingresso const_adv_wnd"); //descrittore del parametro

#endif
