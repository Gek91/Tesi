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


#define DEBUG 1



#define SLUS_TRAFFIC_STAT_TIMER_UP 3000
#define SLUS_TRAFFIC_STAT_TIMER_DOWN 1500