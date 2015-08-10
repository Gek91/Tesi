
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

static struct nf_hook_ops nfho;   //Struttura dati Netfilter

//Strutture dati per la manipolazione dei pacchetti
struct iphdr *ip  = NULL;
struct udphdr *udp = NULL;
struct tcphdr *tcp = NULL;

//Hook utilizzato da Netfilter
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{

}

//Funzione di inizializzazione del modulo, __init indica che è utilizzata solo per quello
static int __init mod_init(void)
{
    printk(KERN_INFO "Hello, world \n");
    return 0;
}


//Funzione di terminazione del modulo, __exit definisce che è utilizzata solo per quello
static void __exit mod_exit(void)
{
    printk(KERN_INFO "Goodbye, world! \n");
}

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);

//Definiscono delle informazioni riguardati in modulo
MODULE_AUTHOR("Giacomo Pandini");
MODULE_DESCRIPTION("SLK, Sap-Law Kerel");
MODULE_LICENSE("Take away pizza");