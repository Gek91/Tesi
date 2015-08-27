//Header per la programmazione kernel
#include <linux/kernel.h>
#include <linux/module.h>
//Header per la manipolazione dei pacchetti
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#include <net/ip.h>
#include <net/tcp.h>

#include <linux/slab.h> //necessario per la kmalloc
#include <linux/gfp.h> //flag della kmalloc , DA VERIFICARE

static struct nf_hook_ops nfho;

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip  = NULL;
    struct tcphdr *tcp = NULL;
    
    if (!skb)  //se non c'è nessun socket buffer
        return NF_DROP;
    
    ip=ip_hdr(skb);

    if (ip->protocol==6)
    {
        tcp=tcp_hdr(skb);
        
        //printk(KERN_INFO "source %d, dest %d, seq %d, ack_seq %d, resl %d, doff %d, bit %d %d %d %d %d %d ,window %d, check %d, urg_ptr %d, ipsource %d, ipdest %d, iptotleng %d\n",tcp->source,tcp->dest,tcp->seq,tcp->ack_seq,tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh , tcp->ack, tcp->urg, tcp->ece,tcp->window,tcp->check,tcp->urg_ptr, ip->saddr,ip->daddr, ip->tot_len);
        printk(KERN_INFO "PRIMA -- normal : %d | ntohs : %d | htons : %d\n",tcp->check,ntohs(tcp->check),htons(tcp->check));
        
        /*u_int16_t tcplen = skb->len - ip_hdrlen(skb);
        tcp->check = 0;
        tcp->check = tcp_v4_check(tcplen,ip->saddr,ip->daddr,csum_partial((char *)tcp, tcplen, 0));*/
        
        u_int16_t tcplen = (skb->len - (ip->ihl << 2));
        tcp->check = 0;
        tcp->check = tcp_v4_check(tcplen,ip->saddr,ip->daddr, csum_partial((char *)tcp, tcplen, 0));
        skb->ip_summed = CHECKSUM_NONE; //stop offloading
        ip->check = 0;
        ip->check = ip_fast_csum((u8 *)ip, ip->ihl);
        
         //printk(KERN_INFO "source %d, dest %d, seq %d, ack_seq %d, resl %d, doff %d, bit %d %d %d %d %d %d ,window %d, check %d, urg_ptr %d, ipsource %d, ipdest %d, iptotleng %d\n",tcp->source,tcp->dest,tcp->seq,tcp->ack_seq,tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh , tcp->ack, tcp->urg, tcp->ece,tcp->window,tcp->check,tcp->urg_ptr, ip->saddr,ip->daddr, ip->tot_len);
        printk(KERN_INFO "DOPO -- normal : %d | ntohs : %d | htons : %d\n",tcp->check,ntohs(tcp->check),htons(tcp->check));
    }
    
    return NF_ACCEPT; //accetta tutti i pacchetti, possono continuare la loro transazione
}

static int __init mod_init(void)
{
    nfho.hook = hook_func; //definisce la funzione da richiamare nell'hook
    nfho.hooknum =NF_INET_PRE_ROUTING ; //Indica in che punto del protocollo è in ascolto l'hook
    nfho.pf = PF_INET; //definisce la famiglia di protocolli da usare
    nfho.priority = NF_IP_PRI_FIRST; //indica la priorità dell'hook
    
    
    nf_register_hook(&nfho); //registra in ascolto l'hook
    printk(KERN_INFO "Modulo CheckSum caricato\n");
    return 0;
}

static void __exit mod_exit(void)
{
    
    nf_unregister_hook(&nfho); //rilascia l'hook
    printk(KERN_INFO "Modulo CheckSum rimosso\n");
}

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);