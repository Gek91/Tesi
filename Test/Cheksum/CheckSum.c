//Header per la programmazione kernel
#include <linux/kernel.h>
#include <linux/module.h>
//Header per la manipolazione dei pacchetti
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#include <linux/slab.h> //necessario per la kmalloc
#include <linux/gfp.h> //flag della kmalloc , DA VERIFICARE

static struct nf_hook_ops nfho;

static u_int16_t slk_calc_chksum_buf(u_int16_t *packet, int packlen) {
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

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip  = NULL;
    struct tcphdr *tcp = NULL;
    
    if (!skb)  //se non c'è nessun socket buffer
        return NF_DROP;

    ip=ip_hdr(skb);
    
    //printk(KERN_INFO "normal : %d | ntohs : %d",ip->protocol,ntohs(ip->protocol));
    //printk(KERN_INFO "normal : %d | ntohs : %d\n",ip->tot_len,ntohs(ip->tot_len));

    if (ip->protocol==6)
    {
        tcp=tcp_hdr(skb);
        
        printk(KERN_INFO "PRIMA -- normal : %d | ntohs : %d\n",tcp->check,ntohs(tcp->check));

        u_int16_t tcp_tot_len = ntohs( (u_int16_t) ip->tot_len) - 20; //calcola lunghezza segmento TCP
        u8 *buf=kmalloc(12 + tcp_tot_len,GFP_KERNEL); //buffer contenente lo pseudo header TCP(12 byte)
        
        //Inizializzazione dello pseudo header
        (void *)memcpy(buf, &(ip->saddr), sizeof(u_int32_t));	// Indirizzo di provenienza IP dello pseudo header
        (void *)memcpy(&(buf[4]), &(ip->daddr), sizeof(u_int32_t));	// Indirizzo di destinazione IP dello pseud header
        buf[8] = 0;							// Reserved location dello pseudo header
        buf[9] = ip->protocol;			// Protocollo di trasporto dello pseudo header
        buf[10]=(u_int16_t)((tcp_tot_len) & 0xFF00) >> 8;	// Lunghezza totale header TCP salvata sullo pseudo header
        buf[11]=(u_int16_t)((tcp_tot_len) & 0x00FF);
        
        tcp->check = 0; //imposto il valore del check a 0 per il suo ricalcolo
        (void *)memcpy(buf + 12, tcp, tcp_tot_len ); //copio il pacchetto tcp nel buffer
        tcp->check = slk_calc_chksum_buf((u_int16_t *)buf, 12 + tcp_tot_len) ; //Ricalcolo del checksum
        kfree(buf); //libera la memoria allocata
        printk(KERN_INFO "DOPO -- normal : %d | ntohs : %d\n",tcp->check,ntohs(tcp->check));
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