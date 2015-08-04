
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;   //net filter hook option struct
int counter=0;
int tcpcounter=0;
int udpcounter=0;

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    
    struct iphdr    *ip  = NULL;
    struct udphdr   *udp = NULL;
    struct tcphdr *tcp = NULL;
    
    counter++;
    
    if (!skb)  //se non c'è nessun socket buffer
        return NF_ACCEPT;
    
    ip=ip_hdr(skb); //prende dal socket buffer l'header ip e lo salva nella struttura adatta
    printk(KERN_INFO "Header IP \t source: %d \t destination: %d \n",ip->saddr,ip->daddr);
    
    if(ip->protocol == 17) //se è UDP
    {
        udpcounter++;
        udp=udp_hdr(skb);
        printk(KERN_INFO "Pacchetto UDP \t source:%d \t destination:%d\n",udp->source,udp->dest);
    }
    
    if(ip->protocol == 6) //se è TCP
    {
        tcpcounter++;
        tcp=tcp_hdr(skb);
        printk(KERN_INFO "Pacchetto TCP \t source:%d \t destination:%d\n",tcp->source,tcp->dest);
    }
    
    return NF_ACCEPT; //accetta tutto
}

int init_module()
{
    nfho.hook = hook_func;
    nfho.hooknum =NF_INET_PRE_ROUTING ;;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    
    nf_register_hook(&nfho);
    printk(KERN_INFO "Modulo caricato\n");
    return 0;
}

void cleanup_module()
{
    nf_unregister_hook(&nfho);
    
   	printk(KERN_INFO "Modulo scaricato\n");
    printk(KERN_INFO "Numero pacchetti: %d \n",counter);
    printk(KERN_INFO "Numero pacchetti UDP: %d \n",udpcounter);
    printk(KERN_INFO "Numero pacchetti TCP: %d \n",tcpcounter);
}
