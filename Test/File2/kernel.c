//Header per la programmazione kernel
#include <linux/kernel.h>
#include <linux/module.h>
//Header per la manipolazione dei pacchetti
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17


struct sock *nl_sk = NULL;
static struct nf_hook_ops nfho;

int pid;
int tot_pkt_count;

typedef struct {
    int count;
    int prot;
}message;


unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip  = NULL;
    
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out; //Buffer messaggio di uscita
    int msg_size;
    int res;
    message m;
    
    
    if (!skb)  //se non c'è nessun socket buffer
        return NF_DROP;
    
    tot_pkt_count++; //aggiorna il contatore dei pacchetti
    
    if(pid!=-1)
    {
        ip=ip_hdr(skb);
        
        if (ip->protocol==17)
        {
            m.count=tot_pkt_count;
            m.prot = 17;
            
            msg_size = sizeof(m); //Grandezza del messaggio
            skb_out = nlmsg_new(msg_size, 0); //Crea il messaggio
            if (!skb_out)
            {
                printk(KERN_INFO "Failed to allocate new skb\n");
                return;
            }
            
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; //Messaggio unicast
            memcpy(nlmsg_data(nlh), &m, msg_size); //Copia il messaggio
            
            res = nlmsg_unicast(nl_sk, skb_out, pid); //Invia il messaggio per il socket
            if (res < 0)
                printk(KERN_INFO "Error while sending back to user TCP\n");
        }
        
        if(ip->protocol==6)
        {
            m.count=tot_pkt_count;
            m.prot = 6;
            
            msg_size = sizeof(m); //Grandezza del messaggio
            skb_out = nlmsg_new(msg_size, 0); //Crea il messaggio
            if (!skb_out)
            {
                printk(KERN_INFO "Failed to allocate new skb\n");
                return;
            }
            
            nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
            NETLINK_CB(skb_out).dst_group = 0; //Messaggio unicast
            memcpy(nlmsg_data(nlh), &m, msg_size); //Copia il messaggio
            
            res = nlmsg_unicast(nl_sk, skb_out, pid); //Invia il messaggio per il socket
            if (res < 0)
                printk(KERN_INFO "Error while sending back to user UDP\n");
        }
    }
    return NF_ACCEPT;
    
}


static void recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    
    nlh = (struct nlmsghdr *)skb->data; //Riceve il messaggio
    printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    if(pid==-1)
        pid = nlh->nlmsg_pid; // Pid del processo che ha inviato il messaggio
    else
        pid=-1;
}

static int __init mod_init(void)
{
    nfho.hook = hook_func; //definisce la funzione da richiamare nell'hook
    nfho.hooknum =NF_INET_PRE_ROUTING ; //Indica in che punto del protocollo è in ascolto l'hook
    nfho.pf = PF_INET; //definisce la famiglia di protocolli da usare
    nfho.priority = NF_IP_PRI_FIRST; //indica la priorità dell'hook
    
    tot_pkt_count=0;
    pid=-1;
    
    struct netlink_kernel_cfg cfg = {
        .input = recv_msg,
    };
    
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg); //Crea il socket
    if (!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }
    
    nf_register_hook(&nfho); //registra in ascolto l'hook
    
    printk(KERN_INFO "Modulo File caricato\n");
    
    return 0;
}

static void __exit mod_exit(void)
{
    nf_unregister_hook(&nfho); //rilascia l'hook
    netlink_kernel_release(nl_sk); //Rilascia il socket
    printk(KERN_INFO "Modulo File rimosso\n");
}

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);