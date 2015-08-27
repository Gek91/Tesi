//Header per la programmazione kernel
#include <linux/kernel.h>
#include <linux/module.h>
//Header per la manipolazione dei pacchetti
#include <linux/skbuff.h>

#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17


struct sock *nl_sk = NULL;

static void hello_nl_recv_msg(struct sk_buff *skb)
{
    
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out; //Buffer messaggio di uscita
    int msg_size;
    char *msg = "Hello from kernel";
    int res;
    
    
    nlh = (struct nlmsghdr *)skb->data; //Riceve il messaggio
    printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    
    pid = nlh->nlmsg_pid; // Pid del processo che ha inviato il messaggio
    msg_size = strlen(msg); //Grandezza del messaggio
    skb_out = nlmsg_new(msg_size, 0); //Crea il messaggio
    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; //Messaggio unicast
    strncpy(nlmsg_data(nlh), msg, msg_size);
    
    res = nlmsg_unicast(nl_sk, skb_out, pid); //Invia il messaggio per il socket
    if (res < 0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static int __init mod_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = hello_nl_recv_msg,
    };
    
    printk(KERN_INFO "Modulo File caricato\n");
    
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg); //Crea il socket
    
    if (!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }
    return 0;
}

static void __exit mod_exit(void)
{
    netlink_kernel_release(nl_sk); //Rilascia il socket
    printk(KERN_INFO "Modulo File rimosso\n");
}

//Definiscono le funzioni di inizializzazione e di terminazione
module_init(mod_init);
module_exit(mod_exit);