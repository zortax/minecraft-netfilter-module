#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops *nfho = NULL;

unsigned int hook_func(
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (ntohs(tcph->dest) == 25565 && !tcph->syn && !tcph->fin && !tcph->rst) {
            int tcph_len = tcph->doff*4;
            unsigned char* payload = (unsigned char *)((unsigned char *)tcph + tcph_len);
            int payload_size = ntohs(iph->tot_len)-ip_hdrlen(skb)-tcph_len;
            
            unsigned char* payload_copy = kcalloc(payload_size*20+1, sizeof(unsigned char), GFP_KERNEL);
            unsigned char* c_pointer = payload_copy;
            int i;
            for (i = 0; i < payload_size; i++) {
                sprintf(c_pointer, "0x%02x ", payload[i]);
                c_pointer += 5;
            }

            printk(KERN_INFO "MC PACKET: tot_len=%d payload_size=%d ip_hdrlen=%d tcph_len=%d data=%s\n", ntohs(iph->tot_len), payload_size, ip_hdrlen(skb), tcph_len,  payload_copy);
            kfree(payload_copy);
            return NF_DROP;
        }

    }
    
    return NF_ACCEPT;
}

static int __init LKM_init(void)
{
    printk(KERN_INFO "Loading minecraft netfilter kernel module!\n");

    nfho = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho->hook = (nf_hookfn*)hook_func;
    nfho->hooknum = NF_INET_PRE_ROUTING;
    nfho->pf = PF_INET;
    nfho->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, nfho);
    return 0;
}

static void __exit LKM_exit(void)
{
    printk(KERN_INFO "Cleaning up minecraft netfilter kernel module...\n");
    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);
