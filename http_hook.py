from __future__ import print_function
from socket import inet_ntop, AF_INET
from struct import pack
from bcc import BPF


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>

struct data_t {
    u8 pkt[100];
    u8 dport;
    u8 lport;
};

BPF_PERF_OUTPUT(packet_msg);

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 zero = 0;
    struct msghdr *i_msghdr = msg;
    size_t buflen = 0;

    
    u16 l_dport = sk->__sk_common.skc_dport;
    u16 l_lport = sk->__sk_common.skc_num;
    u16 lport= ntohs(l_lport);    
    u16 dport= ntohs(l_dport);

    if (dport != 80 || lport != 80) 
        return 0;

    struct data_t data= {0};

    data.dport = dport;
    data.lport = lport;

    void *iovbase = msg->msg_iter.iov->iov_base;
    bpf_probe_read(data.pkt, 50, iovbase);
    packet_msg.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""
def print_packet(cpu, data, size):
    event = b["packet_msg"].event(data)
    payload = event.pkt
    print(payload[0])


b = BPF(text=bpf_text)
b.attach_kretprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")

b["packet_msg"].open_perf_buffer(print_packet)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

