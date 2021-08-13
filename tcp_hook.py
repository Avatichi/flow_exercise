from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
struct ipv4_key_t {
    u32 pid;
    u32  msg[1000];
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);



int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct ipv4_key_t ipv4_key = {.pid = pid};
    memcpy(ipv4_key.msg, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
    ipv4_send_bytes.increment(ipv4_key, size);

    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ipv4_key_t ipv4_key = {.pid = pid};
    ipv4_recv_bytes.increment(ipv4_key, copied);

    return 0;
}
"""


b = BPF(text=bpf_text)

ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]
result_tuple = namedtuple('TCPSession', ['pid'])

while 1:
    for k, v in ipv4_recv_bytes.items():
        result = result_tuple(k)
        print(result[0].pid)
        ipv4_recv_bytes.clear()

    for k, v in ipv4_send_bytes.items():
        result = result_tuple(k)
        print(result[0].pid)

        # print(k)
        ipv4_recv_bytes.clear()


