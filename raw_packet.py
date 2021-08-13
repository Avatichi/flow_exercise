from bcc import BPF

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct urandom_read_args {
    // from /sys/kernel/debug/tracing/events/random/urandom_read/format
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
};

int printarg(struct urandom_read_args *args) {
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
};
int hello(struct __sk_buff *skb) {

	return 0;
}

"""

# load BPF program
#b = BPF(text=bpf_text)

b = BPF(src_file="test.c")
#b.attach_tracepoint("random:urandom_read", "printarg")

fn=b.load_func("hello", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(fn, "eth0")
