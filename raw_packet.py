from bcc import BPF


b = BPF(src_file="test.c")


#b.attach_tracepoint("random:urandom_read", "printarg")

fn=b.load_func("hello", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(fn, "lo")

