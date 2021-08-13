

from bcc import BPF

bpf_text = """

int http_filter(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}


"""

b = BPF(text=bpf_text)


#u = USDT(pid=int(pid))
#u = BPF(text=bpf_text)




function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)


BPF.attach_raw_socket(function_http_filter, interface)
socket_fd = function_http_filter.sock

