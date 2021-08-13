#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>


int hello(struct __sk_buff *skb) {

	return 0;
}
