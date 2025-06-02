#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_CPUS 32

// Size: 8 bytes
struct flow_key_t {
    __u32 src_ip_be;
    __u16 src_port_be;
    __u16 dst_port_be;
};

// Size: 16 bytes
struct flow_entry_t {
    __u64 timestamp_ns;
    __u32 dst_ip_be;
    __u16 dst_port_be;
    __u16 src_port_be;
};

// Clang generates FWD types for the above without these...
struct flow_key_t key __attribute__((unused));
struct flow_entry_t entry __attribute__((unused));

struct flows_t {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key_t);
    __type(value, struct flow_entry_t);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_CPUS + 1);
    __type(key, __u32);
    __array(values, struct flows_t);
} per_cpu_flows SEC(".maps");

SEC("xdp")
int test(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
