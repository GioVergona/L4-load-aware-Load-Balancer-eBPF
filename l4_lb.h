#ifndef L4_LB_H_
#define L4_LB_H_

#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include <cyaml/cyaml.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/ether.h>

// #include <netlink/netlink.h>
// #include <netlink/route/addr.h>
// #include <netlink/route/link.h>
// #include <netlink/route/qdisc.h>
// #include <netlink/socket.h>

#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "log.h"

// Include skeleton file
#include "l4_lb.skel.h"

static int ifindex_iface1 = 0;
static __u32 xdp_flags = 0;

struct ip {
    const char *ip;
};

struct backends {
    const char *vip;
    struct ip *backends;
    uint64_t backends_count;
};

static const cyaml_schema_field_t ip_field_schema[] = {
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct ip, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t ip_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct ip, ip_field_schema),
};

static const cyaml_schema_field_t backends_field_schema[] = {
    CYAML_FIELD_STRING_PTR("vip", CYAML_FLAG_POINTER, struct ip, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE("backends", CYAML_FLAG_POINTER, struct backends, backends, &ip_schema, 0,CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t backends_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct backends, backends_field_schema),
};

static const cyaml_config_t config = {
    .log_fn = cyaml_log,            /* Use the default logging function. */
    .mem_fn = cyaml_mem,            /* Use the default memory allocator. */
    .log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_iface1 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface1, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface1, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface1);
            }
        }
    }

}

int attach_bpf_progs(unsigned int xdp_flags, struct l4_lb_bpf *skel) {
    int err = 0;
    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.l4_lb), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 1st XDP program to the interface");
        return err;
    }

    return 0;
}

static void get_iface_ifindex(const char *iface1) {
    if (iface1 == NULL) {
        log_warn("No interface specified, using default one (veth1)");
        iface1 = "veth1";
    }

    log_info("XDP program will be attached to %s interface", iface1);
    ifindex_iface1 = if_nametoindex(iface1);
    if (!ifindex_iface1) {
        log_fatal("Error while retrieving the ifindex of %s", iface1);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface1, ifindex_iface1);
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

#endif // L4_LB_H
