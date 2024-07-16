// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>
#include "l4_lb.h"
#include "log.h"

typedef struct{
        __uint32_t backend_ip; 
		__uint16_t flows_count;
		__uint16_t pkts_count;
		__uint16_t load;
} backend_info;

static const char *const usages[] = {
    "l4_lb [options] [[--] args]",
    "l4_lb [options]",
    NULL,
};

int load_maps_config(struct l4_lb_bpf *skel, const char *config_file) {
    
    struct backends *backends;
    cyaml_err_t err;
    int ret = EXIT_SUCCESS;

    /* Load input file. */
    err = cyaml_load_file(config_file, &config, &backends_schema, (void **)&backends, NULL);
    if (err != CYAML_OK) {
        fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
        return EXIT_FAILURE;
    }

    log_info("Loaded %d backends' IPs", backends->backends_count);

    //Get fd of ipv4_lookup_map
    int flow_packets_count_lookup_map_fd = bpf_map__fd(skel->maps.flow_packets_count_map);

    //Check if the file descriptor is valid
    if (flow_packets_count_lookup_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    backend_info val;  // struct to initialize every flow_map entry to 0
    val.flows_count = 0;
    val.pkts_count =  0;
    val.load = 0;
    struct in_addr addr;

    int total_backends_fd = bpf_map__fd(skel->maps.number_of_backends);
    if (total_backends_fd<0){
        log_error("FAILED ON SETTING MAXIMUM BACKENDS");
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    int index = 0; 
    ret = bpf_map_update_elem(total_backends_fd, &index, &backends->backends_count, BPF_ANY);
    if (ret != 0)
    {
        log_error("ERROR ON UPDATE");
    }
    log_info("Total number of backends inserted in a map");

    for (int i = 0; i < backends->backends_count; i++) {
        log_info("Loading IP %s", backends->backends[i].ip);
        
        // Convert the IP to an integer
        
        int ret = inet_pton(AF_INET, backends->backends[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", backends->backends[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }
        
        val.backend_ip = addr.s_addr; 

        ret = bpf_map_update_elem(flow_packets_count_lookup_map_fd, &i, &val, BPF_ANY);
        if (ret != 0) {
             log_error("Failed to update BPF map: %s", strerror(errno));
             ret = EXIT_FAILURE;
             goto cleanup_yaml;
         }
    }

    struct in_addr addr2;
    ret = inet_pton(AF_INET, backends->vip, &addr2);
    if (ret != 1) {
        log_error("Failed to convert IP %s to integer", backends->vip);
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }
    else{
        ret = EXIT_SUCCESS;
    }
    
    uint32_t vip = ntohl(addr2.s_addr);
    log_info("VIP (in integer) is %u", vip);
    // Get fd of ipv4_lookup_map
    int vip_fd = bpf_map__fd(skel->maps.vip_map);
    int key = 0; 
    int err_map = bpf_map_update_elem(vip_fd, &key, &vip, BPF_ANY);
    if (err_map != 0){
        log_error("ERROR while reading the map");
        exit(1);
    }
    log_info("VIP inserted in a map");

    cleanup_yaml:
    /* Free the data */
    cyaml_free(&config, &backends_schema, backends, 0);

    return ret;

}

int main(int argc, const char **argv) {
    struct l4_lb_bpf *skel = NULL;
    int err;
    const char *config_file = NULL;
    const char *iface1 = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('c', "config", &config_file, "Path to the YAML configuration file", NULL, 0, 0),
        OPT_STRING('1', "iface1", &iface1, "1st interface where to attach the BPF program", NULL, 0, 0),  
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse,
                      "\n[PROJECT]",
                      "\nciao");
    argc = argparse_parse(&argparse, argc, argv);

    if (config_file == NULL) {
        log_warn("Use default configuration file: %s", "config.yaml");
        config_file = "config.yaml";
    }

    /* Check if file exists */
    if (access(config_file, F_OK) == -1) {
        log_fatal("Configuration file %s does not exist", config_file);
        exit(1);
    }

    get_iface_ifindex(iface1);

    /* Open BPF application */
    skel = l4_lb_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.l4_lb, BPF_PROG_TYPE_XDP);

    /* Load and verify BPF programs */
    if (l4_lb_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    err = load_maps_config(skel, config_file);
    if (err){
        log_fatal("Error while loading maps configuration");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    err = attach_bpf_progs(xdp_flags, skel);
    if (err) {
        log_fatal("Error while attaching BPF programs");
        goto cleanup;
    }

    log_info("Successfully attached!");

    sleep(10000);
    
cleanup:
    cleanup_ifaces();
    l4_lb_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}
