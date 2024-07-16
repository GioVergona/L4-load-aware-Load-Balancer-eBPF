Final project for the Network Computing course at Politecnico di Milano. It's an eBPF program acting as a L4 load aware Load Balancer, identified by a VIP present in the config.yaml file acting such that, upon receiving speciifically UDP packets, it process them in order to add an additional IP header with the the same source IP address of the original packet and as destination the IP address of one of the backend servers still in the config.yaml. It is built so that packets belonging to the same flow will be redirected to the same server to grant consistency (avoiding TCP reordering) whereas if the flow is new it selects the least loaded backend server (*load = #packets/#flows*). After the packet has been enlarged and modified with the new IP header it is redirected on the same interface as it arrived to the load balancer. This scenario is implemented through the use of a Linux namespace.

INSTRUCTIONS

1) put the project folder in "Home/058172-network-computing-labs/ebpf-labs"

2) open 3 shell in "Home/058172-network-computing-labs/ebpf-labs/project"

3) run "./create_topo.sh"

4) run "make"

5) we attach the program on the veth1_ interface on the ns1 by running on one of the shell the command "sudo ip netns exec ns1 ./l4_lb -1 veth1_"

6) to look for debugging information and check the packet is properly processed run on another shell "sudo su" and then "cat /sys/kernel/debug/tracing/trace_pipe"

7) to send packets on the last shell run one of the following commands:

	7.1) "sudo python3 ./send.py -i veth1 -p 1 -f 1" to send on veth1 as many flows as specified in -f, each with -p packets
	
	7.2) "sudo python3 ./send.py -i veth1 -maxp 10 -f 2" to send on veth1 as many flows as specified in -f, each with a random number of packets between 0 and -maxp
	
8) since the program is not retransmitting packets properly using XDP_TX, to see the packets are correctly processed and updated change the line 406 of "l4_lb.bpf.c" into "return XDP_PASS. Then open other two terminal and run wireshark on both virtual interfaces to see both the packets that are sent by veth1 and the ones that are recevied on veth1_ (once modified) running "sudo wireshark" clicking on veth1 and "sudo ip netns exec ns1 wireshark" clicking on veth1_

