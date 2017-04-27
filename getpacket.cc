#include <stdio.h>
//#include <pcap.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <net/ethernet.h> /* the L2 protocols */
#include "utils.h"

char *get_interface_name();

int main(int argc, char *argv[])
{
	int fd;
	fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		fprintf(stderr, "Failed to create socket, permission denied\n");
	//printf("%s\n", get_interface_name());
	struct sockaddr_ll eth_addr;
	memset(&eth_addr, 0, sizeof(struct sockaddr_ll));//initial struct
	eth_addr.sll_family = AF_PACKET;
	eth_addr.sll_protocol = htons(ETH_P_ALL);
	eth_addr.sll_ifindex = get_lo_interface_num(fd);

	if (bind(fd, (struct sockaddr *)&eth_addr, sizeof(struct sockaddr_ll)) < 0)
    {
        fprintf(stderr ,"bind error\n");
        exit(-1);
    }
    //connect()
	return(0);
}
