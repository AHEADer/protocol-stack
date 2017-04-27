#include <stdio.h>
//#include <pcap.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <net/ethernet.h> /* the L2 protocols */
#include "utils.h"

#define SIZE 1024
char *get_interface_name();

int main(int argc, char *argv[])
{
	if (argc==1)
	{
		fprintf(stderr, "need argument\n");
	}
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
    char buffer[SIZE];
    //printf("%s\n", argv[1]);
    if (argv[1][0]=='1')
    {
    	/*if (sendto(fd, buffer, SIZE, 0, (struct sockaddr *) &eth_addr ,sizeof(struct sockaddr_ll)) == -1 )
    	{
        	fprintf(stderr ,"sendto error\n");
        	return -1;
    	}*/

    	connect(fd, (struct sockaddr *)&eth_addr, sizeof(struct sockaddr_ll));
    	strcpy(buffer, "happy");
    	write(fd, buffer, SIZE);
    }
    else
    {
    	fprintf(stderr, "listening:\n");
    		/*if(recvfrom(fd, buffer, SIZE, 0, (struct sockaddr *) &eth_addr, )>0)
    			printf("buff is %s\n", buffer);*/
    	//listen(fd, )
    }
    
	return(0);
}
