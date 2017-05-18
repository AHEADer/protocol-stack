#include "utils.h"
char *get_interface_name()
{
    struct ifaddrs *ifa = NULL, *ifList;
    char *interface_name = (char *)malloc(sizeof(char) * 12);
    interface_name[0] = '\0';

    if (getifaddrs(&ifList) < 0)
    {
        return NULL;
    }

    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr->sa_family == AF_INET)
        {
            if (strlen(interface_name) == 0)
                strcpy(interface_name, ifa->ifa_name);
            else
                if (strcmp(interface_name, ifa->ifa_name) > 0)
                    strcpy(interface_name, ifa->ifa_name);
        }
    }

    freeifaddrs(ifList);
    return interface_name;
}

int get_lo_interface_num(int listen_socket)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, "lo");
    if (ioctl(listen_socket, SIOCGIFINDEX, &ifr) == -1) {
        fprintf(stderr ,"ioctl error,no such interface\n");
        close(listen_socket);
        exit(-1);
    }
    return ifr.ifr_ifindex;
}
/*
int get_mac_address(char* device_name, unsigned char* mac_buf)
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)  return -1;
    strcpy(ifr.ifr_name, device_name);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
        return -1;
    strcpy((char *)mac_buf, ifr.ifr_hwaddr.sa_data);
    return 1;
}*/