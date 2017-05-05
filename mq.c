#include <mqueue.h>
#include <stdio.h>

int main(int argc, char const *argv[])
{
    int c, flags;
    flags = O_RDWR|O_CREAT;
    mqd_t mqd;
    mqd = mq_open("ip_list", flags);
    while(1);
    return 0;
}