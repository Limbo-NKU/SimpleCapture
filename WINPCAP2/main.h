#pragma once
#include <list>
#include "pcap.h"
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif // !HAVE_REMOTE
#include <remote-ext.h>


#pragma pack(1)
typedef struct FrameHeader_t
{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	WORD FrameType;
}FrameHeader_t;
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;
typedef struct IPFrame_t {
	FrameHeader_t FrameHeader;
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	DWORD  saddr;      // Source address
	DWORD  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}IPFrame_t;

#pragma pack()

struct ARPNode
{
	BYTE MacAddr[6];
	DWORD IPAddr;
};

//static bool IsCapturing = false;
//static bool IsDeviceListFreed = true;
//static pcap_if_t *alldevs;
//static pcap_if_t *d;
//static int inum;
//static int i = 0;
//static pcap_t *adhandle;
//static char errbuf[PCAP_ERRBUF_SIZE];
//static char if_string[] = PCAP_SRC_IF_STRING;
static std::list<ARPNode> ARPTable;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
static void packet_handler_static(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void ARP_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
static void ARP_packet_handler_static(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void IP_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
static void IP_packet_handler_static(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//bool send_ARP(BYTE sourceMAC[],DWORD sourceIP,DWORD destIP);
//static bool send_ARP_static(BYTE sourceMAC[], DWORD sourceIP, DWORD destIP);
//
