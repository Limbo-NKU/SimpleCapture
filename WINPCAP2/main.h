#pragma once
#include<list>
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
/* 4 bytes IP address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

#pragma pack()


static bool IsCapturing = false;
static bool IsDeviceListFreed = true;
static pcap_if_t *alldevs;
static pcap_if_t *d;
static int inum;
static int i = 0;
static pcap_t *adhandle;
static char errbuf[PCAP_ERRBUF_SIZE];
static char if_string[] = PCAP_SRC_IF_STRING;

static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
