#include "stdafx.h"
#include "main.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	packet_handler_static(param, header, pkt_data);
}

// pcap_loop 捕获到一个包后将包数据复制一份 并 发出WM_TCATCH消息
static void packet_handler_static(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct pcap_pkthdr *new_header = new struct pcap_pkthdr;
	u_char *new_data = new u_char[header->len];

	// 复制数据, 发出消息
	*new_header = *header;
	memcpy(new_data, pkt_data, header->len);
	AfxGetApp()->m_pMainWnd->PostMessage(WM_PACKAGE_CAPTURED, (WPARAM)new_header, (LPARAM)new_data);
}

void ARP_packet_handler(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{
	ARP_packet_handler_static(param, header, pkt_data);
}

void ARP_packet_handler_static(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{

	struct FrameHeader_t *fh = (FrameHeader_t*)pkt_data;
	if (fh->FrameType == ntohs(0x0806))
	{
		struct pcap_pkthdr *new_header = new struct pcap_pkthdr;
		u_char *new_data = new u_char[header->len];
		// 复制数据, 发出消息
		*new_header = *header;
		memcpy(new_data, pkt_data, header->len);
		//AfxGetApp()->m_pActiveWnd->PostMessage(WM_ARP_CAPTURED, (WPARAM)new_header, (LPARAM)new_data);
		AfxGetApp()->m_pMainWnd->PostMessage(WM_ARP_CAPTURED, (WPARAM)new_header, (LPARAM)new_data);
	}
}

void IP_packet_handler(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{
	ARP_packet_handler_static(param, header, pkt_data);
}

void IP_packet_handler_static(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{

	struct FrameHeader_t *fh = (FrameHeader_t*)pkt_data;
	if (fh->FrameType == ntohs(0x0800))
	{
		struct pcap_pkthdr *new_header = new struct pcap_pkthdr;
		u_char *new_data = new u_char[header->len];
		// 复制数据, 发出消息
		*new_header = *header;
		memcpy(new_data, pkt_data, header->len);
		//AfxGetApp()->m_pActiveWnd->PostMessage(WM_ARP_CAPTURED, (WPARAM)new_header, (LPARAM)new_data);
		AfxGetApp()->m_pMainWnd->PostMessage(WM_IP_CAPTURED, (WPARAM)new_header, (LPARAM)new_data);
	}
}


//bool send_ARP(BYTE sourceMAC[], DWORD sourceIP, DWORD destIP)
//{
//	return send_ARP_static(sourceMAC, sourceIP, destIP);
//}
//
//static bool send_ARP_static(BYTE sourceMAC[], DWORD sourceIP,DWORD destIP)
//{
//	ARPFrame_t package;
//	for (int i = 0; i <6 ; i++)
//	{
//		package.FrameHeader.SrcMac[i] = sourceMAC[i];
//		package.SendHa[i] = sourceMAC[i];
//	}
//	memset(package.FrameHeader.DesMac, 0xff, sizeof(package.FrameHeader.DesMac));
//	package.FrameHeader.FrameType = htons(0x0806);
//	package.HardwareType = htons(0x0001);
//	package.ProtocolType = htons(0x0800);
//	package.HLen = 6;
//	package.PLen = 4;
//	package.Operation = htons(0x0001);
//	package.SendIP = sourceIP;
//	memset(package.RecvHa, 0, sizeof(package.RecvHa));
//	package.RecvIP = destIP;
//	if (pcap_sendpacket(adhandle, (u_char*)&package, sizeof(package)) != 0)
//	{
//		return false;
//	}
//	return true;
//}
