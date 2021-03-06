// ARPDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "WINPCAP2.h"
#include "ARPDlg.h"
#include "afxdialogex.h"
#include "main.h"


// ARPDlg 对话框

IMPLEMENT_DYNAMIC(ARPDlg, CDialogEx)

ARPDlg::ARPDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ARPDLG, pParent)
{

}

ARPDlg::~ARPDlg()
{
}

void ARPDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(ARPDlg, CDialogEx)
	ON_WM_ACTIVATE()
	ON_MESSAGE(WM_ARP_CAPTURED, &ARPDlg::OnArpCaptured)
	ON_BN_CLICKED(IDC_GETADDRESS, &ARPDlg::OnBnClickedGetaddress)
	ON_BN_CLICKED(IDCANCEL, &ARPDlg::OnBnClickedCancel)
	ON_WM_SHOWWINDOW()
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// ARPDlg 消息处理程序
UINT ARPThreadProc(LPVOID param)
{
	pcap_t* adhandle = (pcap_t*)param;
	// 循环捕获包, 循环可以被 pcap_breakloop 终止
	int loopreturn = pcap_loop(adhandle, 0, ARP_packet_handler, NULL);

	// 退出前发出 WM_TEXIT 消息
	AfxGetApp()->m_pMainWnd->PostMessage(WM_TEXIT, loopreturn, NULL);

	return 0;
}


void ARPDlg::OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized)
{
	CDialogEx::OnActivate(nState, pWndOther, bMinimized);

	// TODO: 在此处添加消息处理程序代码
}



LRESULT ARPDlg::OnArpCaptured(WPARAM wParam, LPARAM lParam)
{
	const struct pcap_pkthdr *header = (const struct pcap_pkthdr *) wParam;
	const u_char *pkt_data = (const u_char *)lParam;

		ARPFrame_t *ah = (ARPFrame_t*)pkt_data;
		if (ah->RecvIP == IP_Addr)
		{
			CString info;
			char buf[256];
			in_addr sendip;
			sendip.S_un.S_addr = ah->SendIP;
			info += inet_ntoa(sendip);
			info += "->";
			for (int i = 0; i < 6; i++)
			{
				sprintf_s(buf, "%02x", ah->SendHa[i]);
				info += buf;
				if (i != 5)
				{
					//printf("-");
					info += '-';
				}
			}
			info += "\r\n";
			CEdit* arplog = (CEdit*)GetDlgItem(IDC_ARPLOG);
			int nLength = arplog->GetWindowTextLength();
			//选定当前文本的末端
			arplog->SetSel(nLength, nLength);
			//l追加文本
			arplog->ReplaceSel(info);
		}
	

	return 0;
}


void ARPDlg::OnBnClickedGetaddress()
{
	// TODO: 在此添加控件通知处理程序代码
	CIPAddressCtrl* ipaddr_ctrl = (CIPAddressCtrl*)GetDlgItem(IDC_IPADDRESS);
	DWORD destIP;
	ipaddr_ctrl->GetAddress(destIP);
	in_addr addr;
	addr.S_un.S_addr = ntohl(destIP);
	CString addr_s;
	addr_s = "目的IP地址：";
	addr_s += inet_ntoa(addr);
	//MessageBox(addr_s);
	addr_s = "目的IP地址：";
	addr.S_un.S_addr = IP_Addr;
	addr_s = inet_ntoa(addr);
	//MessageBox(addr_s);
	ARPFrame_t package;
	for (int i = 0; i <6; i++)
	{
		package.FrameHeader.SrcMac[i] = MAC_Addr[i];
		package.SendHa[i] = MAC_Addr[i];
	}
	memset(package.FrameHeader.DesMac, 0xff, sizeof(package.FrameHeader.DesMac));
	package.FrameHeader.FrameType = htons(0x0806);
	package.HardwareType = htons(0x0001);
	package.ProtocolType = htons(0x0800);
	package.HLen = 6;
	package.PLen = 4;
	package.Operation = htons(0x0001);
	package.SendIP = IP_Addr;
	memset(package.RecvHa, 0, sizeof(package.RecvHa));
	package.RecvIP = ntohl(destIP);
	pcap_sendpacket(adhandle, (u_char*)&package, sizeof(package));
}


void ARPDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnCancel();
}


void ARPDlg::OnShowWindow(BOOL bShow, UINT nStatus)
{
	CDialogEx::OnShowWindow(bShow, nStatus);

	// TODO: 在此处添加消息处理程序代码
	CEdit* info_edit = (CEdit *)GetDlgItem(IDC_INFO);
	CString info;
	GetDlgItemText(IDC_INFO, info);
	info += name;
	info += "\r\n";
	info += description;
	info += "\r\n";
	char buf[256];
	for (int i = 0; i < 6; i++)
	{
		sprintf_s(buf, "%02x", MAC_Addr[i]);
		info += buf;
		if (i != 5)
		{
			//printf("-");
			info += '-';
		}
	}
	info += "\r\n";
	info += IP_Addr_s;
	SetDlgItemText(IDC_INFO, info);
	AfxBeginThread(ARPThreadProc, adhandle, THREAD_PRIORITY_NORMAL);

}


void ARPDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	pcap_breakloop(adhandle);
	CDialogEx::OnClose();
}
