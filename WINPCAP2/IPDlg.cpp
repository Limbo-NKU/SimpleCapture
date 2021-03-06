// IPDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "WINPCAP2.h"
#include "IPDlg.h"
#include "afxdialogex.h"


// IPDlg 对话框

IMPLEMENT_DYNAMIC(IPDlg, CDialogEx)

IPDlg::IPDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_IPDLG, pParent)
{

}

IPDlg::~IPDlg()
{
}

void IPDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(IPDlg, CDialogEx)
	ON_MESSAGE(WM_IP_CAPTURED, &IPDlg::OnIpCaptured)
	ON_BN_CLICKED(IDC_BUTTON1, &IPDlg::OnBnClickedButton1)
	ON_WM_SHOWWINDOW()
END_MESSAGE_MAP()


// IPDlg 消息处理程序


afx_msg LRESULT IPDlg::OnIpCaptured(WPARAM wParam, LPARAM lParam)
{
	const struct pcap_pkthdr *header = (const struct pcap_pkthdr *) wParam;
	const u_char *pkt_data = (const u_char *)lParam;

	IPFrame_t *ih = (IPFrame_t*)pkt_data;
	//显示IP数据包捕获日志
	CString str;
	in_addr buf;
	buf.S_un.S_addr = ih->saddr;
	str += inet_ntoa(buf);
	str += "->";
	buf.S_un.S_addr = ih->daddr;
	str += inet_ntoa(buf);
	str += "\r\n";
	CEdit* iplog = (CEdit*)GetDlgItem(IDC_IPLOG);
	int nLength = iplog->GetWindowTextLength();
	iplog->SetSel(nLength, nLength);
	iplog->ReplaceSel(str);
	//发往本机的IP数据包无需转发
	if (ih->daddr == localIP)
		return 0;
	else
	//目标地址不是本机，查询路由表后转发
	{

	}

	return 0;
}


void IPDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	CIPAddressCtrl* destaddr = (CIPAddressCtrl*)GetDlgItem(IDC_DESTIP);
	CIPAddressCtrl* destmask = (CIPAddressCtrl*)GetDlgItem(IDC_DESTMASK);
	CIPAddressCtrl* nexthop = (CIPAddressCtrl*)GetDlgItem(IDC_NEXTHOP);
	if (destaddr->IsBlank() || destmask->IsBlank() || nexthop->IsBlank())
	{
		MessageBox(L"Fill the address, please.");
		return;
	}
	IPRouteNode node;
	destaddr->GetAddress(node.destIP);
	destmask->GetAddress(node.mask);
	nexthop->GetAddress(node.nextHop);
	router.routeTable.push_back(node);
	UpdateRouteTable(node);
}


void IPDlg::UpdateRouteTable(IPRouteNode node)
{
	// TODO: 在此处添加实现代码.
	CListCtrl* table = (CListCtrl*)GetDlgItem(IDC_ROUTETABLE);
	//table->InsertColumn(0,  L"DestIP");
	//table->InsertColumn(1,  L"DestMask");
	//table->InsertColumn(2,  L"NextHop");
	CString buf;
	in_addr addr_buf;
	IPRouteNode* p = &node;
	int i = table->GetItemCount();
		addr_buf.S_un.S_addr = ntohl(p->destIP);
		buf = inet_ntoa(addr_buf);
		table->InsertItem(i, buf);
		addr_buf.S_un.S_addr = ntohl(p->mask);
		buf = inet_ntoa(addr_buf);
		table->SetItemText(i,1, buf);
		addr_buf.S_un.S_addr = ntohl(p->nextHop);
		buf = inet_ntoa(addr_buf);
		table->SetItemText(i,2, buf);

}


void IPDlg::OnShowWindow(BOOL bShow, UINT nStatus)
{
	CDialogEx::OnShowWindow(bShow, nStatus);

	// TODO: 在此处添加消息处理程序代码
	CListCtrl* table = (CListCtrl*)GetDlgItem(IDC_ROUTETABLE);
	CRect rect;
	table->GetWindowRect(&rect);
	table->InsertColumn(0, L"DestIP",0,rect.Width()/3);
	table->InsertColumn(1, L"DestMask", 0, rect.Width()/3);
	table->InsertColumn(2, L"NextHop", 0, rect.Width()/3);

}
