
// WINPCAP2Dlg.cpp: 实现文件
//

#include "stdafx.h"
#include "WINPCAP2.h"
#include "WINPCAP2Dlg.h"
#include "afxdialogex.h"
#include "main.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CWINPCAP2Dlg 对话框



CWINPCAP2Dlg::CWINPCAP2Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_WINPCAP2_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CWINPCAP2Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CWINPCAP2Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_PACKAGE_CAPTURED, &CWINPCAP2Dlg::OnPackageCaptured)
	ON_BN_CLICKED(IDC_GETDEVICE, &CWINPCAP2Dlg::OnBnClickedGetdevice)
	ON_CBN_SELCHANGE(IDC_DEVICELIST, &CWINPCAP2Dlg::OnCbnSelchangeDevicelist)
	ON_BN_CLICKED(IDC_CAPTURE, &CWINPCAP2Dlg::OnBnClickedCapture)
END_MESSAGE_MAP()


// CWINPCAP2Dlg 消息处理程序

BOOL CWINPCAP2Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CWINPCAP2Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CWINPCAP2Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CWINPCAP2Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CWINPCAP2Dlg::OnBnClickedGetdevice()
{
	// TODO: 在此添加控件通知处理程序代码
	

	if (!IsDeviceListFreed&&alldevs)
	{
		pcap_freealldevs(alldevs);
		IsDeviceListFreed = true;
	}

	/* Retrieve the device list on the local machine */
	IsDeviceListFreed = false;
	if (pcap_findalldevs_ex(if_string, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	CComboBox *device_list_box = (CComboBox*) GetDlgItem(IDC_DEVICELIST);
	for (d = alldevs; d; d = d->next)
	{
		CString *name;
		if (d->description)
		{
			name=new CString(d->description);
		}
		else
		{
			name = new CString(d->name);
		}
		device_list_box->AddString(*name);
	}
	CWnd *capture_btn = (CWnd *)GetDlgItem(IDC_CAPTURE);
	capture_btn->EnableWindow(true);
}


void CWINPCAP2Dlg::OnCbnSelchangeDevicelist()
{
	// TODO: 在此添加控件通知处理程序代码
	
	//get current selection
	CComboBox *device_list_box = (CComboBox*)GetDlgItem(IDC_DEVICELIST);
	inum = device_list_box->GetCurSel();
	for (d = alldevs, i = 0; i < inum; d = d->next, i++);
	//open selected device
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		//fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		CString str = L"Error opening device.";
		SetDlgItemText(IDC_NOWDEVICE, str);
		CWnd *capture_btn = (CWnd *)GetDlgItem(IDC_CAPTURE);
		capture_btn->EnableWindow(false);
		return ;
	}
	CString str;
	GetDlgItemText(IDC_NOWDEVICE, str);
	if (d->description)
	{
		str = d->description;
	}
	else
	{
		str = d->name;
	}
	SetDlgItemText(IDC_NOWDEVICE, str);
}

LRESULT CWINPCAP2Dlg::OnPackageCaptured(WPARAM wParam, LPARAM lParam)
{
	const struct pcap_pkthdr *header = (const struct pcap_pkthdr *) wParam;
	const u_char *pkt_data = (const u_char *) lParam;

	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	FrameHeader_t *data;
	ip_header *ih;
	u_int ip_len;
	CString str;
	//GetDlgItemText(IDC_PACKAGEINFO, str);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	str += "\r\n";
	//str += timestr;
	//str += "\tLength:";
	char buffer[50];
	//_itoa_s(header->len, buffer, 10);
	sprintf_s(buffer, "%s,%.6d Length:%d", timestr, header->ts.tv_usec, header->len);
	str += buffer;

	data = (FrameHeader_t*)pkt_data;

	//printf("\nsourceMAC:");
	str += "\r\nsourceMAC:";
	for (int i = 0; i < 6; i++)
	{
		sprintf_s(buffer,"%02x", data->SrcMac[i]);
		str += buffer;
		if (i != 5)
		{
			//printf("-");
			str += '-';
		}
	}
	//printf("\ndestMAC:");
	str += "\r\ndestMAC:";
	for (int i = 0; i < 6; i++)
	{
		sprintf_s(buffer, "%02x", data->DesMac[i]);
		str += buffer;		
		if (i != 5)
		{
			//printf("-");
			str += '-';
		}
	}
	//str += "\r\nFrameType:";
	sprintf_s(buffer,"\r\nframetype:0x%04x", ntohs(data->FrameType));
	str += buffer;
	str += "\r\n";
	//SetDlgItemText(IDC_PACKAGEINFO, str);
	CEdit *pEdit = (CEdit*) GetDlgItem(IDC_PACKAGEINFO);
	int nLength = pEdit->GetWindowTextLength();
	//选定当前文本的末端
	pEdit->SetSel(nLength, nLength);
	//l追加文本
	pEdit->ReplaceSel(str);
	return 0;
}

// pcap_loop 捕获到一个包后将包数据复制一份 并 发出WM_TCATCH消息
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct pcap_pkthdr *new_header = new struct pcap_pkthdr;
	u_char *new_data = new u_char[header->len];

	// 复制数据, 发出消息
	*new_header = *header;
	memcpy(new_data, pkt_data, header->len);
	AfxGetApp()->m_pMainWnd->PostMessage(WM_PACKAGE_CAPTURED, (WPARAM)new_header, (LPARAM)new_data);
}

UINT ThreadProc(LPVOID param)
{
	// 循环捕获包, 循环可以被 pcap_breakloop 终止
	int loopreturn = pcap_loop(adhandle, 0, packet_handler, NULL);

	// 退出前发出 WM_TEXIT 消息
	AfxGetApp()->m_pMainWnd->PostMessage(WM_TEXIT, loopreturn, NULL);

	return 0;
}


void CWINPCAP2Dlg::OnBnClickedCapture()
{
	// TODO: 在此添加控件通知处理程序代码
	if (IsCapturing)
	{//停止捕获数据包
		pcap_breakloop(adhandle);
		IsCapturing = false;
		CString str;
		GetDlgItemText(IDC_PACKAGEINFO, str);
		str += "\r\nCapture stopped.";
		SetDlgItemText(IDC_PACKAGEINFO, str);
		CWnd *getdevlist_btn = (CWnd *)GetDlgItem(IDC_GETDEVICE);
		getdevlist_btn->EnableWindow(true);
		CWnd *dev_list = (CWnd *)GetDlgItem(IDC_DEVICELIST);
		dev_list->EnableWindow(true);
		IsCapturing = false;
	}
	else
	{//启动捕获数据包
		CWnd *getdevlist_btn = (CWnd *)GetDlgItem(IDC_GETDEVICE);
		getdevlist_btn->EnableWindow(false);
		CWnd *dev_list = (CWnd *)GetDlgItem(IDC_DEVICELIST);
		dev_list->EnableWindow(false);
		CString str("Capture started. \r\n");
		//SetDlgItemText(IDC_PACKAGEINFO, str);
		GetDlgItem(IDC_PACKAGEINFO)->SetWindowText(str);
		IsCapturing = true;
		AfxBeginThread(ThreadProc, NULL, THREAD_PRIORITY_NORMAL);
	}
}
