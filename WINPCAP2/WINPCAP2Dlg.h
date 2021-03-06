
// WINPCAP2Dlg.h: 头文件
//

#pragma once
#include "main.h"

// CWINPCAP2Dlg 对话框
class CWINPCAP2Dlg : public CDialogEx
{
// 构造
public:
	CWINPCAP2Dlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WINPCAP2_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedGetdevice();
	afx_msg void OnCbnSelchangeDevicelist();
	afx_msg LRESULT OnPackageCaptured(WPARAM wParam,LPARAM lParam);
	afx_msg void OnBnClickedCapture();
	afx_msg void OnBnClickedArpbtn();
	bool IsCapturing = false;
	bool IsDeviceListFreed = true;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char* if_string = PCAP_SRC_IF_STRING;
	CWnd *ARP_wnd;
	CWnd *IP_wnd;
protected:
	afx_msg LRESULT OnArpCaptured(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnIpCaptured(WPARAM wParam, LPARAM lParam);
public:
	afx_msg void OnBnClickedIpbtn();
};
