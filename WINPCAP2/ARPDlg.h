#pragma once

#include "main.h"
// ARPDlg 对话框

class ARPDlg : public CDialogEx
{
	DECLARE_DYNAMIC(ARPDlg)

public:
	ARPDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~ARPDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ARPDLG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized);
protected:
	afx_msg LRESULT OnArpCaptured(WPARAM wParam, LPARAM lParam);
public:
	CString name;
	CString description;
	CString IP_Addr_s;
	CString MAC_Addr_s;
	DWORD IP_Addr;
	BYTE MAC_Addr[6];
	afx_msg void OnBnClickedGetaddress();
	pcap_t* adhandle;
	afx_msg void OnBnClickedCancel();
	afx_msg void OnShowWindow(BOOL bShow, UINT nStatus);
	afx_msg void OnClose();
};
