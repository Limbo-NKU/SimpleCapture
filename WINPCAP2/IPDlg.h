#pragma once

#include "main.h"
#include "IPRouter.h"
// IPDlg 对话框

class IPDlg : public CDialogEx
{
	DECLARE_DYNAMIC(IPDlg)

public:
	IPDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~IPDlg();

	DWORD localIP;
	IPRouter router;

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_IPDLG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	DECLARE_MESSAGE_MAP()
	afx_msg LRESULT OnIpCaptured(WPARAM wParam, LPARAM lParam);
public:
	afx_msg void OnBnClickedButton1();
	void UpdateRouteTable(IPRouteNode node);
	afx_msg void OnShowWindow(BOOL bShow, UINT nStatus);
};
