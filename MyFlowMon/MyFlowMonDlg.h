
// MyFlowMonDlg.h : ͷ�ļ�
//

#pragma once


// CMyFlowMonDlg �Ի���
class CMyFlowMonDlg : public CDialogEx
{
// ����
public:
	CMyFlowMonDlg(CWnd* pParent = NULL);	// ��׼���캯��


	HANDLE  m_hMainDevice;
	static bool m_bUnload;

// �Ի�������
	enum { IDD = IDD_MYFLOWMON_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnLoadsys();
	afx_msg void OnBnClickedBtnUnloadsys();
	afx_msg void OnBnClickedBtnLimitup();
	afx_msg void OnBnClickedBtnLimitdown();
};
