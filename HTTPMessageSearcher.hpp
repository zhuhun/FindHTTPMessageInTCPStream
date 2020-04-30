/*��TCP���������ҡ�HTTP��������Э���һ����Ϣ��

��HTTP��������Э���һ����Ϣ��Ϊ�� ��https://tools.ietf.org/html/rfc2616#section-4��

		generic-message = start-line
						  *(message-header CRLF)
						  CRLF
						  [ message-body ]
		start-line      = Request-Line | Status-Line


*/
#pragma once

#include <string>
using std::string;
#include <boost/algorithm/searching/knuth_morris_pratt.hpp>
#include <boost/xpressive/xpressive.hpp>

typedef  unsigned char Byte1_t;

//HTTP��������Э���һ����Ϣ����Ϣ
struct HTTPMessageInfo
{
	//������Ϣ
	enum MessageType {
		Request         //������Ϣ
		,Response       //��Ӧ��Ϣ
	} m_MessageType;//��Ϣ����

	string m_strRequestMethod;   //���󷽷� (������Ϣ������Ϣ��
	string m_strRequestURI;      //URI      (������Ϣ������Ϣ��

	string m_strVersion;         //�汾�ַ��� ��������Э�������������粻������HTTP/���İ汾�ַ�����1.1����

	int    m_nStatusCode;        //״̬��   (��Ӧ��Ϣ������Ϣ��
	string m_strReasonPhrase;    //���ɶ��� (��Ӧ��Ϣ������Ϣ��

	//λ�ó�����Ϣ
	int m_nPos_StartLine;            //������TCP�������е�λ��
	int m_nLen_StartLine;            //���еĳ��ȣ�����CRLF��

	int m_nPos_Header;  //�ײ���㣨�ײ�ָ��������֮�����Ϣ�ײ���(��: m_nPos_StartLine+m_nLen_StartLine)
	int m_nLen_Header;  //�ײ����ȣ�����ĩβ��CRLFCRLF����-1��ʾδ�ҵ���Ϣ�壩(��: m_nPos_Body-m_nPos_Header�������ҵ���Ϣ��)

	int m_nPos_Body;       //��Ϣ������λ�ã�-1��ʾδ�ҵ���Ϣ�壩
	int m_nLen_Body;       //��Ϣ��ĳ��ȣ�-1��ʾδ�ҵ���Ϣ���Content-Length)

	void Print(FILE* fw = stdout) {

		if (m_MessageType == HTTPMessageInfo::Request)
		{
			fprintf(fw, "%7d %4d %7d %4d Request: %s %s %s\n"
				, m_nPos_StartLine
				, m_nLen_StartLine
				, m_nPos_Body
				, m_nLen_Body
				, m_strRequestMethod.c_str()
				, m_strRequestURI.c_str()
				, m_strVersion.c_str()
			);
		} else	{
			fprintf(fw, "%7d %4d %7d %4d Response: %3d, %s, %s\n"
				, m_nPos_StartLine
				, m_nLen_StartLine
				, m_nPos_Body
				, m_nLen_Body
				, m_nStatusCode
				, m_strReasonPhrase.c_str()
				, m_strVersion.c_str()
			);
		}
	
	}
};


// HTTP��������Э�������������
class HTTPMessageSearcher
{
public:
	enum Status {
		Status_NotSetTCPStreamBuff   //��δ����TCP���Ļ�����
		, Status_StartToSearch       //���úû�������׼����ʼ����������λ��Ϊ0
		, Status_Found               //�ҵ�������/��Ӧ��Ϣ
		, Status_EndOfBuff           //����������β����������
	};

private:
	Status m_emStatus; //�����״̬

	int m_nPos_Search; //�ڲ�������λ��

	const char* m_pBuffOfTCPStream; // TCP��������
	int         m_nBytesOfBuff;     // TCP������

private:
	const string m_strProtoName;     //Э�����ƣ�����Ϊ��HTTP������RSTP������SIP��
	const string m_strProtoNameAndSlash;
	const int    m_nLen_ProtoNameAndSlash;
	const boost::algorithm::knuth_morris_pratt<const char *> m_kmp_ProtoNameAndSlash;

	static const string SP;
	static const boost::algorithm::knuth_morris_pratt<const char*> kmp_SP;

	static const string CRLF;
	static const boost::algorithm::knuth_morris_pratt<const char*> kmp_CRLF;

	static const string CRLFCRLF;
	static const boost::algorithm::knuth_morris_pratt<const char*> kmp_CRLFCRLF;

	static const string ContentLengthHead;
	static const boost::algorithm::knuth_morris_pratt<const char*> kmp_ContentLengthHead;

	static boost::xpressive::sregex_compiler s_rc;

public:
	HTTPMessageSearcher(const char szProtocolName[] = "HTTP") 
		: m_strProtoName(szProtocolName)
		, m_strProtoNameAndSlash(m_strProtoName+"/")
		, m_nLen_ProtoNameAndSlash(m_strProtoNameAndSlash.size())
		, m_kmp_ProtoNameAndSlash(m_strProtoNameAndSlash.data(), m_strProtoNameAndSlash.data()+ m_nLen_ProtoNameAndSlash)
		, m_emStatus(Status_NotSetTCPStreamBuff)
		//C++ ��ʼ�����Աʱ���ǰ���������˳���ʼ���ģ������ǰ��ճ����ڳ�ʼ���б��е�˳��
	{
	}

public:
	void SetTCPStreamBuff(
		const char* pBuff
		, int       nBytes
	) {
		if (pBuff != NULL
			&& nBytes > 0
			) {
			m_pBuffOfTCPStream = pBuff;
			m_nBytesOfBuff = nBytes;

			ResetSearchPos();
		}else{
			m_emStatus = Status_NotSetTCPStreamBuff;
		}
	}

	void ResetSearchPos() {
		m_nPos_Search = 0;
		m_emStatus = Status_StartToSearch;
	}

public:
	//��TCP�������в��������������������ҵ�������Ϣ����Ӧ��Ϣ���򷵻�Status_Found�����򣬷�������Status��
	Status Search(HTTPMessageInfo* pMsg) {

		if (m_emStatus == Status_NotSetTCPStreamBuff)
			return m_emStatus;
		else if (m_emStatus == Status_EndOfBuff)
			return m_emStatus;

		//��¼�����������
		int nPos_Search_Start_Now = m_nPos_Search; 

		while (m_nPos_Search < m_nBytesOfBuff) {

			//��1�������ַ���"[Э����]/"������"HTTP/"��: �ҵ���λ��ΪnPos_ProtoNameAndSlash��"[Э����]/"�ַ�������Ϊm_nLen_ProtoNameAndSlash��
			// ��Э��汾�ַ����Ŀ�ͷ�����硰HTTP/��
			std::pair<const char*,const char*> myfoundresult = m_kmp_ProtoNameAndSlash(m_pBuffOfTCPStream + m_nPos_Search, m_pBuffOfTCPStream + m_nBytesOfBuff);
			if (myfoundresult.first == m_pBuffOfTCPStream + m_nBytesOfBuff) {
				m_emStatus = Status_EndOfBuff;
				return m_emStatus;
			}

			int nPos_ProtoNameAndSlash = myfoundresult.first - m_pBuffOfTCPStream;//�ַ���"[Э����]/"��λ��

			pMsg->m_MessageType = HTTPMessageInfo::Response; //��ʱ��Ϊ����Ӧ��Ϣ
			pMsg->m_nPos_StartLine = nPos_ProtoNameAndSlash;

			/*
			��2����nPos_ProtoNameAndSlash+m_nLen_ProtoNameAndSlash֮���8�ֽڣ��汾�š�n.m��n��m����������������һλ��һ�㳤��Ϊ3�����ǵ�����֧�֣��ַ�������С�ڵ���8�ֽڣ��У���"\r\n"�������У���" "��״̬�У�: �ҵ���λ��ΪnPos_VersionEnd��
	 ���ҵ�,ȡ�������м���ַ���������<=8�ֽڣ����ж��Ƿ�������n.m�����汾�ţ����ǵ�����֧�֣�n.m�ַ�������С�ڵ���8�ֽ�)��
	 ���ǣ���
	 �����ҵ��������е�ĩβ�����������1��: pos_StartLineEnd = nPos_VersionEnd+2)��
	 ����״̬�еĿ�ʼ�����������2��: pos_StartLineStart=nPos_ProtoNameAndSlash, pos_StatusCode=nPos_VersionEnd+1)��
*/
			//��SP��CRLF

			int pos_searchend = nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash + 9; //�����ǵ�����֧�֣�n.m�ַ�������С�ڵ���8�ֽ�)
			if (pos_searchend > m_nBytesOfBuff)
				pos_searchend = m_nBytesOfBuff;

			myfoundresult = kmp_SP(m_pBuffOfTCPStream + nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash, m_pBuffOfTCPStream + pos_searchend);
			std::pair<const char*, const char*> myfoundresult2 = kmp_CRLF(m_pBuffOfTCPStream + nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash, m_pBuffOfTCPStream + pos_searchend);

			if (myfoundresult.first == m_pBuffOfTCPStream + pos_searchend) { //δ�ҵ�SP��˵��������Ӧ��Ϣ, ������������Ϣ

				if (myfoundresult2.first == m_pBuffOfTCPStream + pos_searchend) { //δ�ҵ�SP, δ�ҵ�CRLF
					m_nPos_Search = nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash;
					continue;
				}
				else //δ�ҵ�SP, �ҵ�CRLF��˵����������Ϣ
				{
					pMsg->m_MessageType = HTTPMessageInfo::Request;
					myfoundresult = myfoundresult2;
				}
			}
			else if (myfoundresult2.first == m_pBuffOfTCPStream + pos_searchend) { //�ҵ�SP, δ�ҵ�CRLF��˵������Ӧ��Ϣ
				pMsg->m_MessageType = HTTPMessageInfo::Response;
			}
			else {//�ҵ�SP, Ҳ�ҵ�CRLF�� Ҫ�Ƚ�һ��
				if (myfoundresult.first < myfoundresult2.first) {//SP��λ����ǰ
					pMsg->m_MessageType = HTTPMessageInfo::Response;
				}
				else { //CRLF��ǰ
					pMsg->m_MessageType = HTTPMessageInfo::Request;
					myfoundresult = myfoundresult2;
				}
			}

			int nPos_VersionEnd= myfoundresult.first - m_pBuffOfTCPStream; //�汾��֮���λ�� ���п����ǿո��CRLF��

			//ȡ���汾��
			pMsg->m_strVersion.assign(m_pBuffOfTCPStream + nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash, myfoundresult.first);

			//�жϰ汾���Ƿ�Ϸ�
			if (s_rc["[0-9]+\\.[0-9]+"].regex_id() == NULL ) {
				s_rc["[0-9]+\\.[0-9]+"] = s_rc.compile("[0-9]+\\.[0-9]+");
			}

			if ( !boost::xpressive::regex_match(pMsg->m_strVersion, s_rc["[0-9]+\\.[0-9]+"])  ) { //���Ϸ�����
				m_nPos_Search = nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash + 1; //���ٺ����������һ���ֽڣ���Ϊ������SP��������CRLF
				continue;
			}

			//�����ҵ��˰汾�ַ����� ���� ��HTTP/1.1����

			switch (pMsg->m_MessageType)  {
			case HTTPMessageInfo::Request:
			{
				/*
					��3�����ǡ��������1����
	nPos_ProtoNameAndSlash-1λ�ñ���Ϊ" "��
	��nPos_ProtoNameAndSlash-1��ǰ��2083�ֽڣ�URI�ַ�������һ��С��2083�ֽڣ�IE8��URL����󳤶���2083���ֽڣ�����" "��
	���ҵ���λ��ΪnPos_URIHeadSP��nPos_URIHeadSP+1~nPos_ProtoNameAndSlash-2���ַ���ΪURI�����б���Ϊ�ɴ�ӡ�ַ���������\r\n����

	��nPos_URIHeadSP��ǰ��32�ֽڣ�����һ��С��32�ֽڣ�һ�㶼�Ǵ�д��ĸ���»��ߣ��е�һ�� �ǡ���ĸ���»��ߡ���Ϊλ��nPos_Method'��nPos_Method'+1~nPos_URIHeadSP-1Ϊ������Method����
	���뱣֤��������Method���ַ���Ϊ����ġ����롰����Method���Ŀ��ܵļ��Ͻ��бȽϣ�

	pos_StartLineStart = nPos_Method'+1

	���ˣ��ҵ���������Ϣ�����С�
*/
				if (!(nPos_ProtoNameAndSlash > 3 && m_pBuffOfTCPStream[nPos_ProtoNameAndSlash - 1] == ' '))
				{
					m_nPos_Search = nPos_VersionEnd + 2;//�����������CRLF
					continue;
				}

				//��ǰ-��URI
				pos_searchend = nPos_ProtoNameAndSlash - 2 - 2083;
				if (pos_searchend < nPos_Search_Start_Now)
				{
					pos_searchend = nPos_Search_Start_Now;
				}

				int nPos_URIHeadSP = -1; //URI֮ǰ�Ŀո��λ��
				for (int i = nPos_ProtoNameAndSlash - 2; i >= pos_searchend; i--)
				{
					if (m_pBuffOfTCPStream[i] == ' ')
					{
						nPos_URIHeadSP = i;
						break;
					}
					else if (m_pBuffOfTCPStream[i] == '\r' || m_pBuffOfTCPStream[i] == '\n')
					{
						break;
					}
				}
				if (nPos_URIHeadSP == -1 || nPos_URIHeadSP >= nPos_ProtoNameAndSlash - 2) //δ�ҵ�����URI����Ϊ0
				{
					m_nPos_Search = nPos_VersionEnd + 2;//�����������CRLF
					continue;
				}

				//ȡ��URI
				pMsg->m_strRequestURI.assign(m_pBuffOfTCPStream + nPos_URIHeadSP + 1, m_pBuffOfTCPStream + nPos_ProtoNameAndSlash - 1);

				//��ǰ-��Method
				pos_searchend = nPos_URIHeadSP - 1 - 32;
				if (pos_searchend < nPos_Search_Start_Now)
				{
					pos_searchend = nPos_Search_Start_Now;
				}


				int nPos_Method = -1; //Method��λ��
				for (int i = nPos_URIHeadSP - 1; i >= pos_searchend; i--)
				{
					if (!(m_pBuffOfTCPStream[i] == '_' || (m_pBuffOfTCPStream[i] >= 'A' && m_pBuffOfTCPStream[i] <= 'Z'))) 
					{
						//�Ǵ�д��ĸ���»���
						nPos_Method = i + 1;//Method��λ��
						break;
					}
				}
				if (nPos_Method == -1) //δ�ҵ�
				{
					nPos_Method = pos_searchend; //Method��λ��
				}

				if (nPos_Method >= nPos_URIHeadSP - 1) //Method����Ϊ0
				{
					m_nPos_Search = nPos_VersionEnd + 2;//�����������CRLF
					continue;
				}

				//ȡ��Method
				pMsg->m_strRequestMethod.assign(m_pBuffOfTCPStream + nPos_Method, m_pBuffOfTCPStream + nPos_URIHeadSP);


				//���ˣ��ҵ���������Ϣ�����С�
				pMsg->m_nPos_StartLine = nPos_Method;
				pMsg->m_nLen_StartLine = nPos_VersionEnd + 2 - nPos_Method;
				pMsg->m_nPos_Header = pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine;

				m_nPos_Search = nPos_VersionEnd + 2;

				break;
				}

			case HTTPMessageInfo::Response:
			{
				/*
��4�����ǡ��������2����
��nPos_VersionEnd + 2��ʼ�ҵ�һ�������֣������ǿո�ȡ�����е�StatusCode������Ϊ3�����ǵ�����֧�֣�����С�ڵ���8�ֽڣ���

������64�ֽ��У��ҡ�\r\n����λ��Ϊpos5����״̬�еĽ�β����ȡ�����е�ReasonPhrase��ReasonPhrase���ȿ���Ϊ0�������հ��ַ���SP��HT���ķǿ����ַ��� һ������ĸ�Ϳո񣬲�����CRLF������һ��С��64�ֽڣ���

pos_StartLineEnd = pos5+2

���ˣ��ҵ�����Ӧ��Ϣ�����С�
		*/

				//��StatusCode�Ľ�β�ո�
				pos_searchend = nPos_VersionEnd + 1 + 8; //�����ǵ�����֧�֣�StatusCode�ַ�������С�ڵ���8�ֽ�)
				if (pos_searchend > m_nBytesOfBuff)
					pos_searchend = m_nBytesOfBuff;

				int nPos_StatusCode_end = -1;
				for (int i = nPos_VersionEnd + 1; i < pos_searchend; i++)
				{
					if (m_pBuffOfTCPStream[i] >= '0' && m_pBuffOfTCPStream[i] <= '9')
					{
						continue;
					}
					else if (m_pBuffOfTCPStream[i] == ' ')
					{
						nPos_StatusCode_end = i;
						break;
					}
					else
					{
						break;
					}
				}

				if (nPos_StatusCode_end == -1 || nPos_StatusCode_end == nPos_VersionEnd + 1) { //δ�ҵ�StatusCode֮���SP����StatusCode����Ϊ0��˵��������Ӧ��Ϣ
					m_nPos_Search = nPos_VersionEnd + 1; //�����������SP (�汾�ַ���֮��SP��
					continue;
				}

				//ȡ��StatusCode
				string tmp(m_pBuffOfTCPStream + nPos_VersionEnd + 1, m_pBuffOfTCPStream + nPos_StatusCode_end);

				pMsg->m_nStatusCode = atoi(tmp.c_str());

				//��ReasonPhrase
				pos_searchend = nPos_StatusCode_end + 1 + 64; //�����ǵ�����֧�֣�ReasonPhrase�ַ�������С�ڵ���64�ֽ�)
				if (pos_searchend > m_nBytesOfBuff)
					pos_searchend = m_nBytesOfBuff;

				myfoundresult = kmp_CRLF(m_pBuffOfTCPStream + nPos_StatusCode_end + 1, m_pBuffOfTCPStream + pos_searchend);
				if (myfoundresult.first == m_pBuffOfTCPStream + pos_searchend) { //δ�ҵ�CRLF��˵��������Ӧ��Ϣ
					m_nPos_Search = nPos_VersionEnd + 1; //�����������SP (�汾�ַ���֮��SP��
					continue;
				}

				//ȡ��ReasonPhrase
				pMsg->m_strReasonPhrase.assign(m_pBuffOfTCPStream + nPos_StatusCode_end + 1, myfoundresult.first);

				//���ˣ��ҵ���������Ϣ�����С�
				pMsg->m_nPos_StartLine = nPos_ProtoNameAndSlash;
				pMsg->m_nLen_StartLine = myfoundresult.second - m_pBuffOfTCPStream - nPos_ProtoNameAndSlash;
				pMsg->m_nPos_Header = pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine;

				m_nPos_Search = pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine + 1;

				break;
			}
			default:
				//���������е��˴�
				break;
			}//switch (pMsg->m_MessageType)

			//��Head�Ľ�β����CRLFCRLF
			if (m_nPos_Search < m_nBytesOfBuff)
			{

				myfoundresult = kmp_CRLFCRLF(m_pBuffOfTCPStream + m_nPos_Search, m_pBuffOfTCPStream + m_nBytesOfBuff);
				if (myfoundresult.first != m_pBuffOfTCPStream + m_nBytesOfBuff) { //�ҵ�CRLFCRLF

					pMsg->m_nPos_Body = myfoundresult.second - m_pBuffOfTCPStream;
					pMsg->m_nLen_Header = pMsg->m_nPos_Body - pMsg->m_nPos_Header;
					pMsg->m_nLen_Body = -1; //������Ϊ-1

					m_nPos_Search = pMsg->m_nPos_Body;//������ΪpMsg->m_nPos_Body

					//���ҡ�\r\nContent-Length: ����Ȼ�������ó���
					myfoundresult = kmp_ContentLengthHead(m_pBuffOfTCPStream + pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine - 2, m_pBuffOfTCPStream+ pMsg->m_nPos_Body);

					if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //�ҵ���\r\nContent-Length: ��
						const char* pBegin_ContentLength = myfoundresult.second;

						myfoundresult = kmp_CRLF(pBegin_ContentLength, m_pBuffOfTCPStream + pMsg->m_nPos_Body);
						if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //�ҵ�CRLF
							string tmp(pBegin_ContentLength, myfoundresult.first);

							if (s_rc["[0-9]+"].regex_id() == NULL) {
								s_rc["[0-9]+"] = s_rc.compile("[0-9]+");
							}

							if (boost::xpressive::regex_match(tmp, s_rc["[0-9]+"])) { //�Ϸ�����
								int nContentLength = atoi(tmp.c_str());
								pMsg->m_nLen_Body = nContentLength;

								m_nPos_Search = pMsg->m_nPos_Body + nContentLength;
							}
						}//if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //�ҵ�CRLF
					}//if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //�ҵ���\r\nContent-Length: ��

				}//if (myfoundresult.first != m_pBuffOfTCPStream + m_nBytesOfBuff) { //�ҵ�CRLFCRLF
				else {	//δ�ҵ�CRLFCRLF
					pMsg->m_nLen_Header = -1;
					pMsg->m_nPos_Body = -1;
					pMsg->m_nLen_Body = -1;

					m_nPos_Search = m_nBytesOfBuff;
				}

			}//if (m_nPos_Search < m_nBytesOfBuff)

			m_emStatus = Status_Found;
			return m_emStatus;

		}//while (m_nPos_Search < m_nBytesOfBuff) 


		m_emStatus = Status_EndOfBuff;
		return m_emStatus;
	}

};

const string HTTPMessageSearcher::SP = " ";
const boost::algorithm::knuth_morris_pratt<const char*> HTTPMessageSearcher::kmp_SP(HTTPMessageSearcher::SP.data(), HTTPMessageSearcher::SP.data() + 1);

const string HTTPMessageSearcher::CRLF = "\r\n";
const boost::algorithm::knuth_morris_pratt<const char*> HTTPMessageSearcher::kmp_CRLF(HTTPMessageSearcher::CRLF.data(), HTTPMessageSearcher::CRLF.data() + 2);

const string HTTPMessageSearcher::CRLFCRLF = "\r\n\r\n";
const boost::algorithm::knuth_morris_pratt<const char*> HTTPMessageSearcher::kmp_CRLFCRLF(HTTPMessageSearcher::CRLFCRLF.data(), HTTPMessageSearcher::CRLFCRLF.data() + 4);


const string HTTPMessageSearcher::ContentLengthHead="\r\nContent-Length: ";
const boost::algorithm::knuth_morris_pratt<const char*> HTTPMessageSearcher::kmp_ContentLengthHead(
	HTTPMessageSearcher::ContentLengthHead.data()
	, HTTPMessageSearcher::ContentLengthHead.data() + HTTPMessageSearcher::ContentLengthHead.size());

boost::xpressive::sregex_compiler HTTPMessageSearcher::s_rc;

/*
ʹ��ʾ����
	const boost::interprocess::mode_t mode = boost::interprocess::read_only;
	boost::interprocess::file_mapping fm("D:\\pcap-data\\httpdata", mode);
	boost::interprocess::mapped_region region(fm, mode, 0, 0);

	printf("%d\n", region.get_size());

	HTTPMessageSearcher msgsearcher("HTTP");


	msgsearcher.SetTCPStreamBuff((const char*)(region.get_address()), region.get_size());

	HTTPMessageInfo msg;

	while (msgsearcher.Search(&msg) == msgsearcher.Status_Found)
	{
		msg.Print();
	}

*/