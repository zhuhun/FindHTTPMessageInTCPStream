/*在TCP流数据中找“HTTP或者类似协议的一个消息”

“HTTP或者类似协议的一个消息”为： （https://tools.ietf.org/html/rfc2616#section-4）

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

//HTTP或者类似协议的一个消息的信息
struct HTTPMessageInfo
{
	//首行信息
	enum MessageType {
		Request         //请求消息
		,Response       //响应消息
	} m_MessageType;//消息类型

	string m_strRequestMethod;   //请求方法 (请求消息首行信息）
	string m_strRequestURI;      //URI      (请求消息首行信息）

	string m_strVersion;         //版本字符串 （不包括协议名，即，例如不包括“HTTP/”的版本字符串“1.1”）

	int    m_nStatusCode;        //状态码   (响应消息首行信息）
	string m_strReasonPhrase;    //理由短语 (响应消息首行信息）

	//位置长度消息
	int m_nPos_StartLine;            //首行在TCP流数据中的位置
	int m_nLen_StartLine;            //首行的长度（包括CRLF）

	int m_nPos_Header;  //首部起点（首部指：除首行之外的消息首部）(即: m_nPos_StartLine+m_nLen_StartLine)
	int m_nLen_Header;  //首部长度（包括末尾的CRLFCRLF）（-1表示未找到消息体）(即: m_nPos_Body-m_nPos_Header，若有找到消息体)

	int m_nPos_Body;       //消息体的起点位置（-1表示未找到消息体）
	int m_nLen_Body;       //消息体的长度（-1表示未找到消息体或Content-Length)

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


// HTTP或者类似协议的首行搜索者
class HTTPMessageSearcher
{
public:
	enum Status {
		Status_NotSetTCPStreamBuff   //还未设置TCP流的缓冲区
		, Status_StartToSearch       //设置好缓冲区，准备开始搜索，搜索位置为0
		, Status_Found               //找到了请求/响应消息
		, Status_EndOfBuff           //到缓冲区结尾，搜索结束
	};

private:
	Status m_emStatus; //本类的状态

	int m_nPos_Search; //内部搜索的位置

	const char* m_pBuffOfTCPStream; // TCP流缓冲区
	int         m_nBytesOfBuff;     // TCP流长度

private:
	const string m_strProtoName;     //协议名称，可以为“HTTP”，“RSTP”，“SIP”
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
		//C++ 初始化类成员时，是按照声明的顺序初始化的，而不是按照出现在初始化列表中的顺序。
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
	//在TCP流数据中查找首行搜索函数，若找到请求消息或响应消息，则返回Status_Found，否则，返回其它Status。
	Status Search(HTTPMessageInfo* pMsg) {

		if (m_emStatus == Status_NotSetTCPStreamBuff)
			return m_emStatus;
		else if (m_emStatus == Status_EndOfBuff)
			return m_emStatus;

		//记录本次搜索起点
		int nPos_Search_Start_Now = m_nPos_Search; 

		while (m_nPos_Search < m_nBytesOfBuff) {

			//（1）查找字符串"[协议名]/"（例如"HTTP/"）: 找到的位置为nPos_ProtoNameAndSlash。"[协议名]/"字符串长度为m_nLen_ProtoNameAndSlash。
			// 找协议版本字符串的开头，例如“HTTP/”
			std::pair<const char*,const char*> myfoundresult = m_kmp_ProtoNameAndSlash(m_pBuffOfTCPStream + m_nPos_Search, m_pBuffOfTCPStream + m_nBytesOfBuff);
			if (myfoundresult.first == m_pBuffOfTCPStream + m_nBytesOfBuff) {
				m_emStatus = Status_EndOfBuff;
				return m_emStatus;
			}

			int nPos_ProtoNameAndSlash = myfoundresult.first - m_pBuffOfTCPStream;//字符串"[协议名]/"的位置

			pMsg->m_MessageType = HTTPMessageInfo::Response; //暂时认为是响应消息
			pMsg->m_nPos_StartLine = nPos_ProtoNameAndSlash;

			/*
			（2）在nPos_ProtoNameAndSlash+m_nLen_ProtoNameAndSlash之后的8字节（版本号“n.m”n，m都是数字且至少有一位，一般长度为3，考虑到升级支持，字符串长度小于等于8字节）中，找"\r\n"（请求行）或" "（状态行）: 找到的位置为nPos_VersionEnd。
	 若找到,取出夹在中间的字符串（长度<=8字节），判断是否是形如n.m，即版本号（考虑到升级支持，n.m字符串长度小于等于8字节)，
	 若是，则
	 可能找到了请求行的末尾处（可能情况1）: pos_StartLineEnd = nPos_VersionEnd+2)，
	 或者状态行的开始处（可能情况2）: pos_StartLineStart=nPos_ProtoNameAndSlash, pos_StatusCode=nPos_VersionEnd+1)。
*/
			//找SP或CRLF

			int pos_searchend = nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash + 9; //（考虑到升级支持，n.m字符串长度小于等于8字节)
			if (pos_searchend > m_nBytesOfBuff)
				pos_searchend = m_nBytesOfBuff;

			myfoundresult = kmp_SP(m_pBuffOfTCPStream + nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash, m_pBuffOfTCPStream + pos_searchend);
			std::pair<const char*, const char*> myfoundresult2 = kmp_CRLF(m_pBuffOfTCPStream + nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash, m_pBuffOfTCPStream + pos_searchend);

			if (myfoundresult.first == m_pBuffOfTCPStream + pos_searchend) { //未找到SP，说明不是响应消息, 可能是请求消息

				if (myfoundresult2.first == m_pBuffOfTCPStream + pos_searchend) { //未找到SP, 未找到CRLF
					m_nPos_Search = nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash;
					continue;
				}
				else //未找到SP, 找到CRLF，说明是请求消息
				{
					pMsg->m_MessageType = HTTPMessageInfo::Request;
					myfoundresult = myfoundresult2;
				}
			}
			else if (myfoundresult2.first == m_pBuffOfTCPStream + pos_searchend) { //找到SP, 未找到CRLF，说明是响应消息
				pMsg->m_MessageType = HTTPMessageInfo::Response;
			}
			else {//找到SP, 也找到CRLF， 要比较一下
				if (myfoundresult.first < myfoundresult2.first) {//SP的位置在前
					pMsg->m_MessageType = HTTPMessageInfo::Response;
				}
				else { //CRLF在前
					pMsg->m_MessageType = HTTPMessageInfo::Request;
					myfoundresult = myfoundresult2;
				}
			}

			int nPos_VersionEnd= myfoundresult.first - m_pBuffOfTCPStream; //版本号之后的位置 （有可能是空格或CRLF）

			//取出版本号
			pMsg->m_strVersion.assign(m_pBuffOfTCPStream + nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash, myfoundresult.first);

			//判断版本号是否合法
			if (s_rc["[0-9]+\\.[0-9]+"].regex_id() == NULL ) {
				s_rc["[0-9]+\\.[0-9]+"] = s_rc.compile("[0-9]+\\.[0-9]+");
			}

			if ( !boost::xpressive::regex_match(pMsg->m_strVersion, s_rc["[0-9]+\\.[0-9]+"])  ) { //不合法，则
				m_nPos_Search = nPos_ProtoNameAndSlash + m_nLen_ProtoNameAndSlash + 1; //至少后面可以跳过一个字节，因为或者是SP，或者是CRLF
				continue;
			}

			//至此找到了版本字符串， 例如 “HTTP/1.1”。

			switch (pMsg->m_MessageType)  {
			case HTTPMessageInfo::Request:
			{
				/*
					（3）若是“可能情况1”，
	nPos_ProtoNameAndSlash-1位置必须为" "。
	从nPos_ProtoNameAndSlash-1往前的2083字节（URI字符串长度一般小于2083字节，IE8的URL的最大长度是2083个字节）中找" "，
	若找到，位置为nPos_URIHeadSP，nPos_URIHeadSP+1~nPos_ProtoNameAndSlash-2的字符串为URI，其中必须为可打印字符（不能有\r\n）。

	从nPos_URIHeadSP往前的32字节（方法一般小于32字节，一般都是大写字母或下划线）中第一个 非“字母或下划线”，为位置nPos_Method'，nPos_Method'+1~nPos_URIHeadSP-1为“方法Method”。
	必须保证：“方法Method”字符串为合理的。（与“方法Method”的可能的集合进行比较）

	pos_StartLineStart = nPos_Method'+1

	至此，找到了请求消息的首行。
*/
				if (!(nPos_ProtoNameAndSlash > 3 && m_pBuffOfTCPStream[nPos_ProtoNameAndSlash - 1] == ' '))
				{
					m_nPos_Search = nPos_VersionEnd + 2;//后面可以跳过CRLF
					continue;
				}

				//往前-找URI
				pos_searchend = nPos_ProtoNameAndSlash - 2 - 2083;
				if (pos_searchend < nPos_Search_Start_Now)
				{
					pos_searchend = nPos_Search_Start_Now;
				}

				int nPos_URIHeadSP = -1; //URI之前的空格的位置
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
				if (nPos_URIHeadSP == -1 || nPos_URIHeadSP >= nPos_ProtoNameAndSlash - 2) //未找到或者URI长度为0
				{
					m_nPos_Search = nPos_VersionEnd + 2;//后面可以跳过CRLF
					continue;
				}

				//取出URI
				pMsg->m_strRequestURI.assign(m_pBuffOfTCPStream + nPos_URIHeadSP + 1, m_pBuffOfTCPStream + nPos_ProtoNameAndSlash - 1);

				//往前-找Method
				pos_searchend = nPos_URIHeadSP - 1 - 32;
				if (pos_searchend < nPos_Search_Start_Now)
				{
					pos_searchend = nPos_Search_Start_Now;
				}


				int nPos_Method = -1; //Method的位置
				for (int i = nPos_URIHeadSP - 1; i >= pos_searchend; i--)
				{
					if (!(m_pBuffOfTCPStream[i] == '_' || (m_pBuffOfTCPStream[i] >= 'A' && m_pBuffOfTCPStream[i] <= 'Z'))) 
					{
						//非大写字母和下划线
						nPos_Method = i + 1;//Method的位置
						break;
					}
				}
				if (nPos_Method == -1) //未找到
				{
					nPos_Method = pos_searchend; //Method的位置
				}

				if (nPos_Method >= nPos_URIHeadSP - 1) //Method长度为0
				{
					m_nPos_Search = nPos_VersionEnd + 2;//后面可以跳过CRLF
					continue;
				}

				//取出Method
				pMsg->m_strRequestMethod.assign(m_pBuffOfTCPStream + nPos_Method, m_pBuffOfTCPStream + nPos_URIHeadSP);


				//至此，找到了请求消息的首行。
				pMsg->m_nPos_StartLine = nPos_Method;
				pMsg->m_nLen_StartLine = nPos_VersionEnd + 2 - nPos_Method;
				pMsg->m_nPos_Header = pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine;

				m_nPos_Search = nPos_VersionEnd + 2;

				break;
				}

			case HTTPMessageInfo::Response:
			{
				/*
（4）若是“可能情况2”，
从nPos_VersionEnd + 2开始找第一个非数字，必须是空格。取出其中的StatusCode（长度为3，考虑到升级支持，长度小于等于8字节）。

在其后的64字节中，找“\r\n”，位置为pos5，即状态行的结尾处。取出其中的ReasonPhrase（ReasonPhrase长度可以为0，包括空白字符（SP、HT）的非控制字符， 一般是字母和空格，不包含CRLF，长度一般小于64字节）。

pos_StartLineEnd = pos5+2

至此，找到了响应消息的首行。
		*/

				//找StatusCode的结尾空格
				pos_searchend = nPos_VersionEnd + 1 + 8; //（考虑到升级支持，StatusCode字符串长度小于等于8字节)
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

				if (nPos_StatusCode_end == -1 || nPos_StatusCode_end == nPos_VersionEnd + 1) { //未找到StatusCode之后的SP或者StatusCode长度为0，说明不是响应消息
					m_nPos_Search = nPos_VersionEnd + 1; //后面可以跳过SP (版本字符串之后SP）
					continue;
				}

				//取出StatusCode
				string tmp(m_pBuffOfTCPStream + nPos_VersionEnd + 1, m_pBuffOfTCPStream + nPos_StatusCode_end);

				pMsg->m_nStatusCode = atoi(tmp.c_str());

				//找ReasonPhrase
				pos_searchend = nPos_StatusCode_end + 1 + 64; //（考虑到升级支持，ReasonPhrase字符串长度小于等于64字节)
				if (pos_searchend > m_nBytesOfBuff)
					pos_searchend = m_nBytesOfBuff;

				myfoundresult = kmp_CRLF(m_pBuffOfTCPStream + nPos_StatusCode_end + 1, m_pBuffOfTCPStream + pos_searchend);
				if (myfoundresult.first == m_pBuffOfTCPStream + pos_searchend) { //未找到CRLF，说明不是响应消息
					m_nPos_Search = nPos_VersionEnd + 1; //后面可以跳过SP (版本字符串之后SP）
					continue;
				}

				//取出ReasonPhrase
				pMsg->m_strReasonPhrase.assign(m_pBuffOfTCPStream + nPos_StatusCode_end + 1, myfoundresult.first);

				//至此，找到了请求消息的首行。
				pMsg->m_nPos_StartLine = nPos_ProtoNameAndSlash;
				pMsg->m_nLen_StartLine = myfoundresult.second - m_pBuffOfTCPStream - nPos_ProtoNameAndSlash;
				pMsg->m_nPos_Header = pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine;

				m_nPos_Search = pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine + 1;

				break;
			}
			default:
				//不可能运行到此处
				break;
			}//switch (pMsg->m_MessageType)

			//找Head的结尾处的CRLFCRLF
			if (m_nPos_Search < m_nBytesOfBuff)
			{

				myfoundresult = kmp_CRLFCRLF(m_pBuffOfTCPStream + m_nPos_Search, m_pBuffOfTCPStream + m_nBytesOfBuff);
				if (myfoundresult.first != m_pBuffOfTCPStream + m_nBytesOfBuff) { //找到CRLFCRLF

					pMsg->m_nPos_Body = myfoundresult.second - m_pBuffOfTCPStream;
					pMsg->m_nLen_Header = pMsg->m_nPos_Body - pMsg->m_nPos_Header;
					pMsg->m_nLen_Body = -1; //先设置为-1

					m_nPos_Search = pMsg->m_nPos_Body;//先设置为pMsg->m_nPos_Body

					//查找“\r\nContent-Length: ”，然后跳过该长度
					myfoundresult = kmp_ContentLengthHead(m_pBuffOfTCPStream + pMsg->m_nPos_StartLine + pMsg->m_nLen_StartLine - 2, m_pBuffOfTCPStream+ pMsg->m_nPos_Body);

					if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //找到“\r\nContent-Length: ”
						const char* pBegin_ContentLength = myfoundresult.second;

						myfoundresult = kmp_CRLF(pBegin_ContentLength, m_pBuffOfTCPStream + pMsg->m_nPos_Body);
						if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //找到CRLF
							string tmp(pBegin_ContentLength, myfoundresult.first);

							if (s_rc["[0-9]+"].regex_id() == NULL) {
								s_rc["[0-9]+"] = s_rc.compile("[0-9]+");
							}

							if (boost::xpressive::regex_match(tmp, s_rc["[0-9]+"])) { //合法，则
								int nContentLength = atoi(tmp.c_str());
								pMsg->m_nLen_Body = nContentLength;

								m_nPos_Search = pMsg->m_nPos_Body + nContentLength;
							}
						}//if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //找到CRLF
					}//if (myfoundresult.first != m_pBuffOfTCPStream + pMsg->m_nPos_Body) { //找到“\r\nContent-Length: ”

				}//if (myfoundresult.first != m_pBuffOfTCPStream + m_nBytesOfBuff) { //找到CRLFCRLF
				else {	//未找到CRLFCRLF
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
使用示例：
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