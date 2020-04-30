// FindHTTPFirstLineInTCPStream.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "HTTPMessageSearcher.hpp"

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

int main()
{
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
	


 //   std::cout << "Hello World!\n";


	//static boost::xpressive::sregex_compiler s_rc;
	//if (s_rc["[0-9]+\\.[0-9]+"].regex_id() == NULL) {
	//	s_rc["[0-9]+\\.[0-9]+"] = s_rc.compile("[0-9]+\\.[0-9]+");
	//}

	//if (!boost::xpressive::regex_match(string("154354230.52345.2354235235234523"), s_rc["[0-9]+\\.[0-9]+"])) { //不合法，则
	//	std::cout << "不合法\n";
	//}
	//else {
	//	std::cout << "合法\n";
	//}

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件


//
//
//class A
//{
//public:
//	A()  {}
//	~A() {}
//
//public:
//	enum em
//	{
//		TYPE1,
//		TYPE2
//	} m_emType;
//public:
//	void SetType(em emType)
//	{
//		m_emType = emType;
//	}
//
//	em GetType()  const
//	{
//		return m_emType;
//	}
//};
//
//
//int main()
//{
//	A a, b;
//	a.SetType(A::TYPE1);
//	b.SetType(A::TYPE1);
//
//	if (b.GetType() == a.GetType())	{
//		std::cout << "a==b" << std::endl;
//	}
//	else {
//		std::cout << "a!=b" << std::endl;
//	}
//	return 0;
//}
