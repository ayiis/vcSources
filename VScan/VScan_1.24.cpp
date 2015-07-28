
//	VScan	v1.24 Read ON
//	2013-03-25
//	2013-05-06
//	2013-06-05
//	2013-06-12	v1.20
//	2014-07-22	v1.22
//	2014-07-30	v1.23
//	2014-08-04	v1.24 Read ON

#include <WinSock2.h>
#include <Windows.h>
#include <process.h>
#include <string>
#include "HttpControler.h"
#pragma comment(lib,"ws2_32.lib")

#define Max_PATH 360
#define MAX_THREAD_NUMS 64
#define RECV_BUF_SIZE 1024
#define TIMEOUT 4096
#define SLEEP_TIME 8
#define PSTATUE 128
#define Method_GET   "GET %s%s HTTP/1.0\r\nHost:%s\r\nAccept:*/*\r\n\r\n"
#define Method_HEAD "HEAD %s%s HTTP/1.0\r\nHost:%s\r\n\r\n"


char WEB_IP[18] = {0};	// IP地址
int  WEB_PORT = 80;		// 端口
char WEBSITE[64] = {0};	// 网站Host
char WEBPATH[256] = {0};// 起始路径

long iThreadCount = 0;	// 创建的线程数目计数
bool GET_HEAD = true;	// 默认是GET的true，HEAD是false	/--/ 用HEAD代替GET可以减轻服务器压力，提高速度。但有些防火墙不允许HEAD，只允许GET和POST
bool SAVE_Y = false;		// 是否保存扫描的结果文件
bool EXIT_FLAG = false;		// 退出标志（按下了CTRL+C），文件是否已经读取完毕 
long fileline=0, badcount = 0, rcount = 0;	// 读取的行数，Socket错误次数，成功探测到的路径数

CRITICAL_SECTION beswapRead,beswapWrite;	// 临界区声明,读文件临界区，输出/写文件临界区
FILE *fpRead,*fpWrite;	// 输入文件和输出文件


// 退出事件的监听函数
// 此处保留 CTRL + BREAK 的强制停止方式
// 
BOOL WINAPI ConsoleHandler(DWORD msgType){
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


// 输出并保存到文件
//
void saveAout(char *output){
	if(SAVE_Y){
		fputs(output,fpWrite);
	}
	printf("%s",output);
}


// 测试本程序对目标是否有效
//
bool Detect(const char *ip,const int port){
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.S_un.S_addr = inet_addr(ip);
	SOCKET sClient = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

	if(connect(sClient,(sockaddr*)&sin,sizeof(sin))==SOCKET_ERROR){
		printf("\n***Target may not be reachable i guess.Check the url or port.\n");
		return false;
	}

	char buf[RECV_BUF_SIZE] = {0};
	sprintf( buf, GET_HEAD ? Method_GET : Method_HEAD , WEBPATH, "", WEBSITE );
	send( sClient, buf, strlen(buf), 0 );
	char rec[RECV_BUF_SIZE] = {0};
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
	if( sCode < 100 || sCode > 600){
		printf("\n***Sorry, got an invalid Status Code %d\n",sCode);
		return false;
	}
	else{
		sprintf(buf,"%s*GOT STATUS CODE: %d\n",buf,sCode);
	}
	saveAout(buf);
	return true;
}

// 线程函数，作了大量优化
//
unsigned _stdcall _callThread(void*){
	char buf[RECV_BUF_SIZE] = {0};
	char tmpBuf[MAX_PATH] = {0};
	char tmpBuf2[Max_PATH] = {0};
	char *METHOD = GET_HEAD ? Method_GET : Method_HEAD;
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(WEB_PORT);	// 全局的端口
	sin.sin_addr.S_un.S_addr = inet_addr(WEB_IP);	// 全局的IP

	while( EXIT_FLAG==false ){

		EnterCriticalSection(&beswapRead);
//------------------------------进入第一临界区 读--------------------------------
//

		if( EXIT_FLAG || !fgets(tmpBuf, MAX_PATH, fpRead) ){
			EXIT_FLAG = true;
			LeaveCriticalSection(&beswapRead);
			break;
		}		
		if(tmpBuf[strlen(tmpBuf)-1] == '\n'){		// 去除行尾的换行符
			tmpBuf[strlen(tmpBuf)-1] = 0;
		}
		++fileline;
		if( fileline%PSTATUE==0 && strlen(tmpBuf)<30 )	printf("%-76s%c",tmpBuf,13);	// 输出扫描进度

//
//------------------------------退出第一临界区-----------------------------------
		LeaveCriticalSection(&beswapRead);

		SOCKET sClient = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
		if(connect(sClient,(sockaddr*)&sin,sizeof(sin))==SOCKET_ERROR){
			closesocket(sClient);
			Sleep(SLEEP_TIME*SLEEP_TIME);
			continue;
		}

		URLEncode(tmpBuf,tmpBuf2,Max_PATH);	// 进行URL编码，将结果返回tmpBuf2中
		sprintf( buf, METHOD, WEBPATH, tmpBuf2, WEBSITE );

		send( sClient,buf,strlen(buf),0 );
		if(recv(sClient,buf,13,0) == SOCKET_ERROR){	// 只需要接收到状态字就可以了 13
			InterlockedIncrement(&badcount);	// 统计socket的失败次数
			closesocket(sClient);
			Sleep(SLEEP_TIME*SLEEP_TIME);
			continue;
		}
		closesocket(sClient);
		buf[12] = 0;

		int sCode=a2i(buf+9);
		if ( sCode != -1 ){
			if( sCode != 400 && sCode != 404 ){		// 如果状态字不是 400,404
				sprintf(buf,"%-28s \t{%d}\n",tmpBuf,sCode);	// 控制输出格式
//				InterlockedIncrement(&rcount);
				EnterCriticalSection(&beswapWrite);
//------------------------------进入第二临界区 写--------------------------------
//
				++rcount;
				saveAout(buf);
//
//------------------------------退出第二临界区-----------------------------------
				LeaveCriticalSection(&beswapWrite);
			}
		}
	}
	InterlockedDecrement(&iThreadCount);
	return 0;
}


// 使用帮助
//
void usage(const char *argv0){
	printf("\n Vscan 1.24[Read ON] usage:\n\t%s +[Method] +[URL+Port+Path] +[Dic.txt] -[Threads] -[/Ss]\n",argv0);
	printf("\n\t%s HEAD http://www.ayiis.me dir.txt",argv0);
	printf("\n\t%s GET  http://www.ayiis.me/root dir.txt",argv0);
	printf("\n\t%s GET  http://www.ayiis.me/root dir.txt %d /s\n",argv0,MAX_THREAD_NUMS);
}


// 独立的线程调用函数
//
void startThreadVoid(const int thisThread_Nums){

	InitializeCriticalSectionAndSpinCount(&beswapRead, 0x80000400);		// InitializeCriticalSection(&beswapRead);
	InitializeCriticalSectionAndSpinCount(&beswapWrite, 0x80000400);	// InitializeCriticalSection(&beswapWrite);
//---------------------------------------进入线程同步的临界区----------------------------------
//
//

	HANDLE *hThreads = new HANDLE[thisThread_Nums];	// 根据最大线程数创建线程
	ZeroMemory(hThreads,sizeof(HANDLE)*thisThread_Nums);

	for( iThreadCount = 0; iThreadCount < thisThread_Nums ; iThreadCount++){		// 申请挂起的线程,数量为thisThread_Nums
		HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, _callThread, NULL, CREATE_SUSPENDED, NULL);
		if(hThread==NULL){
			printf("***Create thread fail!!\n");
			EXIT_FLAG = true;
			break;
		}
		hThreads[iThreadCount] = hThread;		// 统计线程数
	}

	// 恢复挂起的线程，数量为iThreadCount
	for(int iReCount=0;iReCount<iThreadCount;iReCount++){
		ResumeThread(hThreads[iReCount]);
		Sleep(SLEEP_TIME);
	}

	while( EXIT_FLAG == false && iThreadCount > 0 ){	// 进入循环等待，直到手动停止[CTRL+C]或者字典读完
		Sleep(SLEEP_TIME*SLEEP_TIME*SLEEP_TIME);
	}

	for(int iGroup = 0 ; 0 < iThreadCount ; iGroup++, iThreadCount -= MAXIMUM_WAIT_OBJECTS ){	// 循环等待所有线程退出
		WaitForMultipleObjects(
			iThreadCount > MAXIMUM_WAIT_OBJECTS ? MAXIMUM_WAIT_OBJECTS : iThreadCount,
			hThreads + iGroup * MAXIMUM_WAIT_OBJECTS,
			TRUE,			// FALSE will be faster, but TRUE is safer
			TIMEOUT);
		Sleep(SLEEP_TIME);
	}

	delete[thisThread_Nums] hThreads;	// 清理线程

//
//
//---------------------------------------退出线程同步的临界区----------------------------------	
	DeleteCriticalSection(&beswapRead);
	DeleteCriticalSection(&beswapWrite);
}


// 主函数
//
int main(int argc,char **argv){

	SetConsoleCtrlHandler( (PHANDLER_ROUTINE) ConsoleHandler, TRUE);	// 监听[CTRL+C]等事件

	if( argc < 3 || argc > 6 ){		// 检查参数是否合法
		usage(argv[0]);
		return -1;
	}

	int arg = argc;

	if (!lstrcmpi(argv[arg-1], "/S")){		// 是否将扫描结果输出log
		SAVE_Y = true;
		arg--;
	}

	if( argv[1][0]=='H' || argv[1][0]=='h' ){	// 定义数据的提交方式，GET or HEAD
		GET_HEAD=false;
	}

	if(fillURLPeremeters(argv[2],WEBSITE,WEBPATH,&WEB_PORT)==false){	// 提取 域名 路径 端口
		printf("\n***Unrecognizable URI\n");
		usage(argv[0]);
		return -1;
	}

	int thisThread_Nums = MAX_THREAD_NUMS;	// 定义最大线程数量
	if( 5<=arg ){
		if( a2i(argv[4]) != -1 ){
			thisThread_Nums = a2i(argv[4]);
		}
		else{
			printf("**Warning: illegal Threads.Reset Threads to %d.\n",MAX_THREAD_NUMS);
		}
	}

	WSADATA wsa;
	WSAStartup(MAKEWORD(2,2),&wsa);

	strcpy(WEB_IP,www2ip(WEBSITE));		// 获得域名的解析IP
	SYSTEMTIME sysTime;			// 使用系统时间计时
	GetLocalTime( &sysTime );	// 获取系统时间
	double startTime=((sysTime.wHour*60+sysTime.wMinute)*60+sysTime.wSecond)*1000+sysTime.wMilliseconds;

	if(SAVE_Y == true){		// 如果需要保存扫描结果
		fpWrite=fopen("Pscan_result.txt","a");		// 用输出追加方式打开Pas_result.txt
		if(!fpWrite){
			printf("**Cannot save to result file!\n");
			SAVE_Y = false;
		}
		else{	// 在输出文件里写入基本的信息
			fprintf(fpWrite,"\n\n-------------------------------------------%4d-%02d-%02d %02d:%02d:%02d\n"
				,sysTime.wYear,sysTime.wMonth,sysTime.wDay
				,sysTime.wHour,sysTime.wMinute,sysTime.wSecond);
			fprintf(fpWrite,"**Using [%s] Scanning %s%s with %s using %d Threads\n", GET_HEAD?"GET":"HEAD", WEBSITE, WEBPATH, arg > 3 ? argv[3] : "[NONE]", thisThread_Nums);
		}
	}

	char outBuf[RECV_BUF_SIZE] = {0};

	sprintf(outBuf,"\n*Resolved IP: %s\n",WEB_IP);
	saveAout(outBuf);

	if( !Detect( WEB_IP , WEB_PORT ) ){		// 在线程开始之前先进行探测，如果返回错误则说明本程序不适合目标
		printf("***Error code: %d\n",GetLastError());
		return -1;
	}

	if( arg <= 3  || (fpRead=fopen(argv[3],"r"))==NULL ){		// 打开字典文件，放在这里是为了即使不存在字典也可以先进行上一步侦测返回信息
		saveAout("\n***ERROR: Dic open error\n");
		return -1;
	}

	saveAout("\n-------------Trying-----------\n");

	startThreadVoid(thisThread_Nums);	// 调用多线程,核心部分

	sprintf(outBuf,"-------------Done!------------\n");

	GetLocalTime( &sysTime );
	double duration = (((sysTime.wHour*60+sysTime.wMinute)*60+sysTime.wSecond)*1000+sysTime.wMilliseconds - startTime)/1000;	// 计时
	sprintf(outBuf,"%s\n*Scan Target %s:",outBuf,WEBSITE);
	sprintf(outBuf,"%s\n\tRequset = %d, BadRequest = %d",outBuf,fileline,badcount);
	sprintf(outBuf,"%s\n\tTime = %.3fs, Speed = %.1f L/s",outBuf,duration,(double)fileline/duration);
	sprintf(outBuf,"%s\n\tDetected Path = %d\n",outBuf,rcount);
	saveAout(outBuf);	// 输出/写入到记录文件

	WSACleanup();		// 清理
	if(fpRead)	fclose(fpRead);		// 关闭文件
	if(fpWrite) fclose(fpWrite);	// 关闭文件
	return 0;
}
