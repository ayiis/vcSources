#ifdef MY_HTTPCONTROLER_H
#define   MY_HTTPCONTROLER_H
static char *www2ip(const char *hostName);
static bool CheckHTTP(const char *url);
static bool fillURLPeremeters(char * url,char* domain, char *path,char *port);
static bool fillURLPeremeters(char * url,char* domain, char *path,int *port);
static int URLEncode(LPCTSTR pszUrl, LPTSTR pszEncode, int nEncodeLen);
#endif
#include "MyString.h"

// get IP Address by HostName
//
static char *www2ip(const char *hostName){
	struct hostent *remoteHost;
	struct in_addr addr;
	if((remoteHost = gethostbyname(hostName))== NULL){
		return "127.0.0.1";
	}
	addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
	return inet_ntoa(addr);
}

// Check if start is a legel URL 
//
static bool CheckHTTP(const char *url){
	if( url[0]=='H' || url[0]=='h')
		if( url[1]=='T' || url[1]=='t')
			if( url[2]=='T' || url[2]=='t')
				if( url[3]=='P' || url[3]=='p')
					if( url[4]==':' && url[5]=='/' && url[6]== '/' )
						return true ;
	return false ;
}

// Take DOMAIN PORT and PATH from URL
//
static bool fillURLPeremeters(char *url,char *domain, char *path,char *port)
{
	if( !CheckHTTP(url) ){			// CHECK HTTP
		return false ;
	}
	char *urlStr = url + 7;			// TAKE AFTER [HTTP://]
	int i = 0,loca = 0;
	while( urlStr[loca]!=0 ){		// STRLEN
		loca++;
	}
	for(i = 0; urlStr[i] != 0; i++){	// GET PATH
		if(urlStr[i] == 0x2F ){
			strCpy(path,urlStr,i,loca);
			break;
		}
	}
	for(loca = 0; loca<i; loca++ ){		// GET PORT
		if(urlStr[loca] == 0x3A ){
			strCpy(port,urlStr,loca+1,i);
			break;
		}
	}
	strCpy(domain,urlStr,0,loca);		 // GET DOMAIN
	return !( a2i(port) & -0x10000);
}
// For normal use
//
static bool fillURLPeremeters(char * url,char* domain, char *path,int *port)
{
	char portStr[0x10] = {0};
	bool ret = fillURLPeremeters(url, domain, path, portStr);
	if( ret == true ){
		*port = a2i(portStr);
		if( *port < 1 || 65535 < *port){
			*port = 80;
		}
		if( !path || path[0] == 0 ){
			path[0] = '/';
			path[1] = 0;
		}
	}
	return ret;
}

// Encode URL to UTF-8
//
static int URLEncode(LPCTSTR pszUrl, LPTSTR pszEncode, int nEncodeLen){
	WCHAR* pWString = new WCHAR[nEncodeLen];
	LPSTR pString = new TCHAR[nEncodeLen];
	MultiByteToWideChar(GetACP(), 0, pszUrl, -1, pWString, nEncodeLen);		// Trans to Unicode
	const int nLength = WideCharToMultiByte(CP_UTF8, 0, pWString, -1, pString, nEncodeLen, NULL, NULL) -1;	// Trans to UTF-8
	for( int i = 0; i < nLength && i + 3 <nEncodeLen; i++ ){
		unsigned char ch = pString[i];
		if( 0x23 < ch && ch < 0x7f ){	// From 0x24[$] to 0x7e[~]
			*pszEncode++ = ch;
		}
		else{
			*pszEncode++ = 0x25;		// %
			*pszEncode++ = Hexc[ch >> 0x04];
			*pszEncode++ = Hexc[ch % 0x10];
		}
	}
	*pszEncode = 0;
	delete[nEncodeLen] pWString;	// Clean Memory
	delete[nEncodeLen] pString;
	return nLength;
}
