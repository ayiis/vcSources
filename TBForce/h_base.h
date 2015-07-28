#define Max_PATH 360
// 将字符串进行URL编码
//
void M_URLEncode(const char* str, const int strSize, char* result, const int resultSize) {
	int j = 0; /* for result index */
	char ch;

	for (int i = 0 ; ( i < strSize ) && ( j + 3 < Max_PATH ); i++ ) {
		ch = str[i]; 

		// 在 % （包括）之后，和 } （包括）之前的字符都直接返回
		if ( ch >= 36 && ch <= 125 )
			result[j++] = ch;

		else {	// 将在 # （包括）之前的和 ～（包括）之后的字符进行URL编码
			sprintf(result+j, "%%%02X", (unsigned char)ch);
			// 编码后长度需变为3
			j += 3;
		}
	}
	result[j] = '\0';
}

// 将域名转换为IP地址，GetHostByName
//
char *www2ip(char *argv1){
	struct hostent *remoteHost;
	struct in_addr addr;

	// 无法解析域名则返回127.0.0.1
	if((remoteHost = gethostbyname(argv1))== NULL)
		return "127.0.0.1";

	// 获取第一个解析IP
	addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
	return inet_ntoa(addr);
}


// 字符串转整数
//
int a2i(char *sc){
	int i,len=0,num=0;

	while(sc[len]!='\0')
		len++;

	for(i=0;i<len;i++){
		if(sc[i]<48 || sc[i]>57)
			return -1;
		else
			num=num*10+sc[i]-48;
	}
	return num;
}

// 从地址提取 域名 端口 和 路径
//
bool urlFormatF(const char* url,char* domain,char *path,int *port){
	int len=0;
	int i,j,k;
	char po[7];

	while(url[len]!='\0')
		len++;
	
	// check the format of url
	if(len<10)	// check min len
		return false;

	if( url[0]!='H' && url[0]!='h') //check fromat with "http://"
		return false;
	if( url[1]!='T' && url[1]!='t' || url[2]!=url[1] )
		return false;
	if( url[3]!='P' && url[3]!='p')
		return false;
	if( url[4]!=':' || url[5]!='/' || url[6]!='/' )
		return false;
	
	//*** start for ***//
	for(i=7;i<len;i++){

		// if meet ':' first
		// Like http://www.ayiis.me:8080/wwwroot/admin
		//
		if( url[i]==':' ){
			for( j=0 ; j<i-7 ; j++ )
				domain[j] = url[7+j];
			domain[j]='\0';

			for( j=0; j<7 && url[i+j+1]!='\0' ; j++ ){

				if( j==6 )
					return false;

				if( url[i+j+1]=='/' ){
					if( j==0 )
						return false;
					else
						break;
				}

			}
			for( k=0 ; k<j ; k++ )
				po[k]=url[i+k+1];
			po[k]='\0';

			*port = a2i(po);

			if( *port<1 || 65535<*port )
				return false;

			for( k=0; k<len-i-j ; k++ )
				path[k]=url[i+j+k+1];
			path[k]='\0';

			return true;
		}


		// If meet '/' first
		// Like http://www.ayiis.me/wwwroot/admin
		//
		else if( url[i]=='/' ){
			for( j=0 ; j<i-7 ; j++ )
				domain[j] = url[7+j];
			domain[j]='\0';

			*port=80;

			for( k=0; k<len-i ; k++ )
				path[k]=url[i+k];
			path[k]='\0';
			return true;
		}
	}
	//*** end for ***//

	// No '/' or ':' contain in the rest url
	// Like http://www.ayiis.me
	//
	for( j=0 ; j<len-7 ; j++ )
		domain[j] = url[7+j];
	domain[j]='\0';
	*port=80;
	path[0]='\0';
	
	return true;
}
