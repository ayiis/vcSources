#ifdef MY_STRING_H
#define   MY_STRING_H
static int a2i(char *sc);
static int strLen(char *inStr);
static void strCpy(char *strTo,char *strFrom, int iStart,int iEnd);
#endif
static char Hexc[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
// Transfer string to int
//
static int a2i(char *sc){
	int i=0,num=0;
	for(i = 0; sc[i]!=0 ; i++){
		if(sc[i]<48 || sc[i]>57){
			return -1;
		}
		else{
			num=num*10+sc[i]-48;
		}
	}
	return num;
}

// strLen
//
static int strLen(char *inStr)
{
	int i = 0;
	while(inStr[i]!=0){
		i++;
	}
	return i;
}

// Loca
//
int Loca(char *orgStr,char c)
{
	for(int i=0;orgStr[i]!=0;i++){
		if(orgStr[i]==c){
			return i;
		}
	}
	return -1;
}

// toUpper
//
char CharToUpper(char inStr){

	if(inStr < 'a' || inStr > 'z')
	{
		return inStr;
	}
	return inStr -32;
}

// return the first matched location
//
bool startWithA(char *orgStr, char *ptnStr){
	if( strLen(orgStr) < strLen(ptnStr) )
	{
		return false;
	}
	for(int i=0 ; ptnStr[i]!=0 ; i++){
		if(orgStr[i] != ptnStr[i] && orgStr[i] != CharToUpper(ptnStr[i])){
			return false ;
		}
	}
	return true;
}

// strcpy 
//
static void strCpy(char *strTo,char *strFrom, int iStart,int iEnd)
{
	int i = 0;
	for(i = 0; i+iStart<iEnd && strFrom[i+iStart]!=0; i++){
		strTo[i] = strFrom[i+iStart];
	}
	strTo[i] = 0;
}
