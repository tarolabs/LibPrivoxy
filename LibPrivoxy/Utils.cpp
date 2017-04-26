#include "stdafx.h"
#include "Utils.h"
#include <tcpmib.h>
#include "tchar.h"
#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include <assert.h>

#ifdef FEATURE_ENCRYPTCFG
#include "filebuilder.h"
#include "cryptlib.h"
using CryptoPP::Exception;
#include "aes.h"
using CryptoPP::AES;
#include "ccm.h"
using CryptoPP::CBC_Mode;
#include "modes.h"
using CryptoPP::CFB_Mode;
#include "miscutil.h"
#endif

using namespace std;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FEATURE_ENCRYPTCFG
char *encrypt_msg( const char *msg, int length, BOOL base64_encode_result )
{
	if( !msg || length <= 0 ) return NULL;

	byte key[AES::DEFAULT_KEYLENGTH];
	byte iv[AES::BLOCKSIZE];

	memcpy( key, SYSCBCKEY, AES::DEFAULT_KEYLENGTH );
	memcpy( iv, SYSCBCKEY_IV, AES::BLOCKSIZE );

	char *EncryptedMsg = (char *) zalloc( length );
	if( !EncryptedMsg  ) return NULL;

	//////////////////////////////////////////////////////////////////////////
	// Encrypt
	CFB_Mode<AES>::Encryption cfbEncryption( key, sizeof( key ), iv);
	cfbEncryption.ProcessData((byte *)EncryptedMsg, (const byte *)msg, length );

	if( !base64_encode_result )
		return EncryptedMsg;

	char *Base64edMsg = base64_encode( (const unsigned char *)EncryptedMsg,length );

	free( EncryptedMsg );

	return Base64edMsg ;
}

char *decrypt_msg( const char *msg, int length, BOOL base64_encoded_result )
{
	if( !msg || length <= 0 ) return NULL;

	int DeBase64Len = 0;
	char *DeBase64Msg = NULL;
	if( base64_encoded_result )
	{
		DeBase64Msg = (char *)base64_decode( msg, &DeBase64Len );
	}
	else 
	{
		DeBase64Len = length;

		DeBase64Msg = ( char *) zalloc( DeBase64Len + 1 );
		if( DeBase64Msg )
		{
			memcpy( DeBase64Msg, msg, DeBase64Len );
		}
	}

	if( !DeBase64Msg ) return NULL;

	byte key[AES::DEFAULT_KEYLENGTH] = {0};
	byte iv[AES::BLOCKSIZE] = {0};

	memcpy( key, SYSCBCKEY, sizeof( key ) );
	memcpy( iv, SYSCBCKEY_IV, sizeof( iv ) );

	char *DecryptMsg = (char *)zalloc( DeBase64Len + 1);
	if( !DecryptMsg ) 
	{
		free( DeBase64Msg );
		return NULL;
	}
	//////////////////////////////////////////////////////////////////////////
	// Decrypt
	CFB_Mode<AES>::Decryption cfbDecryption( key, sizeof( key ), iv);
	cfbDecryption.ProcessData((byte *)DecryptMsg, (const byte *) DeBase64Msg, DeBase64Len );

	free( DeBase64Msg );

	return DecryptMsg;
}

unsigned char *read_encrypt_filebody( const char * full_filename )
{
	if( !full_filename ) return NULL;

	CFileBuilder file( full_filename );
	if( !file.Open( TRUE ,FALSE ) ) return NULL;

	return file.Read();;
}

BOOL write_encrypt_filebody( const char *full_filename, const char * filebody, int length )
{
	if( !full_filename || !filebody || length <= 0 ) return FALSE;

	CFileBuilder file( full_filename );
	if( !file.Open( FALSE ,FALSE ) )
		return FALSE;

	file.Write( (unsigned  char *)filebody,length );

	return TRUE;
}
#endif

/** @brief 检测某个TCP端口是否占用了
*
* @returns
* -TRUE: 指定的端口可用
* -FALSE; 指定的端口不可用
*/
BOOL CheckTcpPortValid( WORD nPort )
{
	if (nPort < 1024 || nPort > 65000)
		FALSE;

	PMIB_TCPTABLE ptcptable = NULL; 
	DWORD dwSize = 0; 

	HINSTANCE hInst;		//动态链接库模块句柄
	hInst = LoadLibrary( _T("iphlpapi.dll") );		//动态加载iphlpapi.dll

	//定义函数指针类型
	typedef DWORD  (__stdcall *ADDPROC) (PMIB_TCPTABLE pTcpTable, PDWORD pdwSize, BOOL bOrder);

	//获取iphlpapi.dll导出函数
	ADDPROC GetTcpTable = (ADDPROC) GetProcAddress(hInst, "GetTcpTable"); 

	if (GetTcpTable(ptcptable,&dwSize,TRUE) == ERROR_INSUFFICIENT_BUFFER)		//pTcpTable空间不足
	{ 
		ptcptable=new MIB_TCPTABLE[dwSize];		//为pTcpTable申请足够的空间

		if (GetTcpTable(ptcptable,&dwSize,TRUE) == NO_ERROR)     //GetTcpTable调用成功
		{ 
			//检测端口nPort是否在
			for (UINT i=0; i<ptcptable->dwNumEntries; i++) 
			{ 
				if (nPort != ntohs( ptcptable->table[i].dwLocalPort ) )
					continue;  

				//释放资源
				delete[] ptcptable; 
				FreeLibrary((HMODULE)hInst);

				return FALSE; 
			} 
		} 
	} 
	//释放资源
	delete[] ptcptable; 
	FreeLibrary((HMODULE)hInst);

	return TRUE; 
}

/** @brief 搜索一个未占用的端口
*
* @param nFromPort 起始搜索端口
*/
extern WORD SearchAnUnsedPort( WORD nFromPort ,UINT nSearchAmount)
{
	WORD nFoundPort = 0;
	while( nSearchAmount > 0 )
	{
		// 找到可用的端口
		if( CheckTcpPortValid ( nFromPort ) )
		{
			nFoundPort = nFromPort;
			break;
		}

		nFromPort ++;

		nSearchAmount --;
	}

	return nFoundPort;
}

int explode(const string& input, const string& delimiter, vector<string>& results, bool includeEmpties )
{
	int iPos = 0;
	int newPos = -1;
	int sizeS2 = (int)delimiter.size();
	int isize = (int)input.size();

	if( 
		( isize == 0 )
		||
		( sizeS2 == 0 )
		)
	{
		return 0;
	}

	vector<int> positions;

	newPos = (int)input.find (delimiter, 0);

	if(newPos == string::npos)
	{//没有分隔符，本身当一个
		results.push_back(input);
		return 1;
	}
	/** ?0??? */
	//positions.push_back(0);
	int numFound = 1;
	while( newPos >= iPos )
	{
		numFound++;
		positions.push_back(newPos);
		iPos = newPos;
		newPos =(int) input.find (delimiter, iPos+sizeS2);
	}

	if( numFound == 0 )
	{
		return 0;
	}

	int offset =0 ;
	for( int i=0; i <= (int)positions.size(); ++i )
	{
		string s("");

		if( i == 0)
		{
			s = input.substr( offset, positions[i] ); 
			offset = positions[i] + sizeS2 ;
		}
		else 
		{
			if( i == positions.size() )
			{
				s = input.substr(offset);
				offset = isize ;
			}
			else 
			{
				s = input.substr( offset, positions[i] - positions[i-1] - sizeS2 ); 
				offset = positions[i] + sizeS2 ;
			}
		}

		if( includeEmpties || ( s.size() > 0 ) )
		{
			results.push_back(s);
		}
		//		if( offset >= isize )
		//			break;
	}

	return numFound;
}

string   Replace(string   &str,  string string_to_replace, string new_string)
{   
	//   Find   the   first   string   to   replace   
	int   index   =   str.find(string_to_replace);   
	//   while   there   is   one   
	while(index   !=   std::string::npos)   
	{   
		//   Replace   it   
		str.replace(index,   string_to_replace.length(),   new_string);   
		//   Find   the   next   one   
		index   =   str.find(string_to_replace,   index   +  new_string.length());   
	}   
	return   str;   
}   

string implode(const vector<string>& vec, const char* delim)
{
	stringstream res;
	copy(vec.begin(), vec.end(), ostream_iterator<string>(res, delim));
	return res.str();
}

extern char *implode_user_extend_pac_file( const char *in_str )
{
	vector<string> results;
	assert( in_str );

	string pac_body = string( in_str );

	Replace( pac_body, "\r\n","\n" );

	explode( pac_body, string("\n"), results , false );

	if( results.size() > 0 )
	{
		string strResult;
		int count = (int ) results.size();
		for( int i = 0 ; i < count; i ++ )
		{
			strResult += string(",\"") + results[i] + string( "\":1\r\n" );
		}

		if( strResult.length() > 0 )
		{
			return strdup( strResult.c_str() );
		}
	}
	return NULL;
}

char * strdup_printf(const char* fmt,...)
{
	char *buffer = NULL;
	int len  =  0;
	va_list args;
	va_start (args, fmt);
	len = _vscprintf(fmt,args);
	if(len>0)
	{
		buffer = (char*)malloc(sizeof(char)*(len+1));
		if(buffer)
			vsprintf(buffer,fmt,args);
	}
	va_end (args);
	return buffer;
}
#ifdef __cplusplus
}
#endif