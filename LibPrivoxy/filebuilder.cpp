//#include "stdafx.h"
//#include <afxwin.h>
#include <windows.h>
#include <assert.h>
#include <string.h>
#include <STDLIB.H>
#include "filebuilder.h"
//#include "openssl/md5.h"
//#include "openssl/des.h"
#include "Utils.h"
//#include "../lib.h"
#include "cryptlib.h"
using CryptoPP::Exception;
#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
#include "aes.h"
using CryptoPP::AES;
#include "ccm.h"
using CryptoPP::CBC_Mode;
#include "modes.h"
using CryptoPP::CFB_Mode;
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "md5.h"

#include <io.h>
#include <sys/stat.h>
//using CryptoPP::Weak;

/*
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
*/
//#pragma comment(lib,"libeay32.lib")
//#pragma comment(lib,"ssleay32.lib")
//#pragma comment(lib,"cryptlib32.lib")

unsigned char CFileBuilder::cfb_iv[8]={0x02,0x19,0x38,0xea,0xa9,0x0a,0xd9,0xee};
extern int errno; 
#define FILE_CLOSE(x) { if( x ) { fclose( x ); x = NULL ; } }

CFileBuilder::CFileBuilder( )
{
	file_handle = NULL;
	pFileBuffer = NULL;
	m_bBareMode = false;

	nFileBodyLength = 0;
	nFileLength = 0;

	memset( szPathFile,0, sizeof(TCHAR) * 1024 );
}


CFileBuilder::CFileBuilder(const TCHAR *file)
{
	assert( file != NULL );

	file_handle = NULL;
	pFileBuffer = NULL;
	m_bBareMode = false;

	nFileBodyLength = 0;
	nFileLength = 0;
	
	if( file )
		_tcsncpy_s(szPathFile,260 , file, 259 );
}

CFileBuilder::~CFileBuilder()
{
	MY_FREE(pFileBuffer);
	Close();
}
void CFileBuilder::des_encrypt(unsigned char *in,unsigned char *out,unsigned int length)
{
	byte key[AES::DEFAULT_KEYLENGTH];
	byte iv[AES::BLOCKSIZE];

	memcpy( key, SYSCBCKEY, AES::DEFAULT_KEYLENGTH );
	memcpy( iv, SYSCBCKEY_IV, AES::BLOCKSIZE );

	//////////////////////////////////////////////////////////////////////////
	// Encrypt
	CFB_Mode<AES>::Encryption cfbEncryption( key, sizeof( key ), iv);
	cfbEncryption.ProcessData(out, in, length );
}
void CFileBuilder::des_decrypt(unsigned char *in,unsigned char *out,unsigned int length)
{
	byte key[AES::DEFAULT_KEYLENGTH] = {0};
	byte iv[AES::BLOCKSIZE] = {0};

	memcpy( key, SYSCBCKEY, sizeof( key ) );
	memcpy( iv, SYSCBCKEY_IV, sizeof( iv ) );

	//////////////////////////////////////////////////////////////////////////
	// Encrypt
	CFB_Mode<AES>::Decryption cfbDecryption( key, sizeof( key ), iv);
	cfbDecryption.ProcessData(out, in, length );
}
#if 0
void CFileBuilder::des_encrypt(unsigned char *in,unsigned char *out,unsigned int length)
{
	static unsigned char  cfb_tmp[8];
	static unsigned char cfb_key[8];
	des_key_schedule ks;
	memcpy(cfb_key,SYSCBCKEY,8);
	DES_set_key_unchecked(&cfb_key,&ks);
	memcpy(cfb_tmp,CFileBuilder::cfb_iv,sizeof(CFileBuilder::cfb_iv));
	des_cfb_encrypt(in,out,8,length,ks,&cfb_tmp,DES_ENCRYPT);
}
void CFileBuilder::des_decrypt(unsigned char *in,unsigned char *out,unsigned int length)
{
	static unsigned char  cfb_tmp[8];
	static unsigned char cfb_key[8];
	des_key_schedule ks;
	memcpy(cfb_key,SYSCBCKEY,8);
	DES_set_key_unchecked(&cfb_key,&ks);
	memcpy(cfb_tmp,CFileBuilder::cfb_iv,sizeof(CFileBuilder::cfb_iv));
	des_cfb_encrypt(in,out,8,length,ks,&cfb_tmp,DES_DECRYPT);
}
#endif

unsigned char * CFileBuilder::ReadOrignalFileBody()
{
	unsigned char *filebuffer = NULL;
	long filelength = 0;

	if( !file_handle ) return NULL;

	nFileLength = filelength = _GetFileLength();
	if( !filelength ) return NULL;

	// 多分配一个字节,文本内容方便处理
	filebuffer = (unsigned char*)malloc( ( filelength + 1 ) );
	memset( filebuffer , 0 , filelength + 1 );

	fseek( file_handle, 0, SEEK_SET ); // move the file pointer to beginning of file.
	fread( filebuffer , 1, filelength , file_handle );

	return filebuffer;
}

unsigned char * CFileBuilder::Read( )
{
	unsigned char *filebuffer = NULL,*tempbuffer =NULL;
	unsigned char md5_org[32]={0};
	//int readlen =0;

	if( !IsFileOpend() )
	{
		nLastError = ERR_OPENFILE;
		return NULL;
	}

	MY_FREE(pFileBuffer);

	// 读出原始文件内容
	filebuffer = ReadOrignalFileBody();
	if(!filebuffer)
	{
		nLastError = ERR_OPENFILE;
		return NULL;
	}

	if( m_bBareMode ) 
	{
		nLastError=ERR_OK;
		
		nFileBodyLength = nFileLength;

		// 我们大多数处理字符串, 多加一个字节,给字符一个结束符,方便处理
		tempbuffer = (unsigned char*)malloc( sizeof(char) * ( nFileLength + 1) );
		if( !tempbuffer )
		{
			MY_FREE(filebuffer);
			nLastError = ERR_OPENFILE;
			return NULL;
		}
		
		memset( tempbuffer,0, sizeof(char) * ( nFileLength + 1) );
		memcpy( tempbuffer, filebuffer,nFileLength );
		
		pFileBuffer = tempbuffer;
		MY_FREE(filebuffer);

		return pFileBuffer;
	}

	tempbuffer = filebuffer;
	// checking begin flag.
	if(memcmp(tempbuffer,FILE_BEGINFLAG,4)!=0)
	{
		MY_FREE(filebuffer);
		nLastError = ERR_BEGINFLAG;
		return NULL;
	}
	// skip begin flag
	tempbuffer += 4;
	// cheching version info.
	if( *tempbuffer != FILE_VERSION1 || *(tempbuffer+1)!=FILE_VERSION2 || *(tempbuffer +2)!=FILE_VERSION3 || *(tempbuffer +3 )!= FILE_VERSION4 )
	{
		MY_FREE(filebuffer);
		nLastError= ERR_VERSION;
		return NULL;
	}
	// skip version
	tempbuffer +=4;
	int leng_copyright = (int)strlen( FILE_COPYRIGHT );
	// checking copyright
	if( _strnicmp((char *)tempbuffer,FILE_COPYRIGHT,leng_copyright )!=0) 
	{
		MY_FREE(filebuffer);
		nLastError= ERR_COPYRIGHT;
		return NULL;
	}

	// skip copyright.
	tempbuffer += leng_copyright; 
	memcpy(md5_org,tempbuffer,FILE_MD5LEN);

	// skip md5
	tempbuffer += FILE_MD5LEN;

	int body_length = 0;
	memcpy( &body_length,tempbuffer, 4 );
	if( body_length <= 0 ){
		MY_FREE(filebuffer);
		nLastError= ERR_EMPTYBODY;
		return NULL;
	}

	// skip body length
	tempbuffer += 4;

	unsigned char *tempbuffer_1 = filebuffer + (nFileLength - 4);
	// checking end flag
	if(memcmp(tempbuffer_1,FILE_ENDFLAG,4)!=0) 
	{
		MY_FREE(filebuffer);
		nLastError= ERR_ENDFLAG;
		return NULL;
	}

	unsigned char *body_buffer = (unsigned char *)malloc( body_length + 1 );
	if(!body_buffer){
		MY_FREE(filebuffer);
		nLastError= ERR_OTHER;
		return NULL;
	}

	memset(body_buffer,0,body_length + 1 );
	des_decrypt(tempbuffer,body_buffer,body_length );

	//MD5(body_buffer,body_length,md5_dst);
	CryptoPP::Weak::MD5 hash;
	byte md5_dst[ CryptoPP::Weak::MD5::DIGESTSIZE ] ={0};
	hash.CalculateDigest( md5_dst, (byte*) body_buffer, body_length );

	if(memcmp(md5_org,md5_dst,FILE_MD5LEN)!=0){
		MY_FREE(filebuffer);
		MY_FREE(body_buffer);
		nLastError=ERR_MD5;
		return NULL;
	}

	//memcpy(tempbuffer,filebuffer+FILE_BEGIN_LENGTH,readlen - FILE_ALLFLAG_LENGTH);
	nLastError=ERR_OK;
	MY_FREE(filebuffer);

	nFileBodyLength = body_length;
	pFileBuffer = body_buffer;
	
	return pFileBuffer;
}

BOOL CFileBuilder::Write( unsigned char *buffer,int leng )
{
	unsigned char version[4];
	unsigned char *tempbuffer =0;
	//unsigned char md5_dst[32];
	long nTempContentLength = 0;
	
	if( buffer == NULL || !IsFileOpend()  )
	{
		nLastError = ERR_OTHER;
		return FALSE;
	}
	
	tempbuffer = (unsigned char *) malloc(leng);
	if(!tempbuffer) 
	{
		nLastError = ERR_OTHER;
		return FALSE;
	}

	memset(tempbuffer,0,leng);

	if( !m_bBareMode )
	{
		//MD5(buffer,leng,md5_dst);
		CryptoPP::Weak::MD5 hash;
		byte md5_dst[ CryptoPP::Weak::MD5::DIGESTSIZE ]={0};
		hash.CalculateDigest( md5_dst, (byte*) buffer, leng );

		des_encrypt(buffer,tempbuffer,leng);
		fwrite(FILE_BEGINFLAG,1,4, file_handle );//begin flag
		nTempContentLength = 4;

		version[0]=FILE_VERSION1;
		version[1]=FILE_VERSION2;
		version[2]=FILE_VERSION3;
		version[3]=FILE_VERSION4;

		fwrite(version,1,4, file_handle);	//version
		nTempContentLength += 4;

		int leng_copyright = (int)strlen( FILE_COPYRIGHT );
		fwrite(FILE_COPYRIGHT,1,leng_copyright,file_handle);//copyright
		nTempContentLength += leng_copyright;

		fwrite(md5_dst,1,FILE_MD5LEN,file_handle);	//md5 check
		nTempContentLength += FILE_MD5LEN;

		fwrite( &leng,1,4,file_handle );	// buffer length.
		nTempContentLength +=4;

		fwrite( tempbuffer,1,leng,file_handle ); //buffer
		nTempContentLength += leng;

		fwrite(FILE_ENDFLAG,1,4,file_handle);//end flag
		fflush( file_handle );

		nTempContentLength += 4;

		nFileLength = nTempContentLength;
		nFileBodyLength = leng;
	}
	else 
	{
		fwrite(buffer,1,leng,file_handle); // buffer
		fflush( file_handle );

		nFileLength = leng;
		nFileBodyLength = leng;
	}

	MY_FREE(tempbuffer);
	nLastError = ERR_OK;

	return TRUE;
}
// 看文件是否存改了.
// lastModified:  会将文件的最后修改时间和这个比较,以判断是否在这个时间之后被改过了.
// 如果文件被修改过了, lastModified 参数将被修改为文件最后修改时间.
BOOL CFileBuilder::IsFileModified( time_t &lastModified )
{
	struct stat fs;

	if( !file_handle )
		return FALSE;

	fstat( _fileno( file_handle ), &fs );
	
	if( fs.st_mtime == lastModified )
		return FALSE;

	lastModified = fs.st_mtime;

	return TRUE;
}

BOOL CFileBuilder::GetFileLastModifiTime( time_t &lastModified )
{
	struct stat fs;

	if( !file_handle )
		return FALSE;

	fstat( _fileno( file_handle ), &fs );

	lastModified = fs.st_mtime;

	return TRUE;
}

void CFileBuilder::Close()
{
	FILE_CLOSE( file_handle );
}

/** @brief 打开文件.
	*
	* @param bRead 
	* - TRUE: 以2进制读的方式打开文件
	* - FALSE: 以2进制写的文件打开文件
	*
	* @return
	* - TRUE: 打开文件成功
	* - FALSE: 打开文件失败
	*/
BOOL CFileBuilder::Open( BOOL bRead , BOOL bShowErrorMsg )
{
	FILE *f=NULL;
	FILE_CLOSE( file_handle );

	TCHAR *open_file_mode = _T("rb");
	if( bRead == FALSE )
		open_file_mode = _T("wb");
	
	f = _tfsopen( szPathFile, open_file_mode, _SH_DENYNO );
	if( !f )
	{
		if( bShowErrorMsg )
		{
			TCHAR errmsg[500]={0};
			int errret = _tcserror_s( errmsg, 500, errno );
			if( errret == 0 )
			{
				TCHAR szErrorMsgShow[1000] = {0};
				_stprintf_s( szErrorMsgShow, 1000, _T("Open file %s error, error msg: %s"), szPathFile, errmsg );
				::MessageBox(NULL, szErrorMsgShow, _T("Open file in CFileBuilder::Open"),MB_OK );
			}
		}

		nLastError = ERR_OPENFILE;
		return FALSE;
	}
	file_handle = f;

	nLastError = ERR_OK;

	return TRUE;
}

/** @brief 获取原始文件长度, 调用_filelength
*/
long CFileBuilder::_GetFileLength()
{
	if( file_handle == NULL ) return 0;

	return _filelength( file_handle->_file );
}
