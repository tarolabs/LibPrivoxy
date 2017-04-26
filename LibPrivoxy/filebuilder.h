#pragma once
#include <tchar.h>

#define SYSCBCKEY "*&-sockscap64-&*dkdksdkj83-02(*&#!@&*(@)(*%)jsdfuio)(*$)*@#$"
#define SYSCBCKEY_IV "000000000000000000000000000000000000000000000000000000000000000"

#define FILE_BEGINFLAG "MC##" // 4 bytes
#define FILE_VERSION1 1
#define FILE_VERSION2 1
#define FILE_VERSION3 1
#define FILE_VERSION4 1
#define FILE_COPYRIGHT "sockscap64.com#"
#define FILE_ENDFLAG "#MC\0"

#define ERR_OK			0
#define ERR_BEGINFLAG	1			// 文件起始标识错误.
#define ERR_VERSION		2			// 版本错误
#define ERR_COPYRIGHT	3			// 版权错误
#define ERR_ENDFLAG		4			// 文件结束标识错误
#define ERR_OPENFILE	5			// 打开文件错误
#define ERR_MD5			6			// 内容MD5错误
#define ERR_OTHER		7			// 其它错误
#define ERR_EMPTYBODY	8			// 内容为空.
#define ERR_COMPRESS    9			// 压缩或者解压缩失败
#define ERR_BASE64      10

/** 我们专有的文件扩展名*/
#define FILE_EXTENSION	".dat"
#define FILE_BGFLAG_LENGTH (8 + strlen( FILE_COPYRIGHT ) ) // 4 (begin flag) + 1 + 1 + 1 + 1 ( version ) + strlen( copyright ) 
#define FILE_MD5LEN	16	// md5 length 16 bytes
#define FILE_BEGIN_LENGTH (FILE_BGFLAG_LENGTH+FILE_MD5LEN)
#define FILE_BODY_LENGTH_FLAG 4 // 真实的文件内容长度(4字节) 紧接着就是之后的真正的文件内容
#define FILE_END_LENGTH 4	// 4 bytes
#define FILE_ALLFLAG_LENGTH (FILE_BEGIN_LENGTH + FILE_BODY_LENGTH_FLAG + FILE_END_LENGTH)  // 除了文件内容之外的其它标识总长度

#ifndef MY_FREE
#define MY_FREE(x) {if(x) { free( x ); x = NULL; } }
#endif
/** \brief
* 本程序专属文件类
* 
* \author blode(blodes@gmail.com)
*/
#define   BASICLIB_API

class BASICLIB_API CFileBuilder
{
public:
	CFileBuilder();
	CFileBuilder(const TCHAR *file);
	~CFileBuilder();

	/** @brief 打开文件.
	*
	* @param bRead 
	* - TRUE: 以2进制读的方式打开文件
	* - FALSE: 以2进制写的文件打开文件
	*
	* @param bShowErrorMsg 如果打开出错时是否显示错误信息.
	* 
	* @return
	* - TRUE: 打开文件成功
	* - FALSE: 打开文件失败
	*/
	virtual BOOL Open( BOOL bRead = TRUE , BOOL bShowErrorMsg = FALSE );

	unsigned char * Read( );
	virtual BOOL Write( unsigned char *buffer,int leng );
public:
	void Close();
	BOOL IsFileOpend()
	{
		return ( file_handle != NULL ) ? TRUE: FALSE;
	}
	TCHAR *GetFileName()
	{
		return (TCHAR *)szPathFile;
	}
	int GetLastError()
	{
		return nLastError;
	}
	/** @brief 获取原始文件大小(刚打开时的大小,非解密后的大小)
	*/
	long GetOriginalFileLength()
	{
		return nFileLength;
	}
	long GetFileBodyLength()
	{
		return nFileBodyLength;
	}
	unsigned char *GetFileBuffer()
	{
		return pFileBuffer;
	}
	void SetBareMode(bool bMode= false)
	{
		m_bBareMode = bMode ;
	}
	// 看文件是否存改了.
	// lastModified:  会将文件的最后修改时间和这个比较,以判断是否在这个时间之后被改过了.
	// 如果文件被修改过了, lastModified 参数将被修改为文件最后修改时间.
	BOOL IsFileModified( time_t &lastModified );
	BOOL GetFileLastModifiTime( time_t &lastModified );
protected:
	/** @brief 获取原始文件长度, 调用_filelength
	*/
	long _GetFileLength();

	/** @brief 读取原始 文件内容出来
	*/
	unsigned char * ReadOrignalFileBody();

	void des_encrypt(unsigned char *in,unsigned char *out,unsigned int length);
	void des_decrypt(unsigned char *in,unsigned char *out,unsigned int length);

	unsigned char *pFileBuffer;
	int nLastError;
	long nFileLength;		// 读出来的原始文件长度.
	long nFileBodyLength;	// 解出来的最终文件内容长度.
	
	/** 赤裸模式，将去掉所有的标记，加密，采用原文保存，读取*/
	bool m_bBareMode;
protected:
	FILE *file_handle;
	TCHAR szPathFile[260];		// 当前操作的文件
	unsigned char fileflag[4];//MC?0
	unsigned char version[4]; //1111
	unsigned char copyright[14];//moencycopy.cn0
	unsigned char md5_check[32];
	unsigned char endflag[4];//##MC
	static unsigned char cfb_iv[8];
};
