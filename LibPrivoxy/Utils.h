#pragma once

#ifdef __cplusplus
extern "C" {
#endif
/** @brief 搜索一个未占用的端口
*
* @param nFromPort 起始搜索端口
*/
WORD SearchAnUnsedPort( WORD nFromPort ,UINT nSearchAmount);

char *implode_user_extend_pac_file( const char *in_str );

#ifdef FEATURE_ENCRYPTCFG
unsigned char *read_encrypt_filebody( const char * full_filename );

BOOL write_encrypt_filebody( const char *full_filename, const char * filebody, int length );

char *encrypt_msg( const char *msg, int length, BOOL base64_encode_result );

char *decrypt_msg( const char *msg, int length, BOOL base64_encoded_result );
#endif

char * strdup_printf(const char* fmt,...);

#ifdef __cplusplus
}
#endif