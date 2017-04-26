const char nscache_rcs[] = "$Id: nscache.cpp,v 1.0 2016/11/27 17:48:00 fabiankeil Exp $";

#ifdef FEATURE_NSCACHE
#ifdef _WIN32
#  include <windows.h>
#endif
#include "jcc.h"
#include "nscache.h"
#include <map>
#include <string>

using namespace std;

privoxy_mutex_t nscache_mutex;
typedef map<string,string> MAP_PROXY_NS_CACHE;
typedef map<string,string>::iterator ITER_MAP_PROXY_NS_CACHE;

MAP_PROXY_NS_CACHE _nscache;

#if defined(__cplusplus)
extern "C" {
#endif

void push_nscahce( const char *domain, const char *ip)
{
	if( !domain || !ip ) return;

	if( is_nscache_exist( domain ) ) return;

	_nscache.insert( make_pair( domain, ip ) );

	return;
}

BOOL is_nscache_exist( const char *domain )
{
	if( !domain ) return FALSE;

	string s( domain );
	ITER_MAP_PROXY_NS_CACHE iter = _nscache.find( s );
	if( iter != _nscache.end() )
		return TRUE;

	return FALSE;
}

const char *get_nscache( const char *domain )
{
	if( !domain ) return NULL;

	string s( domain );
	ITER_MAP_PROXY_NS_CACHE iter = _nscache.find( s );
	if( iter != _nscache.end() )
	{
		return strdup( iter->second.c_str() );
	}

	return NULL;
}

#if defined(__cplusplus)
}
#endif

#endif