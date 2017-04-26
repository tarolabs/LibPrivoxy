#ifndef _NSCACHE_H_
#define _NSCACHE_H_

#ifdef FEATURE_NSCACHE
#if defined(__cplusplus)
extern "C" {
#endif

	BOOL is_nscache_exist( const char *domain );
	const char *get_nscache( const char *domain );
	void push_nscahce( const char *domain, const char *ip);

#if defined(__cplusplus)
}
#endif

#endif


#endif

/*
  Local Variables:
  tab-width: 3
  end:
*/
