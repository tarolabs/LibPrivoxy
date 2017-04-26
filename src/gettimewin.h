#ifndef _GETTIME_WIN_H_
#define _GETTIME_WIN_H_

#ifdef WIN32
	int	gettimeofday(struct timeval *tp, void *tzp);
#endif

#endif