#ifndef _TIMER_H_
#define _TIMER_H_
/********************* TIMER **************************************/
#ifndef __timer_h_
#define __timer_h_
#include <sys/time.h>
#include <math.h>

static unsigned long t_sum = 0;
static unsigned long measures[NTESTS];
static int _i = 0;
#define TIMER_BEGIN() { struct timeval _begin, _end;	\
  gettimeofday(&_begin, NULL);
#define TIMER_END() gettimeofday(&_end, NULL);		  \
  measures[_i] = 1000000 * (_end.tv_sec - _begin.tv_sec) +	\
    _end.tv_usec - _begin.tv_usec;				\
  t_sum += measures[_i];					\
  _i ++;}
#define TIMER_RESULT(_a) {					\
    double mean = ((double) t_sum) / ((double) NTESTS);			\
    unsigned long _dif_squared = 0;					\
    for(_i = 0; _i < NTESTS; _i ++)						\
      _dif_squared += (measures[_i] - mean) * (measures[_i] - mean);	\
    printf("%s: %.6f seconds  (σ=%.6f seconds)\n", _a, 0.000001 * mean,			\
	   0.000001 * (sqrt(((double) _dif_squared) / (double) (NTESTS-1)))); \
    _i = t_sum = 0;							\
  }
#endif
/********************* TIMER **************************************/
#endif
