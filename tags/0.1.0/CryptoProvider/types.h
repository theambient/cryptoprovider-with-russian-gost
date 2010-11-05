
#ifndef _TYPES_HEADER_FILE
#define _TYPES_HEADER_FILE

#define _GOST_TEST

#ifdef _IMPLEMENT_INTEL


#include "ippcp.h"

typedef Ipp32u Digit;
typedef Ipp8u BYTE;


#else

//#include "own/modular.h"

#endif //_IMPLEMENT_INTEL

#endif //_TYPES_HEADER_FILE

