
#ifndef PARAMS_HEADER_FILE
#define PARAMS_HEADER_FILE

#include "bignumber.h"
#include "elliptic.h"

struct Params {
	DIGIT p[MAX_SIZE], q[MAX_SIZE], m[MAX_SIZE];
	EllPoint P;
	EllCurve ecc;
	Params(const char* sp, const char* sq, const char* sm, const char* sa, const char* sb, const char* sxp, const char* syp){
		BigNum bnA, bnB, bnPX, bnPY;
		strtodigitn( sp, p, MAX_SIZE );
		strtodigitn( sq, q, MAX_SIZE );
		strtodigitn( sm, m, MAX_SIZE );
		strtodigitn( sa, bnA, MAX_SIZE );
		strtodigitn( sb, bnB, MAX_SIZE );
		strtodigitn( sxp, bnPX, MAX_SIZE );
		strtodigitn( syp, bnPY, MAX_SIZE );
		ellCurveInit( ecc, bnA, bnB, p );
		ellInit( P, bnPX, bnPY, ecc );
	}
	Params(){;}
};



//const Params params;
#endif //PARAMS_HEADER_FILE