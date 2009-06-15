
#ifndef PARAMS_HEADER_FILE
#define	PARAMS_HEADER_FILE

#include "ippcp.h"
 
const int iPrivateKeySize = 8;
const int iPublicKeySize = 16;

enum ParamSet34102001 { ParamSet1, ParamSet2 };

struct Params34102001 {
	int feBitSize;
	IppsECCPState* pECC;
	IppsBigNumState *pOrder, *pPrime;
	IppsECCPPointState * pP;
	Params34102001(ParamSet34102001 paramSet = ParamSet1);
	~Params34102001();
};

struct Params341194 {
	//define later
};

struct Params2814789{
	//define later
};

#endif //PARAMS_HEADER_FILE