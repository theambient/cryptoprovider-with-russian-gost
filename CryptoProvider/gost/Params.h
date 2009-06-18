
#ifndef PARAMS_HEADER_FILE
#define	PARAMS_HEADER_FILE

#include "ippcp.h"
#include <windows.h>
 
const int iPrivateKeySize = 8;
const int iPublicKeySize = 16;

#define PARAMSET_GOST_SIGN_1 0x01

struct PARAMS_GOST_SIGN {
	DWORD dwParamSet;
	int feBitSize;
	IppsECCPState* pECC;
	IppsBigNumState *pOrder, *pPrime;
	IppsECCPPointState * pP;
	PARAMS_GOST_SIGN(DWORD dwParamSet = PARAMSET_GOST_SIGN_1);
	~PARAMS_GOST_SIGN();
};

struct Params341194 {
	//define later
};

struct Params2814789{
	//define later
};

#endif //PARAMS_HEADER_FILE