
#ifndef PARAMS_HEADER_FILE
#define	PARAMS_HEADER_FILE

#include "ippcp.h"
#include <windows.h>
 
const int iPrivateKeySize = 8;
const int iPublicKeySize = 16;

#define PARAMSET_GOST_SIGN_1 0x01

/*	\brief Contains all nessesarry information about 
 *			GOST digital signature params like a,b, p, P etc.
 *
 *	\bug	When assigning one parsameters struct to another one
 *			 the pECC gets invalid.
 */
struct PARAMS_GOST_SIGN {
	DWORD dwParamSet;
	int feBitSize;
	IppsECCPState* pECC;
	IppsBigNumState *pOrder, *pPrime;
	IppsECCPPointState * pP;
	explicit PARAMS_GOST_SIGN(DWORD dwParamSet = PARAMSET_GOST_SIGN_1);
	~PARAMS_GOST_SIGN();
private:
	// hide it until solve bug.
	PARAMS_GOST_SIGN operator=(PARAMS_GOST_SIGN& params);
};

struct Params341194 {
	//define later
};

struct Params2814789{
	//define later
};

#endif //PARAMS_HEADER_FILE