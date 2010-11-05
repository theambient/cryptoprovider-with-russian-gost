
#ifndef PARAMS_HEADER_FILE
#define	PARAMS_HEADER_FILE

#include "ippcp.h"
#include <windows.h>
 
const int iPrivateKeySize = 8;
const int iPublicKeySize = 16;

#define PARAMSET_GOST_SIGN_1 0x01
#define PARAMSET_GOST_CRYPT_TESTPARAMSET 0x01

#define GOST_CRYPT_ECB	0x01
#define	GOST_CRYPT_CBC	0x02
#define GOST_CRYPT_OFB	0x03
#define	GOST_CRYPT_MAC	0x04


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


/*	\brief Contains all nessesarry information about 
 *			GOST 28147-89 params according to the RFC 4357.
 *
 */
struct PARAMS_GOST_CRYPT {
	DWORD	dwParamSet;		//< ParamSet number.
	BYTE	sbox[8][16];	//< S-box or "uzly zameni".
	DWORD	dwMode;			//< cipher mode (CBC, ECB, etc).
	DWORD	dwKeyMeshing;	//< key meshing algorithm.
	explicit PARAMS_GOST_CRYPT( DWORD dwParamSet = PARAMSET_GOST_CRYPT_TESTPARAMSET );
};

struct PARAMS_GOST_HASH {
	//define later
};

#endif //PARAMS_HEADER_FILE