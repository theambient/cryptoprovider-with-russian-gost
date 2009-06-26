
//#define _TEST_VERIFY

#include "gost.h"
#include "types.h"
#include "rand/rand.h"
#include "hash.h"
#include "constants.h"

void digest(const byte* pBuf, const int iBufSize, byte *pDigest, const Params341194 *params){
	hash( pBuf, iBufSize, pDigest );
}

void sign(const byte *pDigestMsg, const IppsBigNumState *pPrivateKey, byte *pSignature, const PARAMS_GOST_SIGN *params, Rand & rand){
	IppsBigNumState *pE = bnNew( iBNSize, pDigestMsg );
	ippsMod_BN( pE, params->pOrder, pE );
#ifdef _TEST_SIGN
	std::cout << pE << std::endl;
#endif
	Ipp32u iResult;
	ippsCmpZero_BN( pE, &iResult );
	if ( iResult == IS_ZERO )
		bnSet( pE, "1" );
	IppsBigNumState *pS = bnNew( iBNSize );
	IppsBigNumState *pR = bnNew( iBNSize );
	do {
#ifdef _GOST_TEST
		IppsBigNumState *pK = bnNew( "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3", iBNSize );
#else
		IppsBigNumState *pK = rand(iBNSize);
		ippsMod_BN( pK, params->pOrder, pK );
#endif
		do {
			IppsECCPPointState *pC = eccPointNew( params->pECC );
			ippsECCPMulPointScalar( params->pP, pK, pC, params->pECC );
			IppsBigNumState *pCX = bnNew( iBNSize );
			ippsECCPGetPoint(pCX, NULL, pC, params->pECC );
			ippsMod_BN( pCX, params->pOrder, pR );
			ippsCmpZero_BN( pR, &iResult );
			// release resources
			eccPointRelease( pC );
		} while ( iResult == IS_ZERO);
		IppsBigNumState *pD = bnNew(iBNSize);
		bnCopy( pD, pPrivateKey, iBNSize );
		//IppsBigNumState *pTemp1 = bnNew( 2*iBNSize );
		//IppsBigNumState *pTemp2 = bnNew( 2*iBNSize );
		IppsBigNumState *pSum = bnNew( 2*iBNSize+1 );
		//ippsMul_BN( pR, pD, pTemp1 );
		//ippsMul_BN( pK, pE, pTemp2 );
		//ippsAdd_BN( pTemp1, pTemp2, pSum );
		ippsMAC_BN_I( pR, pD, pSum );
		ippsMAC_BN_I( pK, pE, pSum );

		ippsMod_BN( pSum, params->pOrder, pS );
		ippsCmpZero_BN( pS, &iResult );

		// release resources
		bnRelease( pK );
		bnRelease( pD );
		//bnRelease( pTemp1 );
		//bnRelease( pTemp2 );
		bnRelease( pSum );
	} while ( iResult == IS_ZERO );

	ippsGetOctString_BN( pSignature, GOSTR34102001SigLen/2, pR );
	ippsGetOctString_BN( pSignature + GOSTR34102001SigLen/2, GOSTR34102001SigLen/2, pS );

	// release resources
	bnRelease( pE );
	bnRelease( pS );
	bnRelease( pR );
}

bool verify(const Ipp8u *pDigestMsg, const IppsECCPPointState *pPublicKey, const Ipp8u *pSignature, const PARAMS_GOST_SIGN *params){
	
	IppsBigNumState *pE = bnNew( iBNSize, pDigestMsg );
	ippsMod_BN( pE, params->pOrder, pE );
	Ipp32u iResult;
	ippsCmpZero_BN( pE, &iResult );
	if ( iResult == IS_ZERO )
		bnSet( pE, "1" );
	IppsBigNumState *pV = bnNew( iBNSize );
	ippsModInv_BN( pE, params->pOrder, pV );
	
	IppsBigNumState *pR = bnNew( iBNSize, pSignature );
	IppsBigNumState *pS = bnNew( iBNSize, pSignature + iBNSize*4);
	
#ifdef _TEST_VERIFY
	std::cout << "pE:\t" << pE << std::endl;
	std::cout << "pV:\t" << pV << std::endl;
	std::cout << "pR:\t" << pR << std::endl;
	std::cout << "pS:\t" << pS << std::endl;
	std::cout << "params->pOrder:\t" << params->pOrder << std::endl;
#endif
	IppsBigNumState *pZ1 = bnNew( iBNSize );
	IppsBigNumState *pZ2 = bnNew( iBNSize );
	IppsBigNumState *pTemp = bnNew( 2*iBNSize );
	ippsMul_BN( pS, pV, pTemp );
	ippsMod_BN( pTemp, params->pOrder, pZ1 );

	ippsMul_BN( pR, pV, pTemp );
	ippsMod_BN( pTemp, params->pOrder, pZ2 );
	ippsSub_BN( params->pOrder, pZ2, pZ2 );

#ifdef _TEST_VERIFY
	std::cout << "pZ1:\t" << pZ1 << std::endl;
	std::cout << "pZ2:\t" << pZ2 << std::endl;
#endif

	IppsECCPPointState *pC = eccPointNew( params->pECC );
	IppsECCPPointState *pEccTemp1 = eccPointNew( params->pECC );
	IppsECCPPointState *pEccTemp2 = eccPointNew( params->pECC );
	ippsECCPMulPointScalar( params->pP, pZ1, pEccTemp1, params->pECC );
	ippsECCPMulPointScalar( pPublicKey, pZ2, pEccTemp2, params->pECC );
	ippsECCPAddPoint( pEccTemp1, pEccTemp2, pC, params->pECC );


	IppsBigNumState *pCalculatedR = bnNew(iBNSize);
	IppsBigNumState *pTrash = bnNew(iBNSize);
	ippsECCPGetPoint( pCalculatedR, pTrash, pC, params->pECC );
	ippsMod_BN( pCalculatedR, params->pOrder, pCalculatedR );

#ifdef _TEST_VERIFY
	std::cout << "pCalculatedR:\t" << pCalculatedR << std::endl;
#endif

	ippsCmp_BN( pR, pCalculatedR, &iResult );
	return iResult == IS_ZERO;
	
}


bool genKeyPair(IppsECCPPointState **ppPublicKey, IppsBigNumState **ppPrivateKey, const PARAMS_GOST_SIGN *pParams, Rand *pRand){
	
	*ppPrivateKey = bnNew( iBNSize);
	*ppPublicKey = eccPointNew( pParams->pECC );
	IppStatus res = ippsECCPGenKeyPair( *ppPrivateKey, *ppPublicKey, pParams->pECC, ippsPRNGen, pRand->getPRNG() );
	return res == ippStsNoErr;
}