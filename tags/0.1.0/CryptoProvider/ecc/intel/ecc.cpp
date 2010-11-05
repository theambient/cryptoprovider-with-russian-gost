
#include "bignum/bignum.h"
#include "types.h"
#include "ecc.h"
#include <iostream>
#include "constants.h"
#include "csp/csp-debug.h"

inline int getFEBitSize(){
	int res;
	ippsBigNumGetSize( iBNSize, &res );
	return res*8;
}

const int feBitSize = getFEBitSize();

IppsECCPPointState* eccPointNew( const IppsBigNumState *pPX, const IppsBigNumState* pPY, IppsECCPState *pECC){

	int eccPointSize;
	IppStatus res = ippsECCPPointGetSize(feBitSize, &eccPointSize);
	if ( res != ippStsNoErr){
		std::cerr << res;
		return NULL;
	}

	IppsECCPPointState *pPoint = (IppsECCPPointState* ) (new Ipp8u[eccPointSize]);

	res = ippsECCPPointInit( feBitSize, pPoint );
	if ( res != ippStsNoErr){
		std::cerr << res;
		return NULL;
	}

	if ( pPX != NULL && pPY != NULL){
		res = ippsECCPSetPoint( pPX, pPY, pPoint, pECC );
		if ( res != ippStsNoErr){
			std::cerr << res;
			return NULL;
		}
	}
	else {
		std::cerr << "eccPointNew: NULL cordinates supplied" << std::endl;
		return NULL;
	}
	return pPoint;
}

IppsECCPPointState* eccPointNew(IppsECCPState *pECC){

	int eccPointSize;
	IppStatus res = ippsECCPPointGetSize(feBitSize, &eccPointSize);
	if ( res != ippStsNoErr)
		std::cout << res;

	IppsECCPPointState *pPoint = (IppsECCPPointState* ) (new Ipp8u[eccPointSize]);

	res = ippsECCPPointInit( feBitSize, pPoint );
	if ( res != ippStsNoErr)
		std::cout << res;

	ippsECCPSetPointAtInfinity( pPoint, pECC );

	return pPoint;
}


void eccPointRelease( IppsECCPPointState* pPoint){
	if (pPoint != NULL)
		delete[] (Ipp8u*) pPoint;
	pPoint = NULL;
}


void eccPointToOctet( const IppsECCPPointState *pPoint, IppsECCPState *pECC, Ipp8u *pRawKey ){
	IppsBigNumState *pX = bnNew( iBNSize );
	IppsBigNumState *pY = bnNew( iBNSize );
	ippsECCPGetPoint( pX, pY, pPoint, NULL );
	ippsGetOctString_BN( pRawKey, iBNSize*4, pX );
	ippsGetOctString_BN( pRawKey + iBNSize*4, iBNSize*4, pY );
}

void eccPointToString( const IppsECCPPointState *pPoint, IppsECCPState *pECC, char *sPoint ){
	IppsBigNumState *pX = bnNew( iBNSize );
	IppsBigNumState *pY = bnNew( iBNSize );
	ippsECCPGetPoint( pX, pY, pPoint, pECC );
	bnConvertToString( pX, sPoint );
	bnConvertToString(  pY, sPoint + iBNSize*8 );
}



IppsECCPPointState* eccPointNew( const Ipp8u *baseData, const int byteDataLen, IppsECCPState* pECC){
	if ( byteDataLen%2 == 1 ){
		DEBUG( 0, "eccPointNew: byteDataLength is odd" );
		return NULL;
	}
	if ( byteDataLen/2 > iBNSize*4 ){
		DEBUG( 0, "eccPointNew: byteDataLength/2 is greater then iBNSize*4" );
		return NULL;
	}

	IppsBigNumState *pX = bnNew( iBNSize, baseData );
	IppsBigNumState *pY = bnNew( iBNSize, baseData+byteDataLen/2 );
	return eccPointNew( pX, pY, pECC );
}