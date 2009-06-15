
#include "params.h"
#include "ecc/ecc.h"
#include "bignum/bignum.h"
#include <iostream>

Params34102001::Params34102001( ParamSet34102001 paramSet){
	switch( paramSet ){
		case ParamSet1:
		default:{ // ParamSet1
			int eccSize;
			const int size = 8;
			ippsBigNumGetSize(8, &feBitSize);
			feBitSize *=8;
			ippsECCPGetSize( feBitSize, &eccSize );
			//IppsECCPState sECC;
			IppsECCPState *pECC = (IppsECCPState*)new Ipp8u[eccSize];
			ippsECCPInit( feBitSize, pECC );
			IppsBigNumState *pPrime = bnNew( "8000000000000000000000000000000000000000000000000000000000000431", size  );
			IppsBigNumState *pA = bnNew( "7", size );
			IppsBigNumState *pB = bnNew(     "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E", size );
			IppsBigNumState *pPX = bnNew( "2", size );
			IppsBigNumState *pPY = bnNew( "8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8", size );
			IppsBigNumState *pOrder = bnNew( "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", size );

			IppStatus ippStsRes = ippsECCPSet( pPrime, pA, pB, pPX, pPY, pOrder, 1, pECC );
			if ( ippStsRes != ippStsNoErr)
				std::cout << ippStsRes;

			IppsECCPPointState *pP = eccPointNew( pPX, pPY, pECC );

			
			this->pECC = pECC;
			this->pOrder = pOrder;
			this->pP = pP;
			this->pPrime = pPrime;

			// release resources
			bnRelease( pA );
			bnRelease( pB );
			bnRelease( pPX );
			bnRelease( pPY );

				}
	}
}

Params34102001::~Params34102001(){
	delete[] (Ipp8u*) pECC;
	delete[] (Ipp8u*) pOrder;
	delete[] (Ipp8u*) pPrime;
	delete[] (Ipp8u*) pP;
}