
#include "params.h"
#include "ecc/ecc.h"
#include "bignum/bignum.h"
#include <iostream>

PARAMS_GOST_SIGN::PARAMS_GOST_SIGN( DWORD _dwParamSet){
	switch( _dwParamSet ){
		case PARAMSET_GOST_SIGN_1:
		default:{ // ParamSet1
			dwParamSet = _dwParamSet;
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

PARAMS_GOST_SIGN::~PARAMS_GOST_SIGN(){
	delete[] (Ipp8u*) pECC;
	delete[] (Ipp8u*) pOrder;
	delete[] (Ipp8u*) pPrime;
	delete[] (Ipp8u*) pP;
}

PARAMS_GOST_CRYPT::PARAMS_GOST_CRYPT(DWORD dwParamSet ){

	switch( dwParamSet ){
		case PARAMSET_GOST_CRYPT_TESTPARAMSET:
			{
				// TestParamSet S-box.
				BYTE m_sbox[8][16] = {
					{ 4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3},
					{14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9},
					{ 5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11},
					{ 7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3},
					{ 6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2},
					{ 4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14},
					{13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12},
					{ 1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12},
				};
				memcpy( sbox, m_sbox, 8*16 );
				dwMode = GOST_CRYPT_CBC;
			}
			break;
		default:
			std::cerr << "Unknown paramset in PARAMS_GOST_CRYPT constructor" ;
	}
}