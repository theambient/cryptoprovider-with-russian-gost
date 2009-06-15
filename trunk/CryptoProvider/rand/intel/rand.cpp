
#include "rand.h"
#include "types.h"
#include "bignum/intel/bignum.h"
#include "bignum/bignum.h"
#include <windows.h>

Rand::Rand(const int iSeedSizeParam, unsigned char *pSeedValue) {
	int iPrngCtxSize;
	ippsPRNGGetSize(&iPrngCtxSize);
	pPRNG = (IppsPRNGState*)(new Ipp8u [iPrngCtxSize] );
	const int iSeedSize = (iSeedSizeParam != 0 )? iSeedSizeParam: sizeof(SYSTEMTIME);
	SYSTEMTIME st;
	GetSystemTime( &st );
	if ( pSeedValue == NULL )
		pSeedValue = (unsigned char*) &st;
	
	IppsBigNumState *pbnSeed = bnNew( iSeedSize, pSeedValue );
	ippsPRNGInit(iSeedSize*8, pPRNG);
	ippsPRNGSetSeed( pbnSeed, pPRNG );
	IppsBigNumState *pModulus = bnNew("8000000000000000000000000000000000000000000000000000000000000431", iSeedSize );
	ippsPRNGSetModulus( pModulus, pPRNG );
	IppsBigNumState *pAugment = bnNew("5555555555555555555555555555555555555555555555555", iSeedSize );
	ippsPRNGSetAugment( pAugment, pPRNG );
	delete[] (Ipp8u*) pModulus;
	delete[] (Ipp8u*) pAugment;	
}

Rand::~Rand(){
	delete[] (Ipp8u*) pPRNG;
}

	// генерирует случайное число длины iSize байт
IppsBigNumState* Rand::operator()(const int iSize){
	IppsBigNumState *pRand = bnNew( (iSize+3)/4 );
	ippsPRNGen_BN( pRand, iSize*8, pPRNG );
	return pRand;
}

/*
void randInit(IppsPRNGState* pPRNG, const int iSeedSizeParam, IppsBigNumState *pSeedValue ){
	int iPrngCtxSize;
	ippsPRNGGetSize(&iPrngCtxSize);
	pPRNG = (IppsPRNGState*)(new Ipp8u [iPrngCtxSize] );
	const int iSeedSize = (iSeedSizeParam != 0 )? iSeedSizeParam: 8;
	if ( pSeedValue == NULL ) {
		Ipp32u *pSeedData = new Ipp32u[iSeedSize];
		pSeedValue = bnNew( iSeedSize, pSeedData );
	}
	ippsPRNGInit(iSeedSize, pPRNG);
	ippsPRNGSetSeed( pSeedValue, pPRNG );

	IppsBigNumState *pModulus = bnNew("8000000000000000000000000000000000000000000000000000000000000431", iSeedSize );
	ippsPRNGSetModulus( pModulus, pPRNG );
	IppsBigNumState *pAugment = bnNew("5555555555555555555555555555555555555555555555555", iSeedSize );
	ippsPRNGSetAugment( pAugment, pPRNG );
	delete[] (Ipp8u*) pModulus;
	delete[] (Ipp8u*) pAugment;
}

void randSetSeed(IppsPRNGState* pPRNG, IppsBigNumState *pSeedValue ){
	ippsPRNGSetSeed( pSeedValue, pPRNG );
}

IppsBigNumState* bnRand(int iSize, IppsPRNGState* pPRNG){
	IppsBigNumState *pRand = bnNew( iSize );
	ippsPRNGen_BN( pRand, iSize*32, pPRNG );
	return pRand;
}

*/