
#include "gost.h"
#include "elliptic.h"
#include "params.h"
#include "rand.h"
#include <stdexcept>
#include <iostream>
//#include "hash.h"

void sign( const DIGIT hash[], const DIGIT prKey[], DIGIT signature[], const Params &params){


	BigNum e;
	div( hash, params.q, NULL, e, MAX_SIZE, MAX_SIZE );
	BigNum d;
	div( prKey, params.q, NULL, d, MAX_SIZE, MAX_SIZE );
	if ( isZero(e, MAX_SIZE) )
		assignDigit( e, 1, MAX_SIZE );
	BigNum s, r, k;
	do {
		do {

#ifdef _GOST_CONTROL_TEST
			strtodigitn( "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3", k, MAX_SIZE );
#else
			bnrand( k, MAX_SIZE );
#endif

			div( k, params.q, NULL, k, MAX_SIZE, MAX_SIZE );
			//std::cout << "k:\n"<< k << std::endl;
			EllPoint C;
			ellMul( C, k, params.P, params.ecc );
			//std::cout << "C:\n" <<C << std::endl;
			div( C.bnX, params.q, NULL, r, MAX_SIZE, MAX_SIZE ); // r = x_c ( mod q )
			//std::cout << "r:\n"<< r << std::endl;
		} while ( isZero(r, MAX_SIZE ) );
		BigNum bnTemp1, bnTemp2;
		modmul( bnTemp1, r, d, params.q, MAX_SIZE );
		modmul( bnTemp2, k, e, params.q, MAX_SIZE );
		modadd( s, bnTemp1, bnTemp2, params.q, MAX_SIZE );
		//std::cout << "s:\n"<< s << std::endl;
	} while ( isZero(s, MAX_SIZE ) );

	assign( signature, r, MAX_SIZE );
	assign( signature + MAX_SIZE, s, MAX_SIZE );
}

bool verify( const DIGIT hash[], const DIGIT signature[], const DIGIT pubKey[], const Params &params ){

	//std::cout << "Verify:"<< std::endl;
	if ( bncmp( signature, params.q, MAX_SIZE )>=0 )
		return false;
	if ( bncmp( signature + MAX_SIZE, params.q, MAX_SIZE )>=0 )
		return false;
	const DIGIT *r = signature;
	const DIGIT *s = signature + MAX_SIZE;
	BigNum e;
	//std::cout << "r:\n"<< r << std::endl;
	//std::cout << "s:\n"<< s << std::endl;
	div( hash, params.q, NULL, e, MAX_SIZE, MAX_SIZE );
	if ( isZero(e, MAX_SIZE) )
		assignDigit( e, 1, MAX_SIZE );
	BigNum v, z1, z2, bnTemp;
	modInvert( v, e, params.q, MAX_SIZE );
	modmul( z1, s, v, params.q, MAX_SIZE );
	modmul( bnTemp, r, v, params.q, MAX_SIZE );
	modNegative( z2, bnTemp, params.q, MAX_SIZE );
	EllPoint epTemp1, epTemp2, C, Q;
	ellMul( epTemp1, z1, params.P, params.ecc );
	ellInit( Q, &pubKey[MAX_SIZE], pubKey, params.ecc );
	ellMul( epTemp2, z2, Q, params.ecc );
	ellAdd( C, epTemp1, epTemp2, params.ecc );
	
	BigNum bnR;
	div( C.bnX, params.q, NULL, bnR, MAX_SIZE, MAX_SIZE );
	//std::cout << "C:\n" <<C << std::endl;
	return bncmp( bnR, r, MAX_SIZE ) == 0;
}
