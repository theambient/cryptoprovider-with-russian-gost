// tst.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <limits>
#include "bignumber.h"
#include "rand.h"
#include "gost.h"
#include "params.h"

typedef unsigned short int byte;


void gost_check(){

	const Params params (
		"8000000000000000000000000000000000000000000000000000000000000431",
		"8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
		"8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
		"0000000000000000000000000000000000000000000000000000000000000007",
		"5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"
		);
	DIGIT bnPrKey[MAX_SIZE], bnPubKey[2*MAX_SIZE], signature[2*MAX_SIZE];
	strtodigitn( "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28", bnPrKey, MAX_SIZE );
	strtodigitn( "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA", bnPubKey, 2*MAX_SIZE );
	DIGIT h_msg[MAX_SIZE];

	std::cout << "Signature Test" << std::endl;
#ifdef _GOST_CONTROL_TEST
	const unsigned test_count = 1;
#else
	const unsigned test_count = 10;
#endif
	for (unsigned i=0; i<test_count; i++){
#ifdef _GOST_CONTROL_TEST
		strtodigitn( "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", h_msg, MAX_SIZE );
#else

		do {
			bnrand( h_msg, MAX_SIZE);
		} while ( isZero( h_msg, MAX_SIZE ) );
#endif
		std::cout << "Hash:" << std::endl;
		std::cout << h_msg << std::endl;
		//print( bnPubKey, 2*MAX_SIZE);
		sign( h_msg, bnPrKey, signature, params);
		std::cout << "Signature:\n";
		print( signature, 2*MAX_SIZE );
		std::cout << std::endl;

#ifdef _GOST_CONTROL_TEST
		DIGIT benchmark_signature[2*MAX_SIZE];
		strtodigitn( "1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C4041AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", benchmark_signature, 2*MAX_SIZE );
		if ( bncmp( signature, benchmark_signature, 2*MAX_SIZE ) ==0 )
			std::cout << "Signature IS valid" << std::endl;
		else
			std::cout << "Signature IS NOT valid" << std::endl;
#endif
		const bool bCorrect = verify( h_msg, signature, bnPubKey, params);
		if ( bCorrect )
			std::cout << "DS verification result - TRUE" << std::endl;
		else
			std::cout << "DS verification result - false" << std::endl;
	}
}



void ell_check(){
	EllCurve ecc;
	BigNum bnA, bnB, bnPrime, bnQ, bnPX, bnPY, bnQX, bnQY, bnD;
	strtodigitn( "0000000000000000000000000000000000000000000000000000000000000007", bnA, MAX_SIZE );
	strtodigitn( "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E", bnB, MAX_SIZE );
	strtodigitn( "8000000000000000000000000000000000000000000000000000000000000431", bnPrime, MAX_SIZE );
	strtodigitn( "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", bnQ, MAX_SIZE );
	strtodigitn( "0000000000000000000000000000000000000000000000000000000000000002", bnPX, MAX_SIZE );
	strtodigitn( "8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8", bnPY, MAX_SIZE );
	strtodigitn( "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28", bnD, MAX_SIZE );
	ellCurveInit( ecc, bnA, bnB, bnPrime );


	EllPoint epP, epQ, epRes;
	ellInit( epP, bnPX, bnPY, ecc );
	ellInit( epQ, ecc );

	ellMul( epRes, bnQ, epP, ecc );	
	//std::cout << epRes << std::endl;
	if ( ellIsZero(epRes) )
		std::cout << "Test Valid" << std::endl;
	else
		std::cout << "Test is NOT Valid" << std::endl;

	ellMul( epRes, bnD, epP, ecc );
	strtodigitn( "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B", bnQX, MAX_SIZE );
	strtodigitn( "26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA", bnQY, MAX_SIZE );
	ellInit( epQ, bnQX, bnQY, ecc );
	if ( ellIsEqual( epQ, epRes ) )
		std::cout << "Test Valid" << std::endl;
	else
		std::cout << "Test is NOT Valid" << std::endl;
};


void mod_check(){

	BigNum bnA, bnB, bnPrime, bnQ, bnPX, bnPY, bnRand, bnRes, bnDegree;
	strtodigitn( "0000000000000000000000000000000000000000000000000000000000000007", bnA, MAX_SIZE );
	strtodigitn( "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E", bnB, MAX_SIZE );
	strtodigitn( "8000000000000000000000000000000000000000000000000000000000000431", bnPrime, MAX_SIZE );
	strtodigitn( "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", bnQ, MAX_SIZE );
	strtodigitn( "0000000000000000000000000000000000000000000000000000000000000002", bnPX, MAX_SIZE );
	strtodigitn( "8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8", bnPY, MAX_SIZE );

	bnrand( bnRand, MAX_SIZE );
	subDigit( bnDegree, bnPrime, 1, MAX_SIZE );
	modPowerMont( bnRes, bnRand, bnDegree, bnPrime, MAX_SIZE, MAX_SIZE );
	std::cout << bnRes << std::endl;
}

int _tmain(int argc, _TCHAR* argv[])
{
	try {
		gost_check();
	} 
	catch (std::exception &e ){
		std::cout << e.what() << std::endl;
	}
	return 0;
}

