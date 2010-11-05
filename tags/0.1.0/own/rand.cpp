
#include "rand.h"


void bnrand(DIGIT bn[], const unsigned num){	
	static DIGIT bn_a[MAX_SIZE], bn_seed[MAX_SIZE];
	static bool bFirstTime = true;
	if ( bFirstTime ){
		strtodigitn( "5851F42D4C957F2D", bn_a, num );
		strtodigitn( "5851F42D4C957F2D", bn_seed, num );
		bFirstTime = false;
	}
	DIGIT bnTemp[2*MAX_SIZE];
	mul( bnTemp, bn_a, bn_seed, MAX_SIZE );
	assign( bn, bnTemp, num );
	assign( bn_seed, bnTemp, num );
}
