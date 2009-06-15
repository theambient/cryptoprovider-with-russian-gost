
#include "elliptic.h"
#include "bignumber.h"
#include <iostream>

// конструкторы
void ellCurveInit( EllCurve &ecc, const BigNum &bnA,  const BigNum &bnB, const BigNum &bnPrime ){
	assign( ecc.bnA, bnA, MAX_SIZE );
	assign( ecc.bnB, bnB, MAX_SIZE );
	assign( ecc.bnPrime, bnPrime, MAX_SIZE );
}

void ellInit( EllPoint &ep, const DIGIT bnX[], const DIGIT bnY[], const EllCurve &ecc ){

	/*
	#ifdef _VERBOSE_CHECKING
	if ( bncmp( bnX, ecc.bnPrime, MAX_SIZE ) > 0 )
	throw std::invalid_argument( "ellInit: Params do not match" );
	if ( bncmp( bnY, ecc.bnPrime, MAX_SIZE ) > 0 )
	throw std::invalid_argument( "ellInit: Params do not match" );
	#endif
	*/
	if ( bncmp( bnX, ecc.bnPrime, MAX_SIZE ) > 0 )
		div( bnX, ecc.bnPrime, NULL, ep.bnX, MAX_SIZE, MAX_SIZE );
	else
		assign( ep.bnX, bnX, MAX_SIZE );

	if ( bncmp( bnY, ecc.bnPrime, MAX_SIZE ) > 0 )
		div( bnY, ecc.bnPrime, NULL, ep.bnY, MAX_SIZE, MAX_SIZE );
	else
		assign( ep.bnY, bnY, MAX_SIZE );
	ep.isZero = false;
}

void ellInit( EllPointProject &ep, const EllCurve &ecc ){
	zero( ep.bnXP, MAX_SIZE );
	zero( ep.bnZP, MAX_SIZE );
	assignDigit( ep.bnYP, 1, MAX_SIZE );
}

void ellInit( EllPoint &ep, const EllCurve &ecc ){
	ep.isZero = true;
}

void ellAssign( EllPointProject &ellDst, const EllPointProject &ellSrc ){
	assign( ellDst.bnXP, ellSrc.bnXP, MAX_SIZE );
	assign( ellDst.bnYP, ellSrc.bnYP, MAX_SIZE );
	assign( ellDst.bnZP, ellSrc.bnZP, MAX_SIZE );
}

void ellAssign( EllPoint &ellDst, const EllPoint &ellSrc ){
	if ( ellSrc.isZero ){
		ellDst.isZero = true;
	} else {
		assign( ellDst.bnX, ellSrc.bnX, MAX_SIZE );
		assign( ellDst.bnY, ellSrc.bnY, MAX_SIZE );
		ellDst.isZero = false;
	}
}

void ellDuplicate( EllPoint &epRes, const EllPoint &ep, const EllCurve &ecc ){

#ifdef _VERBOSE_CHECKING
	if ( !ellCheckValidity( ep, ecc ) )
		throw std::invalid_argument( "ellDuplicate: parameter ep1 is not valid point of elliptic curve ecc" );
#endif
	epRes.isZero = false;
	if ( ep.isZero ){
		epRes.isZero = true;
		return;
	}
#ifdef _VERBOSE_CHECKING
	if ( isZero(ep.bnY, MAX_SIZE) )
		throw std::invalid_argument( "ellDuplicate: addition is not defined for such point coordinates - P_y == 0" );
#endif

	// if x1==x2 && y1 == y2 && y2 != 0
	BigNum bnLambda, bnTemp1, bnTemp2;
	// calculating Lambda
	modSquare( bnTemp1, ep.bnX, ecc.bnPrime, MAX_SIZE );
	modmulShort( bnTemp2, bnTemp1, 3, ecc.bnPrime, MAX_SIZE );
	modadd( bnTemp1, bnTemp2, ecc.bnA, ecc.bnPrime, MAX_SIZE );
	modmulShort( bnTemp2, ep.bnY, 2, ecc.bnPrime, MAX_SIZE );
	moddiv( bnLambda, bnTemp1, bnTemp2, ecc.bnPrime, MAX_SIZE );
	// calculating x3
	modSquare( bnTemp1, bnLambda, ecc.bnPrime, MAX_SIZE );
	// \todo test both addition and short multiplication
	modadd( bnTemp2, ep.bnX, ep.bnX, ecc.bnPrime, MAX_SIZE );
	modsub( epRes.bnX, bnTemp1, bnTemp2, ecc.bnPrime, MAX_SIZE );
	// calculating y3
	modsub( bnTemp1, ep.bnX, epRes.bnX, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp2, bnLambda, bnTemp1, ecc.bnPrime, MAX_SIZE );
	modsub( epRes.bnY, bnTemp2, ep.bnY, ecc.bnPrime, MAX_SIZE );
}


void ellAdd( EllPoint &epRes, const EllPoint &ep1, const EllPoint &ep2, const EllCurve &ecc ){

#ifdef _VERBOSE_CHECKING
	if ( !ellCheckValidity( ep1, ecc ) )
		throw std::invalid_argument( "ellAdd: parameter ep1 is not valid point of elliptic curve ecc" );
	if ( !ellCheckValidity( ep2, ecc ) )
		throw std::invalid_argument( "ellAdd: parameter ep2 is not valid point of elliptic curve ecc" );
#endif

	epRes.isZero = false;
	if ( ep1.isZero ){
#ifdef _VERBOSE_CHECKING
		if ( ep2.isZero )
			throw std::invalid_argument ( "ellAdd: parameter ep1 and ep2 are equal. Use ellDuplicate instead" );
#endif
		ellAssign( epRes, ep2);
		return;
	}

	if ( ep2.isZero ){
#ifdef _VERBOSE_CHECKING
		if ( ep1.isZero )
			throw std::invalid_argument( "ellAdd: parameter ep1 and ep2 are equal. Use ellDuplicate instead" );
#endif
		ellAssign( epRes, ep1);
		return;
	}
	// now none is zero
#ifdef _VERBOSE_CHECKING
	if ( bncmp( ep1.bnX, ep2.bnX, MAX_SIZE ) == 0 && bncmp(ep1.bnY, ep2.bnY, MAX_SIZE) == 0 )
		throw std::invalid_argument( "ellAdd: parameter ep1 and ep2 are equal. Use ellDuplicate instead" );
#endif
	if ( bncmp(ep1.bnX, ep2.bnX, MAX_SIZE) != 0 ) {
		// x1 != x2
		BigNum bnLambda, bnTemp1, bnTemp2;
		// calculating Lambda
		modsub( bnTemp1, ep2.bnY, ep1.bnY, ecc.bnPrime, MAX_SIZE );
		modsub( bnTemp2, ep2.bnX, ep1.bnX, ecc.bnPrime, MAX_SIZE );
		moddiv( bnLambda, bnTemp1, bnTemp2, ecc.bnPrime, MAX_SIZE );
		// calculating x3
		modSquare( bnTemp1, bnLambda, ecc.bnPrime, MAX_SIZE );
		modsub( bnTemp2, bnTemp1, ep1.bnX, ecc.bnPrime, MAX_SIZE );
		modsub( epRes.bnX, bnTemp2, ep2.bnX, ecc.bnPrime, MAX_SIZE );
		// calculating y3
		modsub( bnTemp1, ep1.bnX, epRes.bnX, ecc.bnPrime, MAX_SIZE );
		modmul( bnTemp2, bnLambda, bnTemp1, ecc.bnPrime, MAX_SIZE );
		modsub( epRes.bnY, bnTemp2, ep1.bnY, ecc.bnPrime, MAX_SIZE );
	} else if ( bncmp(ep1.bnY, ep2.bnY, MAX_SIZE) != 0 ){
#ifdef _VERBOSE_CHECKING
		BigNum bnTemp;
		modadd( bnTemp, ep1.bnY, ep2.bnY, ecc.bnPrime, MAX_SIZE );
		if ( !isZero( bnTemp, MAX_SIZE ) ){
			// should be an error.
			throw std::invalid_argument( "ellAdd: addition is not defined for such point coordinates." );
		}
#endif
		epRes.isZero = true;
	}
}

void ellDuplicate( EllPointProject &epRes, const EllPointProject &ep1, const EllCurve &ecc ){
	if ( isZero( ep1.bnZP, MAX_SIZE) ){
		ellAssign( epRes, ep1 );
		return;
	}
	BigNum bnTemp1, bnTemp2, bnTemp3;
	BigNum bnTerm1, bnTerm1Sqr, bnTerm1Cube;
	BigNum bnY1Z1, bnY1SqrZ1, bnY1Z1Cube;

	// Precalculations
	modmul( bnY1Z1, ep1.bnYP, ep1.bnZP, ecc.bnPrime, MAX_SIZE );
	modmul( bnY1SqrZ1, ep1.bnYP, bnY1Z1, ecc.bnPrime, MAX_SIZE );

	modSquare( bnTemp1, bnY1Z1, ecc.bnPrime, MAX_SIZE );
	modmul( bnY1Z1Cube, bnTemp1, bnY1Z1, ecc.bnPrime, MAX_SIZE );

	modSquare( bnTemp1, ep1.bnZP, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp2, bnTemp1, ecc.bnA, ecc.bnPrime, MAX_SIZE );
	modSquare( bnTemp1, ep1.bnXP, ecc.bnPrime, MAX_SIZE );
	modmulShort( bnTemp3, bnTemp1, 3, ecc.bnPrime, MAX_SIZE );
	modadd( bnTerm1, bnTemp2, bnTemp3, ecc.bnPrime, MAX_SIZE );
	modSquare( bnTerm1Sqr, bnTerm1, ecc.bnPrime, MAX_SIZE );
	modmul( bnTerm1Cube, bnTerm1Sqr, bnTerm1, ecc.bnPrime, MAX_SIZE );

	//calculating X
	modmul( bnTemp1, bnY1SqrZ1, ep1.bnXP, ecc.bnPrime, MAX_SIZE );
	modmulShort( bnTemp2, bnTemp1, 8, ecc.bnPrime, MAX_SIZE );
	modsub( bnTemp3, bnTerm1Sqr, bnTemp2, ecc.bnPrime, MAX_SIZE );
	modmulShort( bnTemp1, bnY1Z1, 2, ecc.bnPrime, MAX_SIZE );
	modmul( epRes.bnXP, bnTemp1, bnTemp3, ecc.bnPrime, MAX_SIZE );

	//calculating Y
	modmul( bnTemp1, bnTerm1, ep1.bnXP, ecc.bnPrime, MAX_SIZE );
	modmulShort( bnTemp2, bnTemp1, 3, ecc.bnPrime, MAX_SIZE );

	modadd( bnTemp1, bnY1SqrZ1, bnY1SqrZ1, ecc.bnPrime, MAX_SIZE );
	modsub( bnTemp3, bnTemp2, bnTemp1, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp1, bnTemp3, bnY1SqrZ1, ecc.bnPrime, MAX_SIZE );
	modmulShort( bnTemp2, bnTemp1, 4, ecc.bnPrime, MAX_SIZE );
	modsub( epRes.bnYP, bnTemp2, bnTerm1Cube, ecc.bnPrime, MAX_SIZE );

	//calculating Z
	modmulShort( epRes.bnZP, bnY1Z1Cube, 8, ecc.bnPrime, MAX_SIZE );
}

void ellAdd( EllPointProject &epRes, const EllPointProject &ep1, const EllPointProject &ep2, const EllCurve &ecc ){
	if ( isZero( ep1.bnZP, MAX_SIZE ) ){
		ellAssign( epRes, ep2 );
		return;
	}
	
	if ( isZero( ep2.bnZP, MAX_SIZE ) ){
		ellAssign( epRes, ep1 );
		return;
	}

	BigNum bnTemp1, bnTemp2, bnTemp3, bnTemp4;
	BigNum bnTerm1, bnTerm1Sqr, bnTerm2, bnTerm2Sqr, bnTerm3, bnTerm4;
	BigNum bnX2Z1, bnX1Z2, bnY2Z1, bnY1Z2, bnZ1Z2;

	// Precalculations
	modmul( bnY1Z2, ep1.bnYP, ep2.bnZP, ecc.bnPrime, MAX_SIZE );
	modmul( bnY2Z1, ep2.bnYP, ep1.bnZP, ecc.bnPrime, MAX_SIZE );
	modmul( bnZ1Z2, ep1.bnZP, ep2.bnZP, ecc.bnPrime, MAX_SIZE );
	modmul( bnX2Z1, ep2.bnXP, ep1.bnZP, ecc.bnPrime, MAX_SIZE );
	modmul( bnX1Z2, ep1.bnXP, ep2.bnZP, ecc.bnPrime, MAX_SIZE );

	modsub( bnTerm1, bnY2Z1, bnY1Z2, ecc.bnPrime, MAX_SIZE );
	modSquare( bnTerm1Sqr, bnTerm1, ecc.bnPrime, MAX_SIZE );

	modsub( bnTerm2, bnX2Z1, bnX1Z2, ecc.bnPrime, MAX_SIZE );
	modSquare( bnTerm2Sqr, bnTerm2, ecc.bnPrime, MAX_SIZE );

	modadd( bnTerm3, bnX2Z1, bnX1Z2, ecc.bnPrime, MAX_SIZE );

	modmul( bnTerm4, bnZ1Z2, bnTerm1Sqr, ecc.bnPrime, MAX_SIZE );

	//calculating X
	modmul( bnTemp1, bnTerm3, bnTerm2Sqr, ecc.bnPrime, MAX_SIZE );
	modsub( bnTemp3, bnTerm4, bnTemp1, ecc.bnPrime, MAX_SIZE );
	modmul( epRes.bnXP, bnTerm2, bnTemp3, ecc.bnPrime, MAX_SIZE ); 

	// calculating Y
	modadd( bnTemp2, bnTerm3, bnX1Z2, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp3, bnTemp2, bnY2Z1, ecc.bnPrime, MAX_SIZE );

	modadd( bnTemp2, bnTerm3, bnX2Z1, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp4, bnTemp2, bnY1Z2, ecc.bnPrime, MAX_SIZE );

	modsub( bnTemp1, bnTemp3, bnTemp4, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp2, bnTemp1, bnTerm2Sqr, ecc.bnPrime, MAX_SIZE );

	modmul( bnTemp3, bnTerm4, bnTerm1, ecc.bnPrime, MAX_SIZE );
	modsub( epRes.bnYP, bnTemp2, bnTemp3, ecc.bnPrime, MAX_SIZE );

	//calculating Z
	modmul( bnTemp1, bnTerm2Sqr, bnTerm2, ecc.bnPrime, MAX_SIZE );
	modmul( epRes.bnZP, bnZ1Z2, bnTemp1, ecc.bnPrime, MAX_SIZE );
}

void ellConvertToProjective(EllPointProject & epProject, const EllPoint &ep, const EllCurve &ecc){
	if ( ep.isZero ){
		ellInit( epProject, ecc );
	} else {
		assign( epProject.bnXP, ep.bnX, MAX_SIZE );
		assign( epProject.bnYP, ep.bnY, MAX_SIZE );
		assignDigit( epProject.bnZP, 1, MAX_SIZE );
	}
}

void ellConvertToAffine(EllPoint &ep, const EllPointProject & epProject, const EllCurve &ecc){
	
	ep.isZero = false;
	if ( isZero( epProject.bnZP, MAX_SIZE ) ){
#ifdef _VERBOSE_CHECKING
		BigNum bnTemp;
		assignDigit( bnTemp, 1, MAX_SIZE );
		if ( !isZero( epProject.bnXP, MAX_SIZE ) )
			throw std::domain_error( "ellConvertToAffine: the point seems to be invalid, cause bnXP is not zero" );
		//if ( bncmp( bnTemp, epProject.bnYP, MAX_SIZE ) != 0 )
		//	throw std::domain_error( "ellConvertToAffine: the point seems to be invalid, cause bnYP is not unit" );
#endif
		ep.isZero = true;
	} else {
		moddiv( ep.bnX, epProject.bnXP, epProject.bnZP, ecc.bnPrime, MAX_SIZE );
		moddiv( ep.bnY, epProject.bnYP, epProject.bnZP, ecc.bnPrime, MAX_SIZE );
	}
}


void ellMul( EllPoint &epRes, const BigNum &bnK, const EllPoint &epP, const EllCurve &ecc ){

#ifdef _TEST_ELLMUL
	BigNum bnCheck;
	zero( bnCheck, MAX_SIZE );
#endif
#ifdef _PROJECTIVE_COORDS
	EllPointProject epProd, epMult;
	//EllPointProject epPProject;
	//ellConvertToProjective( epPProject, epP, ecc );
	ellConvertToProjective( epMult, epP, ecc );
#else
	EllPoint epProd, epMult;
	ellAssign( epMult, epP );
#endif
	ellInit( epProd, ecc );

	for ( unsigned i = MAX_SIZE - 1; i+1>0; i--)
		for (unsigned j=baseDigits-1; j+1>0; j--){
#ifdef _PROJECTIVE_COORDS
			EllPointProject epTemp;
#else
			EllPoint epTemp;
#endif
			//ellInit( epTemp, ecc );
			ellDuplicate( epTemp, epProd, ecc );
			ellAssign( epProd, epTemp );

#ifdef _DEBUG_ELLMUL
			static int count = 0;
			count ++;
			std::cout << count << std::endl;
#endif
#ifdef _TEST_ELLMULL
			BigNum bnTemp;
			DIGIT res = add( bnTemp, bnCheck, bnCheck, MAX_SIZE );
			if ( res > 0 )
				throw std::domain_error( "EllMul: overflow while checking" );
			assign( bnCheck, bnTemp, MAX_SIZE );
#endif
			if ( ( bnK[i] >> j) &1){
#ifdef _TEST_ELLMUL
				addDigit( bnTemp, bnCheck, 1, MAX_SIZE );
				assign( bnCheck, bnTemp, MAX_SIZE );
#endif
				ellAdd( epTemp, epProd, epMult, ecc );
				ellAssign( epProd, epTemp );
			}
		}
#ifdef _TEST_ELLMUL
		std::cout << "bnCheck:\t" << bnCheck << std::endl;
#endif
#ifdef _PROJECTIVE_COORDS
		ellConvertToAffine( epRes, epProd, ecc );
#else
		ellAssign( epRes, epProd );
#endif
}

/*
void ellMul( EllPoint &epRes, const BigNum &bnK, const EllPoint &epP, const EllCurve &ecc ){

#ifdef _TEST_ELLMUL
BigNum bnCheck;
zero( bnCheck, MAX_SIZE );
#endif
ellInit( epRes, ecc );
for ( unsigned i = MAX_SIZE - 1; i+1>0; i--)
for (unsigned j=baseDigits-1; j+1>0; j--){
EllPoint epTemp;
ellInit( epTemp, ecc );
ellAdd( epTemp, epRes, epRes, ecc );
ellAssign( epRes, epTemp );
#ifdef _DEBUG_ELLMUL
static int count = 0;
count ++;
std::cout << count << std::endl;
#endif
#ifdef _TEST_ELLMULL
BigNum bnTemp;
DIGIT res = add( bnTemp, bnCheck, bnCheck, MAX_SIZE );
if ( res > 0 )
throw std::domain_error( "EllMul^ overflow whilw checking" );
assign( bnCheck, bnTemp, MAX_SIZE );
#endif
if ( ( bnK[i] >> j) &1){
#ifdef _TEST_ELLMUL
addDigit( bnTemp, bnCheck, 1, MAX_SIZE );
assign( bnCheck, bnTemp, MAX_SIZE );
#endif
ellAdd( epTemp, epRes, epP, ecc );
ellAssign( epRes, epTemp );
}
}
#ifdef _TEST_ELLMUL
std::cout << "bnCheck:\t" << bnCheck << std::endl;
#endif
}
*/
bool ellIsEqual( const EllPoint &ep1, const EllPoint &ep2 ){
	if ( ep1.isZero ^ ep2.isZero )
		return false;
	else if ( ep1.isZero )
		return true;

	if ( bncmp( ep1.bnX, ep2.bnX, MAX_SIZE ) == 0 &&
		bncmp( ep1.bnY, ep2.bnY, MAX_SIZE ) == 0 )
		return true;
	else
		return false;
}
bool ellIsZero( const EllPoint &ep ){
	return ep.isZero;
}


bool ellCheckValidity( const EllPoint &ep, const EllCurve &ecc ){
	if ( ep.isZero )
		return true;
	BigNum bnLeft, bnRight, bnTemp1, bnTemp2, bnTemp3;
	modmul( bnLeft, ep.bnY, ep.bnY, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp1, ep.bnX, ep.bnX, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp2, bnTemp1, ep.bnX, ecc.bnPrime, MAX_SIZE );
	modmul( bnTemp1, ep.bnX, ecc.bnA, ecc.bnPrime, MAX_SIZE );
	modadd( bnTemp3, bnTemp1, bnTemp2, ecc.bnPrime, MAX_SIZE );
	modadd( bnRight, bnTemp3, ecc.bnB, ecc.bnPrime, MAX_SIZE );
	return bncmp( bnRight, bnLeft, MAX_SIZE )==0;
}

std::ostream& operator<<(std::ostream & os, const EllPoint &ep){
	if ( !ep.isZero )
		os << ep.bnX << "||" << ep.bnY;
	else
		os << "ZeroPoint";
	return os;
}
