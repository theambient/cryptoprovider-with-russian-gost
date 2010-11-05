
#ifndef ELLIPTIC_HEADER_FILE
#define ELLIPTIC_HEADER_FILE

#include "types.h"
#include "bignumber.h"

#include <stdexcept>

// моделирует эллиптическую кривую (праметры эллиптической кривой)
struct EllCurve {
	BigNum bnA;
	BigNum bnB;
	BigNum bnPrime;
};

// реализует точку на эллиптической кривой (элемент в группе точек на элл. кривой)
struct EllPoint {
	BigNum bnX;
	BigNum bnY;
	bool isZero;
};

struct EllPointProject {
	BigNum bnXP, bnYP, bnZP;
};

// конструткторы
void ellCurveInit( EllCurve &ecc, const BigNum &bnA,  const BigNum &bnB, const BigNum &bnPrime );
void ellInit( EllPoint &ep, const DIGIT x0[], const DIGIT y0[], const EllCurve &ecc );
void ellInit( EllPoint &ep, const EllCurve &ecc );

void ellAssign( EllPoint &ellDst, const EllPoint &ellSrc );

void ellAdd( EllPoint &epRes, const EllPoint &ep1, const EllPoint &ep2, const EllCurve &ecc );
void ellProjectiveAdd( EllPoint &epRes, const EllPoint &ep1, const EllPoint &ep2, const EllCurve &ecc );
void ellMul( EllPoint &epRes, const BigNum &bnK, const EllPoint &epQ, const EllCurve &ecc );

bool ellIsEqual( const EllPoint &ep1, const EllPoint &ep2 );
bool ellIsZero( const EllPoint &eP );
bool ellCheckValidity( const EllPoint &eP, const EllCurve &ecc );

std::ostream& operator<<(std::ostream & os, const EllPoint &eP);


#endif // ELLIPTIC_HEADER_FILE