
#ifndef BIGNUMBER_HEADER_FILE
#define BIGNUMBER_HEADER_FILE

#include "types.h"
#include <limits>
#include <memory.h>
#include <iostream>

/*void assign( DIGIT bn1[], const DIGIT bn2[], const unsigned num );
void assignDigit( DIGIT bn[], DIGIT value, const unsigned num );
void zero( DIGIT bn[], const unsigned num );
*/
bool isZero( const DIGIT bn[], const unsigned num );
int bncmp( const DIGIT bn1[], const DIGIT bn2[], const unsigned num );

// сложение двух длинных чисел: 
//		res = bn1 + bn2
// возвращает:
//		бит переноса
DIGIT add( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const unsigned num );

// сложение двух длинных чисел: 
//		res = bn1 + bn2
// возвращает:
//		бит переноса
DIGIT addDigit( DIGIT res[], const DIGIT bn1[], const DIGIT x, const unsigned num );


// вычитание двух длинных чисел:
//		res = bn1 - bn2
// возвращает:
//		бит заема
DIGIT sub( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const unsigned num );

// вычитание цифры из длинного числа:
//		res = bn1 - bn2
// возвращает:
//		бит заема
DIGIT subDigit( DIGIT res[], const DIGIT bn1[], const DIGIT x, const unsigned num );

// умножение двух длинных чисел:
//		res = bn1*bn2;
// реализован алгоритм умножения столбиком
// возвращает:
//		<ничего>
void mul( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const unsigned num );

// умножение цифры на длинное число:
//		res = bn1*bn2;
// возвращает:
//		<ничего>
void shortMul( DIGIT res[], const DIGIT bn[], const DIGIT x, const unsigned num );

// вычисление квадрата длинного числа
//		res = bn^2;
// возвращает:
//		<ничего>
void square( DIGIT res[], const DIGIT bn[], const unsigned num );

// деление длинного числа на цифру с вычислением остатка от деления:
//      bnQuo = [bn1/bn2]
//		bnRem = bn1 mod bn2;
// возвращает:
//		<ничего>
void shortDiv( DIGIT *res, const DIGIT bn[], DIGIT x, DIGIT *rem, unsigned num );

// деление длинного числа на длинное число с вычислением остатка от деления:
//      bnQuo = [bn1/bn2]
//		bnRem = bn1 mod bn2 == (bn1 - bnQuo*bn2);
// возвращает:
//		<ничего>
void div( const DIGIT bn1[], const DIGIT bn2[], DIGIT *bnQuo, DIGIT *bnRem, const unsigned num1, const unsigned num2 );

// сложение двух длинных чисел по модулю:
//		res = bn1+bn2 (mod bnMod);
// возвращает:
//		<ничего>
void modadd( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num );

// вычитание двух длинных чисел по модулю:
//		res = bn1-bn2 (mod bnMod);
// возвращает:
//		<ничего>
void modsub( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num );


// умножение двух длинных чисел по модулю:
//		res = bn1*bn2 (mod bnMod);
// возвращает:
//		<ничего>
void modmul( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num );

// вычисление квадрата длинного числа по модулю
//		res = bn^2 (mod bnMod);
// возвращает:
//		<ничего>
void modSquare( DIGIT res[], const DIGIT bn[], const DIGIT bnMod[], const unsigned num );

// деление двух длинных чисел по модулю:
//		res = bn1/bn2 (mod bnMod);
// возвращает:
//		<ничего>
void moddiv( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num );

// умножение двух длинных чисел по Монтгомери:
//		res = bn1*bn2 (mod bnMod);
// возвращает:
//		<ничего>
void montMul( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], DIGIT z, const unsigned num );

// умножение цифры на длинное число по модулю:
//		res = x*bn2 (mod bnMod);
// возвращает:
//		<ничего>
void modmulShort( DIGIT res[], const DIGIT bn1[], const DIGIT x, const DIGIT bnMod[], const unsigned num );

// возведение в степень длинного числа по модулю:
//		res = bnBase^bnDegree (mod bnMod);
// возвращает:
//		<ничего>
//void modPower( DIGIT res[], const DIGIT bnBase[], const DIGIT bnDegree[], const DIGIT bnMod[], const unsigned numDegree, const unsigned numMod );

// возведение в степень длинного числа по модулю с использованием операции Монтгомери:
//		res = bnBase^bnDegree (mod bnMod);
// возвращает:
//		<ничего>
void modPowerMont( DIGIT res[], const DIGIT bnBase[], const DIGIT bnDegree[], const DIGIT bnMod[], const unsigned numDegree, const unsigned numMod );

// вычисление наибольшего общего делителя по расширенному алгоритму евклида:
//		bnGCD = НОД( bnA, bnB );
// входные параметры:
//		bnA, bnB	- два больших числа длины num
//		num			- длина больших чисел (unsigned)
// выходные параметры:
//		bnGCD		- наибольший общий делитель чисел bnA, bnB
//		bnX, bnY	- целые числа (длины num) такие, что bnX * bnA + bnY * bnB = 1
//		bXNegative  - отрицательность целого длинного числа bnX
//		bYNegative  - отрицательность целого длинного числа bnY
// возвращает:
//		<ничего>
void gcd(DIGIT bnGCD[], const DIGIT bnA[], const DIGIT bnB[], DIGIT bnX[], DIGIT bnY[], bool &bXNegative, bool &bYNegative, const unsigned num );

// вычисление мультипликативного обратного элемента в поле классов вычетов (по модулю):
//		res = bnA^{-1} (mod bnMod) = 1/bnA (mod bnMod);
// входные параметры:
//		bnA			- большое число длины num
//		bnMod		- модуль по которому вычисляется обратное
//		num			- длина больших чисел (unsigned)
// выходные параметры:
//		res	- большое число, мультипликативное обратное bnA по модулю bnMod
// возвращает:
//		<ничего>
void modInvert(DIGIT res[], const DIGIT bnA[], const DIGIT bnMod[], const unsigned num );

// вычисление противоположного элемента в поле классов вычетов (по модулю):
//		res = -bnA (mod bnMod);
// входные параметры:
//		bnA			- большое число длины num
//		bnMod		- модуль по которому вычисляется обратное
//		num			- длина больших чисел (unsigned)
// выходные параметры:
//		res	- большое число, противоположный элемент bnA по модулю bnMod
// возвращает:
//		<ничего>
void modNegative(DIGIT bnNegative[], const DIGIT bnA[], const DIGIT bnMod[], const unsigned num );

void print( const DIGIT bn[], const unsigned num );

std::ostream& operator<<( std::ostream &os, const BigNum &bn);


////////////////////////////////////////////////////////////////////////////////////////////////
///////////																	////////////////////
///////////					INLINE FUNCTION IMPLEMENTATION					////////////////////
///////////																	////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

inline void assign( DIGIT bn1[], const DIGIT bn2[], const unsigned num ){
	//memcpy( bn1, bn2, num*sizeof(DIGIT) );
	for (unsigned i=0; i<num; i++)
		bn1[i] = bn2[i];
}

inline void assignDigit( DIGIT bn[], DIGIT value, const unsigned num ){
	bn[0] = value;
	//memset( &bn[1], 0, (num-1)*sizeof(DIGIT) );
	for (unsigned i=1; i<num; i++)
		bn[i] = 0;
}

inline void zero( DIGIT bn[], const unsigned num ){
	//memset( bn, 0, num*sizeof(DIGIT) );
	for (unsigned i=0; i<num; i++)
		bn[i] = 0;
}

inline void modNegative(DIGIT bnNegative[], const DIGIT bnA[], const DIGIT bnMod[], const unsigned num ){
#ifdef _VERBOSE_CHECKING
	if ( bncmp(bnA, bnMod, num)>0 ){
		throw std::invalid_argument( "modNegative: Invalid params - bnA > bnMod" );
	}
#endif
	sub( bnNegative, bnMod, bnA, num );
}

inline void modadd( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num ){
	DIGIT bnTemp[MAX_SIZE];
	DIGIT shift = add( bnTemp, bn1, bn2, num );
	if ( shift > 0 || bncmp(bnTemp, bnMod , num) >= 0 ){
#ifdef _VERBOSE_CHECKING
		DIGIT borrow = sub( res, bnTemp, bnMod, num );
		if ( (borrow > 0 && shift == 0) ||
			(borrow ==0 && shift > 0) ){
				throw std::domain_error( "modadd: something weird - shift and borrow flags do not match" );
		}
#else
		sub( res, bnTemp, bnMod, num );
#endif
	} else {
		assign( res, bnTemp, MAX_SIZE );
	}
}

inline void modsub( DIGIT res[], const DIGIT bn1[], const DIGIT bn2[], const DIGIT bnMod[], const unsigned num ){
	DIGIT bnTemp[MAX_SIZE];
	modNegative( bnTemp, bn2, bnMod, num );
	modadd( res, bn1, bnTemp, bnMod, num );
}

inline void modSquare( DIGIT res[], const DIGIT bn[], const DIGIT bnMod[], const unsigned num ){
	DIGIT bnTemp[MAX_SIZE*2];
	square( bnTemp, bn, num);
	div( bnTemp, bnMod, NULL, res, 2*num, num );
}

inline void square( DIGIT res[], const DIGIT bn[], const unsigned num ){
	mul( res, bn, bn, num );
}

inline bool isEven( const DIGIT bn[], const unsigned num ){
	return bn[0] & 1;
}

inline void halfDiv( DIGIT bn[], const unsigned num ){
	static DIGIT mask = 1 << (baseDigits-1);
	for (unsigned i=0; i<num; i++){
		bn[i] >>= 1;
		bn[i] |= (mask & bn[i+1]);
	}
	bn[num-1] &= DIGIT(-1)>>1;
}

#endif //BIGNUMBER_HEADER_FILE

