
#include "ippcp.h"
#include "bignum/bignum.h"

#ifndef _RAND_HEADER_FILE
#define _RAND_HEADER_FILE

// реализует генератор случайных чисел
class Rand {
public:
	// создает и инициализирует генератор случайных чисел
	// параметры:
	//		iSeedSize	- размер инициализирующего значения в байтах
	//							если 0 - то инициализирует из внешнего источника
	//		pSeedValue	- указатель на инициализирующее значение,
	//							если NULL - то инициализирует из внешнего источника
	Rand(const int iSeedSize = 0, unsigned char *pSeedValue = NULL);

	~Rand();

	IppsPRNGState* getPRNG(){ return pPRNG; }

	// генерирует случайное число длины iSize байт
	IppsBigNumState* operator()(const int iSize);
protected:
	IppsPRNGState* pPRNG;
};

/*
// создает и инициализирует генератор случайных чисел
// параметры:
//		pPRNG		- контекст генератор псевдослучайных чисел
//		iSeedSize	- размер инициализирующего значения в 32-х битных словах
//							если 0 - то инициализирует из внешнего источника
//		pSeedValue	- указатель на инициализирующее значение,
//							если NULL - то инициализирует из внешнего источника
void randInit(IppsPRNGState* pPRNG, const int iSeedSize = 0, IppsBigNumState *pSeedValue = NULL);

// инициализирует генератор случайных чисел
// параметры:
//		seedValue	- указатель на инициализирующее значение
// замечания:
//		- размер инициализирующего значения не должен превышать указанное при создании генератора значение seedBits
//		- генератор должен быть уже создан функцией randInit
void randSetSeed(IppsPRNGState* pPRNG, IppsBigNumState *pSeedValue );

// выделяет память и генерирует псевдослучайное число
// параметры:
//		iSize		- длина в 32-х битных словах генерируемого псевдослучайного числа
// замечания:
//		- генератолр должен быть уже создан функцией randInit
//		- память под генерируемое ПСЧ выделяется этой же функцией
IppsBigNumState* bnRand(int iSize, IppsPRNGState* pPRNG);

*/

#endif //_RAND_HEADER_FILE