
#include "ecc/ecc.h"
#include "bignum/bignum.h"
#include "Params.h"
#include "rand/rand.h"
#include <windows.h>

// функция вычисления хеша для произвольного блока данных, содержащягося в буфере buf длины iBufSize
// параметры:
//		pBuf		- указатель на буфер данных, для которых вычисляется хеш
//		iBufSize	- размер буфера данных в байтах
//		pDigestMsg	- указатель на буфер размером 256 бит, в который будет записано значение хеш-функции
//		params		- параметры вычисления хеш-функции
void digest(const BYTE *pBuf, const int iBufSize, BYTE *pDigestMsg, const PARAMS_GOST_HASH *params);

// функция вычисления ЭЦП по ГОСТ Р 34.10-2001
// параметры:
//		pDigestMsg	- указатель на буфер размером 256 бит, содержащий значение хеш-функции
//		pPrivateKey - указатель на закрытый ключ пользователя
//		pSignature	- указатель на буфер длины 512 бит, в который будет записано значение ЭЦП 
//		params		- параметры схемы ЭЦП
//		rand		- генератор случайных чисел
void sign(const BYTE *pDigestMsg, const IppsBigNumState *pPrivateKey, BYTE *pSignature, const PARAMS_GOST_SIGN *params, Rand & rand);

// функция проверки ЭЦП по ГОСТ Р 34.10-2001
// параметры:
//		pDigestMsg	- указатель на буфер размером 256 бит, содержащий значение хеш-функции
//		pPublicKey	- указатель на открытый ключ пользователя (точку элл. кривой)
//		pSignature	- указатель на буфер длины 512 бит, содержащий проверяемое значение ЭЦП
//		params		- параметры схемы ЭЦП
bool verify(const BYTE *pDigestMsg, const IppsECCPPointState *pPublicKey, const BYTE *pSignature, const PARAMS_GOST_SIGN *params);

// генерирует ключевую пару
// параметры:
//		pPublicKey	- указатель на открытый ключ пользователя (точку элл. кривой)
//		pPrivateKey - указатель на закрытый ключ пользователя
//		params		- параметры схемы ЭЦП
//		rand		- генератор случайных чисел
// замечания:
//		- память под ключи заранее выделять НЕ надо, она будет выделена автоматически
bool genKeyPair(IppsECCPPointState **ppPublicKey, IppsBigNumState **ppPrivateKey, const PARAMS_GOST_SIGN *pParams, Rand *pRand);
