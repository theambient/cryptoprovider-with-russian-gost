
#include "ippcp.h"
#include "types.h"


// создает точку элиптической кривой: выделяет под нее память и инициализирует ее, 
// в случае, если параметры pPX, pPY одновременно не NULL
// параметры:
//		feBitSize	-	размер в битах элемента поля
//		pPX, pPY	-	x и y координаты точки
//		pECC		-	конекст эллиптической кривой
// возвращаемое значение:
//		указатель на выделенный и возможно инициализированный контекст точки элл. кривой

IppsECCPPointState* eccPointNew( const IppsBigNumState *pPX, const IppsBigNumState* pPY, IppsECCPState *pECC);

// создает точку элиптической кривой: выделяет под нее память 
// и инициализирует ее как точку в бесконечности ( с неопределенными координатами),
// нуль группы точек эллептической кривой)
// параметры:
//		feBitSize	-	размер в битах элемента поля
//		pECC		-	конекст эллиптической кривой (если координаты NULL, то определять не обязательно)
// возвращаемое значение:
//		указатель на выделенный контекст точки элл. кривой, инициализированный как бесконечно-удаленная точка

IppsECCPPointState* eccPointNew( IppsECCPState *pECC);

// освобождает память, отведенную под контекст точки эллиптической кривой 

void eccPointRelease( IppsECCPPointState* pPoint);

void eccPointToOctet( IppsECCPPointState *pPoint, Ipp8u *pRawKey, IppsECCPState *pECC );

// создает точку эллиптической кривой из ключевого материала - 
// битового вектора, содержащего координаты этой точки.
// параметры:
//		baseData		- ключевой материал: битовый вектор длины keyLengt, hсодержащий координаты точки (X||Y)
//		byteDataLength	- длина в байтах ключеого материала
//		pECC			- контекст эллиптической кривой
IppsECCPPointState* eccPointNew( const Ipp8u* baseData, const int byteDataLength, IppsECCPState* pECC);