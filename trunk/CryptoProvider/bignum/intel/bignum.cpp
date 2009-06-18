
#include "bignum.h"
#include <iomanip>
#include "types.h"

inline int chartobyte ( const char c ){
	if ( !isxdigit(c) )
		std::cerr << "chartobyte: " << c << " is not valid hex digit\n";
	int i = toupper( c );
	if (  i  >= int('A')  )
		return i - int('A')+0xA;
	else
		return i - int('0');
}

inline char bytetochar( const int n ){

	static char xlat[16] = {
		'0', '1', '2', '3',
		'4', '5', '6', '7',
		'8', '9', 'A', 'B',
		'C', 'D', 'E', 'F'
	};

	if ( n > 15)
		throw std::invalid_argument( "bytetochar: the supplied value of argument n is invalid - n > 15" );	

	return xlat[n];
}

// конвертирует строку с шестнадцатиричным представлением числа 
// в 'octet string' - несимвольную строку значений.
void strtoIpp8u(const char* sChar, Ipp8u* sOctet){
	int length = (int) strlen( sChar );
	// если длина нечетная
	if ( length%2 == 1){
		for( unsigned i=(length-1)/2; i>0; i--){
			sOctet[i] = chartobyte(sChar[2*i-1])*16 + chartobyte(sChar[2*i]);
			//std::clog << std::hex << (int) sOctet[i] << std::endl;
		}
		sOctet[0] = chartobyte(sChar[0]);
	}
	else {
		for( unsigned i=(length-1)/2; i+1>0; i--){
			sOctet[i] = chartobyte(sChar[2*i])*16 + chartobyte(sChar[2*i+1]);
		}
	}
}

std::ostream& operator<<(std::ostream& os, const IppStatus ips){
	switch ( ips ){
		case ippStsNoErr:
			os << "ippStsNoErr";
			break;
		case ippStsNullPtrErr:
			os << "ippStsNullPtrErr";
			break;
		case ippStsLengthErr:
			os << "ippStsLengthErr";
			break;
		case ippStsOutOfRangeErr:
			os << "ippStsOutOfRangeErr";
			break;
		case ippStsBadArgErr:
			os << "ippStsBadArgErr";
			break;
		case ippStsContextMatchErr:
			os << "ippStsContextMatchErr";
			break;
		case ippStsSizeErr:
			os << "ippStsSizeErr";
			break;
		default:
			os << "Unknown IppStatus";
	}
	return os;
}

IppsBigNumState* bnNew(const int size, const Ipp32u* pData){
	// get the size of the Big Number context
	int ctxSize;
	IppStatus res; 
	res = ippsBigNumGetSize(size, &ctxSize);
	if (res != ippStsNoErr )
		std::cerr << res;
	// allocate the Big Number context
	IppsBigNumState* pBN = (IppsBigNumState*) ( new Ipp8u[ctxSize] );
	// and initialize one
	res = ippsBigNumInit(size, pBN);
	if (res != ippStsNoErr )
		std::cerr << res;
	// if any data was supplied, then set up the Big Number value
	if(pData){
		res = ippsSet_BN(IppsBigNumPOS, size, pData, pBN);
		if (res != ippStsNoErr )
			std::cerr << res;
	}
	// return pointer to the Big Number context for future use
	return pBN;
}

void bnRelease( IppsBigNumState * pBN ){

	delete[] (Ipp8u*) pBN;
	pBN = NULL;
}

IppsBigNumState* bnNew(const char* sBN, const int size){
	// get the size of the Big Number context
	int ctxSize;
	const int strSize = (const int)(strlen(sBN)+7)/8;
	if ( strSize > size ){
		std::cerr << "Caution in IppsBigNumState* bnNew(const char* sBN, int size):\n\t size of string number representation greater then params size supplied\n";
		std::cerr << sBN << std::endl;
	}
	IppStatus res; 
	res = ippsBigNumGetSize(size, &ctxSize);
	if (res != ippStsNoErr )
		std::cerr << res;
	// allocate the Big Number context
	IppsBigNumState* pBN = (IppsBigNumState*) ( new Ipp8u[ctxSize] );
	// and initialize one
	res = ippsBigNumInit(size, pBN);
	if (res != ippStsNoErr )
		std::cerr << res;

	Ipp8u* octetStr = new Ipp8u[(strlen(sBN)-1)/2+1+1];
	strtoIpp8u( sBN, octetStr);
	res = ippsSetOctString_BN(octetStr, (int)(strlen(sBN)-1)/2+1, pBN);	
	if (res != ippStsNoErr )
		std::cerr << res;
	delete[] octetStr;
	// return pointer to the Big Number context for future use
	return pBN;
}

void bnCopy(IppsBigNumState *pDest, const IppsBigNumState *pSource, const int size){

	int iCtxSize;
	ippsBigNumGetSize (size, &iCtxSize );
	memcpy( pDest, pSource, iCtxSize ) ;
}

IppsBigNumState* bnNew(const int size, const Ipp8u *pData){
	// get the size of the Big Number context
	int ctxSize;
	IppStatus res; 
	res = ippsBigNumGetSize(size, &ctxSize);
	if (res != ippStsNoErr )
		std::cerr << res;
	// allocate the Big Number context
	IppsBigNumState* pBN = (IppsBigNumState*) ( new Ipp8u[ctxSize] );
	// and initialize one
	res = ippsBigNumInit(size, pBN);
	if (res != ippStsNoErr )
		std::cerr << res;

	res = ippsSetOctString_BN(pData, 4*size, pBN);	
	if (res != ippStsNoErr )
		std::cerr << res;
	// return pointer to the Big Number context for future use
	return pBN;
}

void bnGet(const IppsBigNumState* pBN, BYTE* pBuf, const int iBufSize){

	int iLocalBufSize = iBufSize;
	Ipp32u res = ippsGetOctString_BN( pBuf, iLocalBufSize, pBN );
	if ( res != ippStsNoErr )
		std::cerr << "bnGet: ippsGetOctString_BN return following value - " << res << std::endl;
}

void bnAdd(IppsBigNumState* pA, IppsBigNumState* pB, IppsBigNumState* pRes ){
	Ipp32u res = ippsAdd_BN( pA, pB, pRes );
	if ( res != ippStsNoErr )
		std::cerr << "bnAdd: ippsAdd_BN return following value - " << res << std::endl;
}

void bnSub(IppsBigNumState* pA, IppsBigNumState* pB, IppsBigNumState* pRes ){
	Ipp32u res = ippsSub_BN( pA, pB, pRes ); 
	if ( res != ippStsNoErr )
		std::cerr << "bnSub: ippsSub_BN return following value - " << res << std::endl;
}


bool bnConvertToString ( const IppsBigNumState *pBN, char* sBN ){
	// size of Big Number
	int size;
	Ipp32u res = ippsGetSize_BN(pBN, &size);
	if ( res != ippStsNoErr )
		std::cerr << res << std::endl;
	// extract Big Number value and convert it to the string presentation
	Ipp8u* bnValue = new Ipp8u [size*4+4];
	res = ippsGetOctString_BN(bnValue, size*4, pBN);
	if ( res != ippStsNoErr ){
		std::cerr << res << std::endl;
		return false;
	}
	// save representation
	for(int i=0; i<size*4; i++)
		sBN[i] = bytetochar(bnValue[i]);
	delete[] bnValue;	
	return true;
}

std::ostream& operator<<(std::ostream& os, const IppsBigNumState* pBN){
	// size of Big Number
	int size;
	Ipp32u res = ippsGetSize_BN(pBN, &size);
	if ( res != ippStsNoErr )
		std::cerr << res << std::endl;
	// extract Big Number value and convert it to the string presentation
	Ipp8u* bnValue = new Ipp8u [size*4+4];
	res = ippsGetOctString_BN(bnValue, size*4, pBN);
	if ( res != ippStsNoErr )
		std::cerr << res << std::endl;
	// type value
	for(int i=0; i<size*4; i++)
		os<< std::setfill('0') << std::setw(2) << std::hex <<(int)bnValue[i];
	delete[] bnValue;	
	return os;
}

void bnSet( IppsBigNumState *pBN, const char * sBN){
	Ipp8u* octetStr = new Ipp8u[strlen(sBN)/2];
	strtoIpp8u( sBN, octetStr);
	ippsSetOctString_BN(octetStr, (int)strlen(sBN)/2, pBN);
	delete[] octetStr;
}