

#include "string-helpers.h"
#include <iostream>
#include <iomanip>

inline int chartobyte ( const char c ){
	if ( !isxdigit(c) )
		std::cerr << "chartobyte: " << c << " is not valid hex digit\n";
	int i = toupper( c );
	if (  i  >= int('A')  )
		return i - int('A')+0xA;
	else
		return i - int('0');
}


// конвертирует строку с шестнадцатиричным представлением числа 
// в 'octet string' - несимвольную строку значений.
void strtobyte(const char* sChar, BYTE* sOctet){
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

void print( std::ostream &os, const BYTE* pbData, const unsigned uiLen ){
	for( unsigned i=0; i<uiLen; i++)
		os << std::hex << std::setfill('0') << std::setw(2) << (int) pbData[i];
	os << std::endl;
}
