
#include "types.h"
#include <limits>
#include <stdexcept>
#include <cctype>


// конвертирует строку, содержащую шестнадцетиричное представление числа в массив byte*
inline DIGIT chartobyte ( const char c ){
	int i = toupper( c );
	if (  i  >= int('A') )
		return i - int('A')+0xA;
	else
		return i - int('0');

}

// конвертирует строку, содержащую 16-ричное представлеие длинного числа 
// в длинное число длинны N
// в случае переполнени€ лишние цифры тер€ютс€, иначе - дополн€ютьс€ лидирующими нул€ми
// возвращает
//   -1  в случае ошибки
//    0  в случае переполнени€ (не все цифры обработанны)
//    1  в случае успеха
int strtodigitn( const char* s, DIGIT bn[], const unsigned num){
	const unsigned charPerByte = baseDigits / 4;
	const char* const p = s-1;
	while ( *s != '\0' )
		s++;
	s--;
	// s указывает на конец строки
	for (unsigned i=0; i<num; i++){
		bn[i] = 0;
		unsigned count=0;
		DIGIT degree = 1;
		while (s !=p && count < charPerByte ) {
			if ( !isxdigit(*s) )
				return -1;
			bn[i]= bn[i]+ chartobyte(*s)*degree;
			degree*=16;
			count++;
			s--;
		}
	}
	return int( s == p );
}

