

#ifndef _STRING_HELPERS_HEADER_FILE
#define _STRING_HELPERS_HEADER_FILE

#include <windows.h>

// конвертирует строку с шестнадцатиричным представлением числа 
// в 'octet string' - несимвольную строку значений.
void strtobyte(const char* sChar, BYTE* sOctet);



#endif //_STRING_HELPERS_HEADER_FILE