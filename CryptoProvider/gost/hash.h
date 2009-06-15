
#include "ippcp.h"

typedef unsigned char byte; // ќбъ€вл€ем тип byte = unsigned char

// byte arr[] - ссылка на область пам€ти - хэшируемые данные
// int len - длина этой области в байтах
// byte res[] - ссылка на существуюший массив размером 32 байта - результат хэшировани€
void hash(const byte arr[], const int len, byte res[]);
