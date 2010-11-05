
#ifndef GOST_SIGNATURE_HEADER_FILE
#define GOST_SIGNATURE_HEADER_FILE

#include "types.h"
#include "params.h"

void hash( const char* message, DIGIT hashvalue[]);
void sign( const DIGIT hash[], const DIGIT prKey[], DIGIT signature[], const Params &params);
bool verify( const DIGIT hash[], const DIGIT signature[], const DIGIT PubKey[], const Params &params);

#endif //GOST_SIGNATURE_HEADER_FILE