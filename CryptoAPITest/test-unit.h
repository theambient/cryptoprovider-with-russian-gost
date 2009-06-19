
#ifndef _TEST_UNIT_HEADER_FILE
#define _TEST_UNIT_HEADER_FILE

#include <windows.h>
#include <wincrypt.h>
#include <cspdk.h>


bool testAcquireContext(bool);

bool testGenKey();

bool testGetProvParam();

bool testExportKey();

bool testImportKey();

bool testGetUserKey();

bool testDecrypt();

bool testDecrypt();

bool testDecrypt();

bool testCreateHash();
bool testHashData();
bool testSignHash(bool);
bool testVerifyHash(bool);


#endif //_TEST_UNIT_HEADER_FILE