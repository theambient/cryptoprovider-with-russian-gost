
#ifndef _TEST_UNIT_HEADER_FILE
#define _TEST_UNIT_HEADER_FILE

#include <windows.h>
#include <wincrypt.h>
#include <cspdk.h>


bool testAcquireContext(bool);

bool testGenKey(bool);

bool testGetProvParam(bool);

bool testExportKey(bool);

bool testImportKey(bool);

bool testGetUserKey(bool);

bool testCrypt(unsigned uiVerboseLevel);

bool testCreateHash(bool);
bool testHashData(bool);
bool testHashDataLong(bool);
bool testSignHash(bool);
bool testVerifyHash(bool);


#endif //_TEST_UNIT_HEADER_FILE