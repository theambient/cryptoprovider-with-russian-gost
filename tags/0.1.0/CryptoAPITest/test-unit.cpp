
#include "test-unit.h"

				// ## Not Yet
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include <wincrypt.h>
#include <iomanip>
#include <iostream>

#include "string-helpers.h"


#define GOST_SIGN_NAME "GOST R 34.10-2001"
#define GOST_SIGN_MIN_BITS 256
#define GOST_SIGN_MAX_BITS 256
#define GOST_SIGN_BITS 256
#define GOST_SIGN_PUBLIC_BITS 512
#define GOST_SIGN_OID ""
#define GOST_SIGN_OID_LEN 0
#define GOST_HASH_NAME "GOST R 34.11-94"
#define GOST_HASH_MIN_BITS 256
#define GOST_HASH_MAX_BITS 256
#define GOST_HASH_BITS 256
#define GOST_HASH_OID ""
#define GOST_HASH_OID_LEN 0
#define GOST_CRYPT_NAME "GOST 28147-89"
#define GOST_CRYPT_MIN_BITS 256
#define GOST_CRYPT_MAX_BITS 256
#define GOST_CRYPT_BITS 256
#define GOST_CRYPT_OID ""
#define GOST_CRYPT_OID_LEN 0
#define GOST_KEYX_NAME "GOST 28147-89 KeyX"
#define GOST_KEYX_MIN_BITS 256
#define GOST_KEYX_MAX_BITS 256
#define GOST_KEYX_BITS 256
#define GOST_KEYX_OID ""
#define GOST_KEYX_OID_LEN 0

/* define ALG types and clases*/
#define ALG_SID_GOST_SIGN  123
#define ALG_SID_GOST_HASH  124
#define ALG_SID_GOST_CRYPT 125
#define ALG_SID_GOST_KEYX  126

/* define CryptoAPI ALG_ID */
#define CALG_GOST_SIGN  (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_GOST_SIGN)
#define CALG_GOST_HASH  (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GOST_HASH)
#define CALG_GOST_CRYPT (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_GOST_CRYPT)
#define CALG_GOST_KEYX (ALG_CLASS_KEY_EXCHANGE |ALG_TYPE_ANY |ALG_SID_GOST_KEYX)

const char* MESSAGE = "This is message, length=32 bytes";
const int GOSTR34102001SigLen = 64;



HCRYPTPROV hProv;

#undef UNICODE	

std::ostream& operator<<(std::ostream& os, const BYTE* pbData){
	for (unsigned i=0; i<32; i++)
		os << std::setw(2) << std::setfill('0') << std::hex << (int)pbData[i];
	return os;
}


bool testAcquireContext( bool bVerbose ){

	if (!CryptAcquireContextA(&hProv, NULL,
                          "CSP Provider", 900, 0))
	{
		if (bVerbose){
			printf("CryptAcquireConext returned error %x\n", GetLastError());
			printf("FAILED\n");
		}
		return false;
	}
	else 
		return true;

}

bool testSignHash(bool bVerbose){

	BYTE *pbSignature;
	DWORD dwSigLen;
	HCRYPTHASH hHash;
	
	BYTE bHashVal[32+1] = "\x2D\xFB\xC1\xB3\x72\xD8\x9A\x11\x88\xC0\x9C\x52\xE0\xEE\xC6\x1F\xCE\x52\x03\x2A\xB1\x02\x2E\x8E\x67\xEC\xE6\x67\x2B\x04\x3E\xE5";
	if ( bVerbose )
		std::cout << "Supplied hash value is: \n" <<  bHashVal << std::endl;

	if (!(CryptCreateHash(hProv,
					  CALG_GOST_HASH,
					  0,
					  0,
					  &hHash)))
	{   
		if ( bVerbose )
			printf("CryptCreateHash Failed\n");
		return false;
	} 

	if ( !CryptSetHashParam(
		hHash,
		HP_HASHVAL,
		bHashVal,
		0))
	{
		if ( bVerbose )
			printf("CryptSetHashParam Failed\n");
		return false;
	}

	if (!CryptSignHash(hHash,
					AT_SIGNATURE,
					NULL,
					0,
					NULL,
					&dwSigLen))
	{
		if ( bVerbose )
			printf("First call to CryptSignHash Failed\n");
		return false;
	}

	pbSignature = new BYTE[dwSigLen];
	if (!CryptSignHash(hHash,
					AT_SIGNATURE,
					NULL,
					0,
					pbSignature,
					&dwSigLen))
	{
		if ( bVerbose )
			printf("Second call to CryptSignHash Failed\n");
		return false;
	}
	if ( bVerbose )
		std::cout << "Signature:\n" << pbSignature << pbSignature + GOSTR34102001SigLen/2 << std::endl;
	
	BYTE bBenchmarkSignature[64];
	strtobyte( "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC049301456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40" , bBenchmarkSignature );
	if ( memcmp ( bBenchmarkSignature, pbSignature, 64 )==0 )
		return TRUE;
	else
		return false;
}

bool testVerifyHash(bool bVerbose){

	BYTE bSignature[64];
	strtobyte( "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC049301456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40" , bSignature );
	DWORD dwSigLen = 64;
	HCRYPTHASH hHash;
	HCRYPTKEY hPub;
	
	BYTE bHashVal[32+1] = "\x2D\xFB\xC1\xB3\x72\xD8\x9A\x11\x88\xC0\x9C\x52\xE0\xEE\xC6\x1F\xCE\x52\x03\x2A\xB1\x02\x2E\x8E\x67\xEC\xE6\x67\x2B\x04\x3E\xE5";
	if ( bVerbose )
		std::cout << "Supplied hash value is: \n" <<  bHashVal << std::endl;

	if (!(CryptCreateHash(hProv,
					  CALG_GOST_HASH,
					  0,
					  0,
					  &hHash)))
	{   
		if ( bVerbose )
			printf("CryptCreateHash Failed\n");
		return false;
	} 

	if ( !CryptSetHashParam(
		hHash,
		HP_HASHVAL,
		bHashVal,
		0))
	{
		if ( bVerbose )
			printf("CryptSetHashParam Failed\n");
		return false;
	}


	if ( !CryptGetUserKey( 
		hProv,
		AT_SIGNATURE,
		&hPub ))
	{
		if ( bVerbose )
			printf("CryptGetUserKey Failed\n");
		return false;
	}
	if (!CryptVerifySignature(hHash,
					       bSignature,
					       dwSigLen,
					       hPub,
					       NULL,
					       0))
	{
		if ( bVerbose )
			printf("Test Failed\n");
		return false;
	}

	return true;
}

bool testHashData(bool bVerbose){

	HCRYPTHASH hHash;
	BYTE bDataToHash[32];
	BYTE bHashValue[32];
	BYTE bBenchmarkHashValue[32];
	//strtobyte( "73657479622032333D6874676E656C202C6567617373656D2073692073696854", bDataToHash );
	memcpy( bDataToHash, "This is message, length=32 bytes", 32 );
	strtobyte( "FAFF37A615A816691CFF3EF8B68CA247E09525F39F8119832EB81975D366C4B1", bBenchmarkHashValue );

	if (!(CryptCreateHash(hProv,
					  CALG_GOST_HASH,
					  0,
					  0,
					  &hHash)))
	{   
		if ( bVerbose )
			printf("CryptCreateHash Failed\n");
		return false;
	}

	DWORD dwHashLen = 32;
	if ( !CryptHashData( hHash, bDataToHash, 32, 0 ) ){
		if ( bVerbose )
			printf("CryptHashData Failed\n");
		return false;
	}

	if ( !CryptGetHashParam( hHash, HP_HASHVAL, bHashValue, &dwHashLen, 0 ) ){
		if ( bVerbose )
			printf("CryptGetHashParam Failed\n");
		return false;
	}

	if ( memcmp( bHashValue, bBenchmarkHashValue, dwHashLen ) != 0 ){
		if ( bVerbose )
			std::cout << bHashValue << std::endl;
		return false;
	}

	if ( !CryptDestroyHash( hHash ) ){
		if ( bVerbose )
			std::cout << "CryptDestroyHash failed" << std::endl;
		return false;
	}

	return true;

}

bool testHashDataLong(bool bVerbose){

	HCRYPTHASH hHash;
	BYTE bDataToHash[50];
	BYTE bHashValue[32];
	BYTE bBenchmarkHashValue[32];
	//strtobyte( "73657479622032333D6874676E656C202C6567617373656D2073692073696854", bDataToHash );
	memcpy( bDataToHash, "Suppose the original message has length = 50 bytes", 50 );
	strtobyte( "0852F5623B89DD57AEB4781FE54DF14EEAFBC1350613763A0D770AA657BA1A47", bBenchmarkHashValue );

	if (!(CryptCreateHash(hProv,
					  CALG_GOST_HASH,
					  0,
					  0,
					  &hHash)))
	{   
		if ( bVerbose )
			printf("CryptCreateHash Failed\n");
		return false;
	}

	DWORD dwHashLen = 32;
	if ( !CryptHashData( hHash, bDataToHash, 50, 0 ) ){
		if ( bVerbose )
			printf("CryptHashData Failed\n");
		return false;
	}

	if ( !CryptGetHashParam( hHash, HP_HASHVAL, bHashValue, &dwHashLen, 0 ) ){
		if ( bVerbose )
			printf("CryptGetHashParam Failed\n");
		return false;
	}

	if ( memcmp( bHashValue, bBenchmarkHashValue, dwHashLen ) != 0 ){
		if ( bVerbose )
			std::cout << bHashValue << std::endl;
		return false;
	}

	if ( !CryptDestroyHash( hHash ) ){
		if ( bVerbose )
			std::cout << "CryptDestroyHash failed" << std::endl;
		return false;
	}

	return true;

}

bool testCrypt(const unsigned uiVerboseLevel){
	HCRYPTKEY hKey = NULL;
	if ( !CryptGenKey( hProv,
		CALG_GOST_CRYPT,
		0,
		&hKey) )
	{
		if ( uiVerboseLevel > 0 )
			std::cout << "CryptGenKey failed" << std::endl;
		return false;
	}
	const DWORD cdwPlainTextLen = 70;
	const DWORD cdwBufLen = 170;
	DWORD dwDataLen = cdwPlainTextLen;
	BYTE *pbData = new BYTE[cdwBufLen];
	BYTE *pbDataCopy = new BYTE[dwDataLen];
	if ( !CryptGenRandom( hProv,
		dwDataLen, 
		pbData) )
	{

		if ( uiVerboseLevel > 0 )
			std::cout << "CryptGenRandom failed" << std::endl;
		return false;
	}
	memcpy( pbDataCopy, pbData, dwDataLen );

	if ( uiVerboseLevel > 1 ){
		print( std::cout, pbData, dwDataLen );
	}

	if ( !CryptEncrypt(
		hKey,
		0,
		TRUE,
		0,
		pbData,
		&dwDataLen,
		cdwBufLen))
	{
		if ( uiVerboseLevel > 0 )
			std::cout << "CryptEncrypt failed" << std::endl;
		return false;
	}

	if ( uiVerboseLevel > 1 ){
		print( std::cout, pbData, dwDataLen );
	}

	if ( !CryptDecrypt(
		hKey,
		0,
		TRUE,
		0,
		pbData,
		&dwDataLen))
	{
		if ( uiVerboseLevel > 0 )
			std::cout << "CryptDecrypt failed" << std::endl;
		return false;
	}

	if ( uiVerboseLevel > 1 ){
		print( std::cout, pbData, dwDataLen );
	}

	/*if ( dwDataLen != cdwPlainTextLen ){
		if ( uiVerboseLevel > 0 )
			std::cout << "Length of decrypted text is not equal length of plaintext" << std::endl;
		return false;
	}*/

	if ( memcmp( pbData, pbDataCopy, cdwPlainTextLen ) != 0 ){
		if ( uiVerboseLevel > 0 )
			std::cout << "Decrypted text and plaintext do not match" << std::endl;
		return false;
	}

	return true;
}	





