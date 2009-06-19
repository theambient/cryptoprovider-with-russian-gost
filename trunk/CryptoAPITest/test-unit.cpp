
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
	strtobyte( "1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C4041AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493" , bBenchmarkSignature );
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


/*
bool test(){

//    HANDLE         hEvent;
    HCRYPTPROV     hProv;
    HCRYPTKEY      hKey;
    HCRYPTKEY      hKey2;
    HCRYPTPROV     hHash;
    HCRYPTKEY      hPub;
    HCRYPTKEY      hUser;
    CHAR           pszMyName[64];
//    HFILE          hFile;
//    OFSTRUCT       ImageInfoBuf;

    printf("Calling CryptAcquireContext - ");
	if (RCRYPT_FAILED(CryptAcquireContext(&hProv, NULL,
                          "CSP Provider", 900, 0)))
	{
        printf("CryptAcquireConext returned error %x\n", GetLastError());
        printf("FAILED\n");
		getchar();
		return(TRUE);
	}
	else
	    printf("SUCCEED\n");

    printf("Calling CryptGenKey - ");
	if (RCRYPT_FAILED(CryptGenKey(hProv,
					  CALG_GOST_SIGN,
				      0,
				      &hKey)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptDestroyKey - ");
	if (RCRYPT_FAILED(CryptDestroyKey(hKey)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

//
//	Create key for other calls to functions
//
    printf("Calling CryptGenKey - ");
	if ( !CryptGenKey(hProv,
					  CALG_GOST_SIGN,
				      0,
				      &hKey))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
	        printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptSetKeyParam - ");
	if (RCRYPT_FAILED(CryptSetKeyParam(hKey,
					   PARAMETER2,
					   (BYTE *) PARAMETER3,
					   PARAMETER4)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGetKeyParam - ");
	if (RCRYPT_FAILED(CryptGetKeyParam(hKey,
					   PARAMETER2,
					   (BYTE *) PARAMETER3,
					   (DWORD *) PARAMETER4,
					   PARAMETER5)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptSetProvParam - ");
	if (RCRYPT_FAILED(CryptSetProvParam(hProv,
					    PARAMETER2,
					    (BYTE *) PARAMETER3,
					    PARAMETER4)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGetProvParam - ");
	if (RCRYPT_FAILED(CryptGetProvParam(hProv,
					    PARAMETER2,
					    (BYTE *) PARAMETER3,
					    (DWORD *) PARAMETER4,
					    PARAMETER5)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }


    printf("Calling CryptGenRandom - ");
	BYTE bRandValue[50];
	for (unsigned i=0; i<50; i++)
		bRandValue[i] = 0;

	if (RCRYPT_FAILED(CryptGenRandom(hProv,
					 50,
					 bRandValue)))
	{

		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{

		printf("SUCCEED\n");
#ifdef _TEST_GENRANDOM
		std::cout << "Generated value:" << std::endl;
		for (unsigned i=0; i< 50; i++)
			std::cout << std::hex << (int)bRandValue[i];
		std::cout << std::endl;
#endif
    }

	// cheeck CPGenRandom for producing diffferent random numbers
    printf("Calling CryptGenRandom - ");
	//BYTE bRandValue[50];
	if (RCRYPT_FAILED(CryptGenRandom(hProv,
					 50,
					 bRandValue)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
#ifdef _TEST_GENRANDOM
		std::cout << "Generated value:" << std::endl;
		for (unsigned i=0; i< 50; i++)
			std::cout << std::hex << (int)bRandValue[i];
		std::cout << std::endl;
#endif
    }



    printf("Calling CryptGetUserKey - ");
    if (RCRYPT_FAILED(CryptGetUserKey(hProv,
				  AT_SIGNATURE,
				  &hPub)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGenKey - ");
	if (RCRYPT_FAILED(CryptGenKey(hProv,
				      (int) PARAMETER2,
				      PARAMETER3,
				      &hKey)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptExportKey - ");

	DWORD dwKeyBlobSize =0;//eof( BLOBHEADER ) + 256/8 + sizeof( DWORD );

	CryptExportKey(	hKey,
					NULL,
					PUBLICKEYBLOB,
					0,
					NULL,
					&dwKeyBlobSize);
	
	BYTE *pbKeyBlob = new BYTE[dwKeyBlobSize];

	if (RCRYPT_FAILED(CryptExportKey(hKey,
					 NULL,
					 PUBLICKEYBLOB,
					 0,
					 pbKeyBlob,
					 &dwKeyBlobSize)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptImportKey - ");
	if (RCRYPT_FAILED(CryptImportKey(hProv,
					 pbKeyBlob,
					 dwKeyBlobSize,
					 NULL,
					 0,
					 &hKey2)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

#ifdef _TEST_CREATEHASH
    printf("Calling CryptCreateHash - ");
	if (RCRYPT_FAILED(CryptCreateHash(hProv,
					  CALG_GOST_HASH,
					  0,
					  0,
					  &hHash)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }
	DestroyHash( hHash );
#endif

#ifdef _TEST_SETGETHASHPARAM

	if (!CryptCreateHash(hProv,
					  CALG_GOST_HASH,
					  0,
					  0,
					  &hHash))
	{
		printf ("CreateHash fault\n");
	}
	BYTE bHashVal[32+1] = "\x2D\xFB\xC1\xB3\x72\xD8\x9A\x11\x88\xC0\x9C\x52\xE0\xEE\xC6\x1F\xCE\x52\x03\x2A\xB1\x02\x2E\x8E\x67\xEC\xE6\x67\x2B\x04\x3E\xE5";
	std::cout << "Supplied hash value is: \n" <<  bHashVal << std::endl;


	printf("Calling CryptSetHashParam - ");
	if ( !CryptSetHashParam(
		hHash,
		HP_HASHVAL,
		bHashVal,
		0))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

    printf("Calling CryptGetHashParam - ");

		std::cout << "Getting hash size" << std::endl;

	DWORD dwHashSize;
	DWORD dwTemp = 4;
	if ( !CryptGetHashParam(hHash,
					    HP_HASHSIZE,
					    (BYTE *) &dwHashSize,
					    &dwTemp,
					    0))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{

		std::cout << "Hash size is " << dwHashSize << std::endl;

        printf("SUCCEED\n");
    }


		std::cout << "Getting hash value " << dwHashSize << std::endl;
		memset( bHashVal, 0, 32 );


	if ( !CryptGetHashParam(hHash,
					    HP_HASHVAL,
					    bHashVal,
					    &dwHashSize,
					    0))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
		std::cout << "\nHash value is: \n" << bHashVal << std::endl;
        printf("SUCCEED\n");
    }
	CryptDestroyHash( hHash );
#endif
#ifdef _TEST_HASH

	if (!CryptCreateHash(hProv,
		CALG_GOST_HASH,
		0,
		0,
		&hHash))

	{
		printf( "CryptCreateHash fault"); 
	}
	printf("Calling CryptHashData\n");
	DWORD dwHashSize =40;
	BYTE bHashVal[40+1] = "setyb 23=htgnel ,egassem si sihT12345678"; //This is message, length=32 bytes";
		//"\x2D\xFB\xC1\xB3\x72\xD8\x9A\x11\x88\xC0\x9C\x52\xE0\xEE\xC6\x1F\xCE\x52\x03\x2A\xB1\x02\x2E\x8E\x67\xEC\xE6\x67\x2B\x04\x3E\xE5";
	std::cout << "Supplied hash value is: \n" <<  bHashVal << std::endl;


	if ( !CryptHashData(hHash,
		bHashVal,
		dwHashSize,
		0))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			printf("Access violation\n");
		}
		else
		{
			printf("Test Failed\n");
		}
	}
	else
	{
		printf("SUCCEED\n");
		memset( bHashVal, 0, sizeof( bHashVal ) );
		if ( !CryptGetHashParam(hHash,
			HP_HASHVAL,
			bHashVal,
			&dwHashSize,
			0))
		{
			printf("CryptGetHashParam Failed\n");
		} else	{
			std::cout << "\nHash value is: \n" << bHashVal << std::endl;
			printf("SUCCEED\n");
		}
		CryptDestroyHash( hHash );

	}


#endif //_TEST_HASH


    printf("Calling CryptHashSessionKey - ");
	if (RCRYPT_FAILED(CryptHashSessionKey(hHash, hKey, PARAMETER3)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

#ifdef _TEST_CRYPT_DECRYPT
	DWORD dwCryptBlockLen = 0;
    printf("Calling CryptEncrypt - \n");
	std::cout << "Getting crypt block len" << std::endl;
	if ( !CryptEncrypt(hKey,
				       0,
				       FALSE,
				       0,
				       NULL,
				       &dwCryptBlockLen,
				       0))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
		std::cout << "Got crypt block len equal " <<  dwCryptBlockLen  << std::endl;
        printf("SUCCEED\n");
    }
	BYTE* pbCryptData = new BYTE[dwCryptBlockLen];
	std::cout << "Encrypting data, plain data is\n" << pbCryptData   << std::endl;
	if ( !CryptEncrypt(hKey,
				       0,
				       TRUE,
				       0,
				       pbCryptData,
				       &dwCryptBlockLen,
				       dwCryptBlockLen))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
		std::cout << "Got encrypted data\n" << pbCryptData << std::endl;
        printf("SUCCEED\n");
    }

    printf("Calling CryptDecrypt - \n");
	if (!CryptDecrypt(hKey,
				       0,
				       TRUE,
				       0,
				       pbCryptData,
				       &dwCryptBlockLen))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
		std::cout << "Decrypting data, decrypt data is\n" << pbCryptData   << std::endl;
		delete[] pbCryptData;
        printf("SUCCEED\n");
    }
#endif // _TEST_CRYPTDECRYPT


    printf("Calling CryptDeriveKey - ");
	if (RCRYPT_FAILED(CryptDeriveKey(hProv,
					 (int) PARAMETER2,
					 0,
					 0,
					 &hKey2)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }


    printf("Calling CryptDestroyHash - ");
	if (RCRYPT_FAILED(CryptDestroyHash(hHash)))
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
	    {
		    printf("Access violation\n");
        }
        else
        {
		    printf("Test Failed\n");
        }
	}
	else
	{
        printf("SUCCEED\n");
    }

	if (RCRYPT_FAILED(CryptReleaseContext(hProv, PARAMETER2)))
	{
        printf("CryptReleaseContext returned error %d\n", GetLastError());
        printf("FAILED\n");
	}
	else
	{
        printf("SUCCEED\n");
    }

	getchar();
	

	return true;
}
*/