/////////////////////////////////////////////////////////////////////////////
//  FILE          : param.c                                                //
//  DESCRIPTION   : Test to verify parameters of crypto API                //
//  USAGE         : Must have the provider defprov.dll and file "sign"     //
//                  which is the signature in the path.                    //
//                  Placing any charactor on the command line will create  //
//                  debug output from the program.                         //
//  AUTHOR        :                                                        //
//  HISTORY       :                                                        //
//      Dec 22 1994 larrys  New                                            //
//      Jan  5 1995 larrys  Added CryptGetLastError                        //
//      Mar  8 1995 larrys  Removed CryptGetLastError                      //
//      Mar 21 1995 larrys  Removed Certificate APIs                       //
//      Apr  7 1995 larrys  Update to new spec                             //
//                                                                         //
//  Copyright (C) 1993 Microsoft Corporation   All Rights Reserved         //
/////////////////////////////////////////////////////////////////////////////

#undef UNICODE					// ## Not Yet
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include <wincrypt.h>

#include <iostream>
#define UTILITY_BUF_SIZE	1000

// hash alg
const ALG_ID GOSTR341194 = 0x01;
// dss alg
const ALG_ID GOSTR34102001 = 0x02;
//enc alg
const ALG_ID GOST2814789 = 0x03;

#define PARAMETER1 10
#define PARAMETER2 GOSTR34102001
#define PARAMETER3 8
#define PARAMETER4 7
#define PARAMETER5 6
#define PARAMETER6 5
#define PARAMETER7 4
#define PARAMETER8 3
#define PARAMETER9 2
#define PARAMETER10 1

const char* MESSAGE = "This is message, length=32 bytes";
const int GOSTR34102001SigLen = 64;




int main(int cArg, char *rgszArg[])
{
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
	if (RCRYPT_FAILED(CryptAcquireContext(&hProv, pszMyName,
                          "CSP Provider", 900, cArg)))
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
					  (int) GOSTR34102001,
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
	if (RCRYPT_FAILED(CryptGenKey(hProv,
				      (int) GOSTR34102001,
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

	DWORD dwKeyBlobSize;

	CryptExportKey(	hKey,
					NULL,
					PUBLICKEYBLOB,
					0,
					NULL,
					&dwKeyBlobSize);
	
	if ( GetLastError() != ERROR_MORE_DATA )
		std::cout << "CryptExportKey - invalid last error" << std::endl;

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

    printf("Calling CryptCreateHash - ");
	if (RCRYPT_FAILED(CryptCreateHash(hProv,
					  GOSTR341194,
					  hKey,
					  PARAMETER4,
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

    printf("Calling CryptSetHashParam - ");
	if (RCRYPT_FAILED(CryptSetHashParam(hHash,
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

    printf("Calling CryptGetHashParam - ");
	if (RCRYPT_FAILED(CryptGetHashParam(hHash,
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

    printf("Calling CryptHashData - ");
	if (RCRYPT_FAILED(CryptHashData(hHash,
				        (BYTE *) MESSAGE,
					strlen(MESSAGE),
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

    printf("Calling CryptEncrypt - ");
	if (RCRYPT_FAILED(CryptEncrypt(hKey,
				       hHash,
				       (BOOL) PARAMETER3,
				       PARAMETER4,
				       (BYTE *) PARAMETER5,
				       (DWORD *) PARAMETER6,
				       PARAMETER7)))
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

    printf("Calling CryptDecrypt - ");
	if (RCRYPT_FAILED(CryptDecrypt(hKey,
				       hHash,
				       (BOOL) PARAMETER3,
				       PARAMETER4,
				       (BYTE *) PARAMETER5,
				       (DWORD *) PARAMETER6)))
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

    printf("Calling CryptDeriveKey - ");
	if (RCRYPT_FAILED(CryptDeriveKey(hProv,
					 (int) PARAMETER2,
					 hHash,
					 PARAMETER4,
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
	
	BYTE signature[GOSTR34102001SigLen];
    printf("Calling CryptSignHash - ");
	
	DWORD sigLen;

	if (RCRYPT_FAILED(CryptSignHash(hHash,
					AT_SIGNATURE,
					NULL,
					0,
					signature,
					&sigLen)))
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
#ifdef _TEST_SIGNHASH
        for (unsigned i=0; i<sigLen; i++)
			std::cout << std::hex << (int) signature[i];
		std::cout << std::endl;
#endif //_TEST_SIGNHASH
    }


	if (RCRYPT_FAILED(CryptSignHash(hHash,
					AT_SIGNATURE,
					NULL,
					0,
					signature,
					&sigLen)))
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
#ifdef _TEST_SIGNHASH
		printf("SUCCEED\n");
        for (unsigned i=0; i<sigLen; i++)
			std::cout << std::hex << (int) signature[i];
		std::cout << std::endl;
#endif //_TEST_SIGNHASH
    }

    printf("Calling CryptVerifySignature - ");
	if (RCRYPT_FAILED(CryptVerifySignature(hHash,
					       signature,
					       sigLen,
					       hPub,
					       NULL,
					       PARAMETER6)))
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
	return(0);
}

