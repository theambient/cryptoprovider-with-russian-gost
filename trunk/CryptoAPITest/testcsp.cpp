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
#include <iomanip>

#include <iostream>
#include "test-unit.h"

int main(int cArg, char *rgszArg[])
{
	bool bVerbose = cArg> 1;
	testAcquireContext(bVerbose);
	if ( testSignHash( bVerbose ) )
		std::cout << "CryptSignHash test SUCCEEDED" << std::endl;
	else
		std::cout << "CryptSignHash test FAULT" << std::endl;;
	if (testVerifyHash( bVerbose ))
		std::cout << "CryptVerifyHash test SUCCEEDED" << std::endl;
	else
		std::cout << "CryptVerifyHash test FAULT" << std::endl;

	if ( testHashData( true ) )
		std::cout << "CryptHashData test SUCCEEDED" << std::endl;
	else
		std::cout << "CryptHashData test FAULT" << std::endl;;	

	if ( testHashDataLong( true ) )
		std::cout << "CryptHashData long data test SUCCEEDED" << std::endl;
	else
		std::cout << "CryptHashData long data test FAULT" << std::endl;;	

	if ( testCrypt( 2 ) )
		std::cout << "CryptEncryptDecrypt test SUCCEEDED" << std::endl;
	else
		std::cout << "CryptEncryptDecrypt test FAULT" << std::endl;;	

	getchar();
	return(0);
}

