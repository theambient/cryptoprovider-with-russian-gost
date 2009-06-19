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
	testAcquireContext(true);
	testSignHash( true );
	testVerifyHash( true );
	getchar();
	return(0);
}

