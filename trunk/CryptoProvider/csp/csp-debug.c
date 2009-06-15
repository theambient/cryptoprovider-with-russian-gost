/** \file csp-debug.c
 * $Id: csp-debug.c,v 1.3 2004/12/03 15:39:24 rchantereau Exp $ 
 *
 * CSP #11 -- Cryptographic Service Provider PKCS #11.
 *
 * Copyright © 2004 Entr'ouvert
 * http://csp11.labs.libre-entreprise.org
 * 
 *  This file codes and documents all the necessary debug functions.
 * 
 * \author  Romain Chantereau <rchantereau@entrouvert.com>
 * \date    2004
 * \version  0.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "csp-debug.h"

static HANDLE debugFileHandle = INVALID_HANDLE_VALUE; /**< Handle to the debug
                                                           log file.*/
BOOL closeDebug()
{
    if(debugFileHandle == INVALID_HANDLE_VALUE)
    {
        return CloseHandle(debugFileHandle);
    }
    return FALSE;
}


BOOL    fdebug(const char *message)
{
    DWORD   bytesWritten;
    DWORD   dwPos; /* Position in the file.*/

    /** - If the log file handle is invalid,*/
    if(debugFileHandle == INVALID_HANDLE_VALUE)
    {
        /** - Try to get a valid file handle.*/
        debugFileHandle = CreateFile(TEXT(DEBUG_FILE),     /* The debug file.*/
                                     GENERIC_WRITE,  /* Open for writing.*/
                                     FILE_SHARE_READ,/* Allow multiple
                                                        readers.*/
                                     NULL,           /* No security.*/
                                     OPEN_ALWAYS,    /* If not exists, create.*/
                                     FILE_ATTRIBUTE_NORMAL, /* normal file.*/
                                     NULL);         /* No attribute template.*/
    }
    /** - If the log file handle is still invalid, error*/
    if(debugFileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    /** - Go to the end of the file.*/
    dwPos = SetFilePointer(debugFileHandle, 0, NULL, FILE_END);
    /** - Lock at the end of file, on length of message +1.*/
    if(!LockFile(debugFileHandle,dwPos,0, strlen(message),0))
    {
        return FALSE;
    }
    /** - Write the message to the file.*/
    if(!WriteFile(debugFileHandle, message, strlen(message), &bytesWritten, NULL))
    {
        UnlockFile(debugFileHandle, dwPos, 0, strlen(message),0);
        return FALSE;
    }
    /** - Unlock the file.*/
    return UnlockFile(debugFileHandle, dwPos, 0, strlen(message),0);
}

