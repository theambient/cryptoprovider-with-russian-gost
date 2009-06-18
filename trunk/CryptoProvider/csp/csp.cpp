/////////////////////////////////////////////////////////////////////////////
//  FILE          : csp.c                                                  //
//  DESCRIPTION   : Crypto API interface                                   //
//  AUTHOR        :                                                        //
//  HISTORY       :                                                        //
//                                                                         //
//  Copyright (C) 1993 Microsoft Corporation   All Rights Reserved         //
/////////////////////////////////////////////////////////////////////////////



#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#undef UNICODE                  // ## Not Yet
#include <windows.h>
#include <wincrypt.h>
#include <cspdk.h>
#include <stdexcept>
#include <iostream>

#include "csp/csp-services.h"
#include "csp/csp.h"
#include "csp/csp-debug.h"
#include "ui.h"


/*	\brief supported algorithms database
 *	
 *	\ingroup SPInternal
 *
 */
PROV_ENUMALGS_EX algorithms[] = {
	{CALG_GOST_SIGN, GOST_SIGN_BITS, GOST_SIGN_MIN_BITS, GOST_SIGN_MAX_BITS, 0, (DWORD)strlen(GOST_SIGN_NAME), GOST_SIGN_NAME, (DWORD) strlen(GOST_SIGN_NAME), GOST_SIGN_NAME },
	{CALG_GOST_KEYX, GOST_KEYX_BITS, GOST_KEYX_MIN_BITS, GOST_KEYX_MAX_BITS, 0, (DWORD)strlen(GOST_KEYX_NAME), GOST_KEYX_NAME, (DWORD) strlen(GOST_KEYX_NAME), GOST_KEYX_NAME },	
	{CALG_GOST_CRYPT, GOST_CRYPT_BITS, GOST_CRYPT_MIN_BITS, GOST_CRYPT_MAX_BITS, 0, (DWORD)strlen(GOST_CRYPT_NAME), GOST_CRYPT_NAME, (DWORD) strlen(GOST_CRYPT_NAME), GOST_CRYPT_NAME },	
	{CALG_GOST_HASH, GOST_HASH_BITS, GOST_HASH_MIN_BITS, GOST_HASH_MAX_BITS, 0, (DWORD)strlen(GOST_HASH_NAME), GOST_HASH_NAME, (DWORD) strlen(GOST_HASH_NAME), GOST_HASH_NAME }
}; /**< Supported algorithms database.*/

extern const unsigned algorithms_count = sizeof(algorithms);

HINSTANCE g_hModule = NULL; /**< DLL Instance. */

/** \brief Microsoft® Windows® DLL main function.
 *
 *  This function is called when the DLL is attached, detached from a program.
 *  
 *  \param  hinstDLL    Handle to the DLL module.
 *  \param  fdwReason   Reason value of the DLL call.
 *  \param  lpvReserved RFU.
 *
 *  \return TRUE is everything is ok.
 *  
 */
BOOL WINAPI
DllMain(
  HINSTANCE hinstDLL,  // handle to the DLL module
  DWORD fdwReason,     // reason for calling function
  LPVOID lpvReserved)  // reserved
{
    switch( fdwReason ) 
    { 
    
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            g_hModule = hinstDLL;
            

            DEBUG(1, "Library attached\n");
            DEBUG(1, "++++++++++++++++++++++++++++++++++++++++++++++++\n");
            return TRUE;
            break;

        case DLL_PROCESS_DETACH:
            DEBUG(1, "Library detached\n");
            DEBUG(1, "------------------------------------------------\n");
            closeDebug();
            return TRUE;
            break;
    }
    return TRUE;
}


/*
 -  CPAcquireContext
 -
 *  Purpose:
 *               The CPAcquireContext function is used to acquire a context
 *               handle to a cryptographic service provider (CSP).
 *
 *
 *  Parameters:
 *               OUT phProv         -  Handle to a CSP
 *               IN  szContainer    -  Pointer to a string which is the
 *                                     identity of the logged on user
 *               IN  dwFlags        -  Flags values
 *               IN  pVTable        -  Pointer to table of function pointers
 *
 *  Returns:
 */

BOOL WINAPI
CPAcquireContext(
    OUT HCRYPTPROV *phProv,
    IN  LPCSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStruc pVTable)
{
	PROV_CTX *pProvCtx = NULL;
	CONTAINER_INFO *pContainer = NULL;
	char debug[255];

	HWND FuncReturnedhWnd = 0;

	DEBUG(1,"_-_-_-_-_-_-_-_-Acquiiring Context-_-_-_-_-_-_-_-_-\n");
    /** - Test if dwFlags are correct */
    if (dwFlags & ~(CRYPT_SILENT|CRYPT_VERIFYCONTEXT|CRYPT_NEWKEYSET|CRYPT_MACHINE_KEYSET|CRYPT_DELETEKEYSET)){
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
	/** - CSP currently do not suport containers name.*/
	/** - it uses default container.*/
	/*
	if ( szContainer != NULL ){
		SetLastError( NTE_BAD_KEYSET_PARAM );
		return FALSE;
	}*/
	/** - Process flags. Some flags do not supprted. */
	if ( dwFlags & CRYPT_VERIFYCONTEXT && szContainer != NULL){
		SetLastError( NTE_BAD_KEYSET_PARAM );
		return FALSE;
	}

	if ( dwFlags & CRYPT_MACHINE_KEYSET ) {
		SetLastError( NTE_BAD_FLAGS );
		return FALSE;
	}

	// If CRYPT_VERIFYCONTEXT is set all others flags should be unset.
	if ( dwFlags & CRYPT_VERIFYCONTEXT && dwFlags &~(CRYPT_VERIFYCONTEXT) ){
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
	}
	try {
		// Create provider context.
		pProvCtx = new PROV_CTX;
		pContainer = new CONTAINER_INFO;

		// Fill the provider context.
		pProvCtx->bSilent = dwFlags & CRYPT_SILENT;;
		pProvCtx->pContainer = pContainer;
		
		// Fill the container.
		pContainer->cName = NULL;
		pContainer->dwFlags = dwFlags;
		pContainer->hServiceInformation = NULL;

		// Set CSP Instance, user interface windows in proper
		if(pVTable->FuncReturnhWnd != NULL) {
			pVTable->FuncReturnhWnd(&FuncReturnedhWnd);
			sprintf(debug, "Window handle was provided: %x, ", (unsigned int) FuncReturnedhWnd);
			DEBUG(4, debug);
			if(IsWindow((HWND) FuncReturnedhWnd)) {
				pProvCtx->uiHandle = (HWND) FuncReturnedhWnd;
				DEBUG(4, "valid.\n");
			}
			else {
				pProvCtx->uiHandle = 0;
				DEBUG(4, "invalid.\n");
			}
		}
		/** - Transmit the csp instance handle to service.*/
		setCSPInstance(g_hModule);

		phProv = ( HCRYPTPROV* ) pProvCtx;
		// if CRYPT_VERIFYCONTEXT is set container shouldn't be open.
		if ( !(dwFlags & CRYPT_VERIFYCONTEXT) ){
			DEBUG( 3, "Openning container.\n" );
			// Try to open a container
			if ( !OpenContainer(pProvCtx, szContainer) ){
				// \todo OpenContainer SHOULD set last error.
				CPReleaseContext( *phProv, 0 );
				return FALSE;
			}
			DEBUG( 3, "Container has been opened.\n" );
			// if CREATE_NEWKEYSET flag is set.
			if ( dwFlags & CRYPT_NEWKEYSET ){
				DEBUG( 4, "Creating new keyset.\n" );

				HCRYPTKEY hKey = NULL;
				// Check firstly for a existing keyset.
				if ( CPGetUserKey( *phProv, AT_SIGNATURE, &hKey ) ){
					// if found - release resources and exit with error.
					CPDestroyKey( *phProv, hKey );
					CPReleaseContext( *phProv, 0 );
						SetLastError( NTE_EXISTS );
					return FALSE;
				}
				else {
					// define flags for the creating key
					DWORD dwGenKeyFlags;
					if ( !(dwFlags & CRYPT_SILENT) )
						dwGenKeyFlags = CRYPT_USER_PROTECTED;

					// create a key in proper
					if ( CPGenKey( *phProv, AT_SIGNATURE, dwGenKeyFlags, &hKey ) ){
						if ( !CPDestroyKey( *phProv, hKey ) ){
							CPReleaseContext( *phProv, 0 );
							return FALSE;
						}
					}
					else {
						// if failed to create - exit with error
						CPReleaseContext( *phProv, 0 );
						SetLastError( NTE_BAD_KEYSET );
						return FALSE;
					}
				}
				DEBUG( 4, "New keyset created.\n" );
			}
		} // if CRYPT_VERIFYCONTEXT.
		DEBUG(1,"-----------------Context acquired-----------------\n");
		return TRUE;
	}
	catch( std::bad_alloc ){
		// Release resources.
		CPReleaseContext( HCRYPTPROV(pProvCtx), 0 );
		//exit
		SetLastError( NTE_NO_MEMORY );
		return FALSE;
	}
}


/*
 -      CPReleaseContext
 -
 *      Purpose:
 *               The CPReleaseContext function is used to release a
 *               context created by CryptAcquireContext.
 *
 *      Parameters:
 *               IN  phProv        -  Handle to a CSP
 *               IN  dwFlags       -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPReleaseContext(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	CONTAINER_INFO *pContainer = pProvCtx->pContainer;

	DEBUG(1,"_-_-_-_-_-_-_-_-_Releasing Context-_-_-_-_-_-_-_-_-\n");

	// nothing currently to release in provider context 
	// except container context
	if ( !releaseContainer(pProvCtx) ){
		return FALSE;
	}
	// Check flags. They SHOULD be zero.
	if ( dwFlags != 0){
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
	}
	DEBUG(1,"-----------------Context released-----------------\n");
	return TRUE;
}


/*
 -  CPGenKey
 -
 *  Purpose:
 *                Generate cryptographic keys
 *
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      Algid   -  Algorithm identifier
 *               IN      dwFlags -  Flags values
 *               OUT     phKey   -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPGenKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	CONTAINER_INFO *pContainer = pProvCtx->pContainer;
	KEY_INFO *pKey = NULL;

	DEBUG(1,"_-_-_-_-_-_-_-_-_Generating keys-_-_-_-_-_-_-_-_-\n");
	
	// if key size has been defined in flags
	// assume it as a error.
	if ( dwFlags >> 16 ){
		SetLastError(NTE_BAD_FLAGS);
		return FALSE;
	}
	if ( pContainer->dwFlags & CRYPT_VERIFYCONTEXT ){
		SetLastError( NTE_FAIL );
	}
	try {
		// Create the key context.
		pKey = new KEY_INFO;

		// Fill in the key context.
		pKey->algId = 0;
		pKey->blockLen = 0;
		pKey->dwKeySpec = 0;
		pKey->iv = NULL;
		pKey->ivLen = 0;
		pKey->length = 0;
		pKey->salt = NULL;
		pKey->saltLen = 0;
		pKey->mode = 0;
		switch ( Algid ) {
			case CALG_GOST_SIGN:
			case AT_SIGNATURE:
				// Fill in key context.
				pKey->algId = CALG_GOST_SIGN;
				pKey->dwKeySpec = AT_SIGNATURE;
				pKey->length = getKeyLen( Algid );
				pKey->exportable = dwFlags & CRYPT_EXPORTABLE;

				// Generate key pair.
				if (!genKeyPair( pProvCtx, pKey ) ){
					CPDestroyKey( hProv, HCRYPTKEY(pKey) );
					return FALSE;
				}
				break;
			case AT_KEYEXCHANGE:
			case CALG_GOST_CRYPT:
			case CALG_GOST_KEYX:
			default:
				// this algs currently not supported
				SetLastError( NTE_BAD_ALGID );
				return FALSE;
		}
	}
	catch ( std::bad_alloc &e ){
		// log error
		std::cerr << e.what() << std::endl;
		// release resources
		delete pKey;
		SetLastError( NTE_NO_MEMORY );
		return FALSE;
	}
				
	DEBUG(1,"---------------Key has been generated---------------\n");
    return TRUE;
}


/*
 -  CPDeriveKey
 -
 *  Purpose:
 *                Derive cryptographic keys from base data
 *
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      Algid      -  Algorithm identifier
 *               IN      hBaseData -   Handle to base data
 *               IN      dwFlags    -  Flags values
 *               OUT     phKey      -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPDeriveKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	SetLastError(NTE_BAD_ALGID);
    return FALSE;
}


/*
 -  CPDestroyKey
 -
 *  Purpose:
 *                Destroys the cryptographic key that is being referenced
 *                with the hKey parameter
 *
 *
 *  Parameters:
 *               IN      hProv  -  Handle to a CSP
 *               IN      hKey   -  Handle to a key
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey)
{
	DEBUG(1,"_-_-_-_-_-_-_-_-_Destroying keys-_-_-_-_-_-_-_-_-\n");
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	KEY_INFO *pKey = (KEY_INFO*) hKey;
	releaseKey( pProvCtx, pKey );
	delete pKey;
	DEBUG(1,"---------------Key has been destroyed---------------\n");
    return TRUE;

}


/*
 -  CPSetKeyParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hKey    -  Handle to a key
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	KEY_INFO *pKey = (KEY_INFO*) hKey;

	DEBUG(1,"_-_-_-_-_-_-_-_-_Setting key params-_-_-_-_-_-_-_-_-\n");
	// \todo Implement this function
	// \bug  Nothing to implement due to no 
	//	simmetric algs.
	DEBUG(1,"---------------Key params have been set---------------\n");
    return TRUE;
}


/*
 -  CPGetKeyParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hKey       -  Handle to a key
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
	DEBUG(1,"_-_-_-_-_-_-_-_-_Getting key params-_-_-_-_-_-_-_-_-\n");
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	KEY_INFO *pKey = (KEY_INFO*) hKey;

	if ( dwFlags ){
		SetLastError( NTE_BAD_FLAGS );
		return FALSE;
	}
	
	// If pbData = NULL that should be a first call
	// return required buffer length
	if ( pbData == NULL ){
		switch ( dwParam ){
			case KP_PERMISSIONS:
			case KP_KEYLEN:
			case KP_ALGID:
				*pcbDataLen = sizeof(DWORD);
				break;
			default:
				SetLastError ( NTE_BAD_TYPE );
				return FALSE;	
		}
	} else {
		// It's second call. copy parameter to buffer
		switch ( dwParam ){
			case KP_PERMISSIONS:
				// Test if data length is length enough.*/
				if ( *pcbDataLen<sizeof(DWORD) ){
					SetLastError( ERROR_MORE_DATA );
					return FALSE;
				}
				// Fill with permissions.
				*LPDWORD(pbData) = pKey->permissions;
				break;
			case KP_KEYLEN:
				// Test if data length is length enough.*/
				if ( *pcbDataLen<sizeof(DWORD) ){
					SetLastError( ERROR_MORE_DATA );
					return FALSE;
				}
				// Fill with length.
				*LPDWORD(pbData) = pKey->length ;
				break;
            case KP_ALGID:
                // Test if data length is length enough.*/
                if(*pcbDataLen < sizeof(DWORD))
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                // Fill with ALG_ID.
                *LPDWORD(pbData) = pKey->algId;
                break;
			case KP_BLOCKLEN:
				// Test if data length is length enough.*/
				if(*pcbDataLen < (sizeof(DWORD))) {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
				// Switch algs. Not all algs support encryption. 
				switch ( pKey->algId ){
					case CALG_GOST_SIGN:
					case CALG_GOST_KEYX:
						SetLastError( NTE_BAD_TYPE );
						return FALSE;
						break;
					case CALG_GOST_CRYPT:
						*pbData = 64;
						break;
					default:
						SetLastError( NTE_BAD_TYPE );
						return FALSE;
				}
                break;
			default:
				SetLastError ( NTE_BAD_TYPE );
				return FALSE;	
		}
	}
	DEBUG(1,"---------------Key params have been got---------------\n");
    return TRUE;
}


/*
 -  CPSetProvParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPGetProvParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN OUT  pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;

	DEBUG(1,"_-_-_-_-_-_-_-_-_Getting provider params-_-_-_-_-_-_-_-_-\n");
    if(dwFlags && (dwFlags & ~(CRYPT_FIRST))) {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
	// Define appropriate buffer length
	DWORD dwLen = 0; //< local copy of buffer length
	switch ( dwParam ) {
		case PP_ENUMALGS:
			dwLen = sizeof( PROV_ENUMALGS );
			break;
		case PP_ENUMALGS_EX:
			dwLen = sizeof( PROV_ENUMALGS_EX );
			break;
		case PP_CONTAINER:
			if ( pProvCtx->pContainer->cName != NULL )
				dwLen = (DWORD) strlen(pProvCtx->pContainer->cName) + 1;
			else
				dwLen = 0;
			break;
		case PP_IMPTYPE:
		case PP_VERSION:
		case PP_PROVTYPE:
		case PP_KEYSPEC:
			dwLen = sizeof( DWORD );
			break;
		case PP_NAME:
			dwLen = (DWORD) strlen( CSP_NAME ) + 1;
			break;

		case PP_USE_HARDWARE_RNG:
			dwLen = sizeof( BOOL );
			break;
		default:
			SetLastError( NTE_BAD_TYPE );
			return FALSE;
	}
	if ( pbData == NULL ){
		// That should be the first call.
		// Return length of buffer.
		*pcbDataLen = dwLen;
	} else {
		// Test if data buffer is length enough.
		if ( *pcbDataLen < dwLen ) {
			SetLastError( ERROR_MORE_DATA );
			return FALSE;			
		}

		// Fill in pcbDataLength
		*pcbDataLen = dwLen;
		switch ( dwParam ) {
			case PP_ENUMALGS: {
				// Test if for actual first call and 
				// CRYPT_FIRST flag correspondance
				static bool bFirstCall = true;
				if ( bFirstCall && !(dwFlags & CRYPT_FIRST) ){
					SetLastError( NTE_BAD_TYPE );
					return FALSE;
				} else {
					bFirstCall = false;
				}

				static unsigned index; //< enumerating index
				if ( dwFlags & CRYPT_FIRST ){
					index = 0;
				} else if (index >= sizeof(algorithms)){
						SetLastError( NTE_NO_MORE_ITEMS );
						return FALSE;
				}
				PROV_ENUMALGS_EX *pAlgEx = &algorithms[index];
				PROV_ENUMALGS *algInfo = (PROV_ENUMALGS*) pbData;
				algInfo->aiAlgid = pAlgEx->aiAlgid;
				algInfo->dwBitLen = pAlgEx->dwDefaultLen;
				algInfo->dwNameLen = pAlgEx->dwNameLen;
				strncpy( algInfo->szName, pAlgEx->szName, 20 );
				index++;
				break;
							  }
			case PP_ENUMALGS_EX: {
				// Test if for actual first call and 
				// CRYPT_FIRST flag correspondance

				static bool bFirstCall = true;
				if ( bFirstCall && !(dwFlags & CRYPT_FIRST) ){
					SetLastError( NTE_BAD_TYPE );
					return FALSE;
				} else {
					bFirstCall = false;
				}

				static unsigned index; //< enumerating index
				if ( dwFlags & CRYPT_FIRST ){
					index = 0;
				} else if (index >= sizeof(algorithms)){
						SetLastError( NTE_NO_MORE_ITEMS );
						return FALSE;
				}
				memcpy( pbData, &algorithms[index], sizeof( PROV_ENUMALGS_EX ) );
				index++;
				break;
								 }
			case PP_CONTAINER:
				if ( pProvCtx->pContainer->cName != NULL )
					strcpy( (LPSTR)pbData, pProvCtx->pContainer->cName );
				break;
			case PP_IMPTYPE:
				*pbData = CRYPT_IMPL_SOFTWARE;
				break;
			case PP_NAME:
				memcpy( pbData, CSP_NAME, strlen(CSP_NAME)+1 );
				break;
			case PP_VERSION:
				*LPDWORD( pbData ) = CSP_VERSION;
				break;
			case PP_PROVTYPE:
				*LPDWORD( pbData ) = CSP_PROVTYPE;
				break;
			case PP_KEYSPEC:
				*LPDWORD( pbData ) = ( AT_SIGNATURE | AT_KEYEXCHANGE );
				break;
			case PP_USE_HARDWARE_RNG:
				*pbData = FALSE;
				break;
			default:
				*pcbDataLen = 0;
				SetLastError( NTE_BAD_TYPE );
				return FALSE;
		}
	}
	DEBUG(1,"---------------Provider params have been got---------------\n");
    return TRUE;
}


/*
 -  CPSetHashParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hHash   -  Handle to a hash
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
    PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	HASH_INFO *pHash = (HASH_INFO*) hHash;
	DEBUG(1,"_-_-_-_-_-_-_-_-_Setting hash params-_-_-_-_-_-_-_-_-\n");
	if ( dwFlags ){
		SetLastError( NTE_BAD_FLAGS );
		return FALSE;
	}

	switch ( dwParam ){
		case HP_HASHVAL:
			// import external hashvalue into hash container.
			// assume that algorithm correctnes has ben checked by caller.
			if ( !setHash( pProvCtx, pHash, pbData ) ){
				// Last error is set by setHash(...)
				return FALSE;
			}
			break;
		default:
			SetLastError( NTE_BAD_TYPE );
			return FALSE;
	}

	DEBUG(1,"---------------Hash params have been set---------------\n");
	return TRUE;
}


/*
 -  CPGetHashParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hHash      -  Handle to a hash
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
    PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	HASH_INFO *pHash = (HASH_INFO*) hHash;
	DEBUG(1,"_-_-_-_-_-_-_-_-_Getting hash params-_-_-_-_-_-_-_-_-\n");
	if ( dwFlags ){
		SetLastError( NTE_BAD_FLAGS );
		return FALSE;
	}
	DWORD dwLen; //< local copy of the appropriate buffer length
	switch ( dwParam ){
		case HP_HASHVAL:
			dwLen = pHash->dwHashLen;
			break;
		case HP_ALGID:
			dwLen = sizeof( DWORD );
			break;
		case HP_HASHSIZE:
			dwLen = sizeof( DWORD );
			break;
		default:
			SetLastError( NTE_BAD_TYPE );
			return FALSE;
	}

	if ( pbData == NULL ) {
		*pcbDataLen = dwLen;
	} else {
		// Test if data buffer is length enough.
		if ( *pcbDataLen < dwLen ){
			SetLastError( ERROR_MORE_DATA );
			return FALSE;
		}
		switch ( dwParam ){
			case HP_HASHVAL:
				// export hashvalue into buffer.
				if ( !getHash( pProvCtx, pHash, pbData, pcbDataLen ) ){
					// Last error is set by getHash(...)
					return FALSE;
				}
				break;
			case HP_ALGID:
				*LPDWORD( pbData ) = pHash->algid;
				break;
			case HP_HASHSIZE:
				*LPDWORD( pbData ) = pHash->dwHashLen;
				break;
			default:
				SetLastError( NTE_BAD_TYPE );
				return FALSE;
		}
	}
	DEBUG(1,"---------------Hash params have been got---------------\n");
	return TRUE;
}


/*
 -  CPExportKey
 -
 *  Purpose:
 *                Export cryptographic keys out of a CSP in a secure manner
 *
 *
 *  Parameters:
 *               IN  hProv         - Handle to the CSP user
 *               IN  hKey          - Handle to the key to export
 *               IN  hPubKey       - Handle to exchange public key value of
 *                                   the destination user
 *               IN  dwBlobType    - Type of key blob to be exported
 *               IN  dwFlags       - Flags values
 *               OUT pbData        -     Key blob data
 *               IN OUT pdwDataLen - Length of key blob in bytes
 *
 *  Returns:
 */

BOOL WINAPI
CPExportKey(
			IN  HCRYPTPROV hProv,
			IN  HCRYPTKEY hKey,
			IN  HCRYPTKEY hPubKey,
			IN  DWORD dwBlobType,
			IN  DWORD dwFlags,
			OUT LPBYTE pbData,
			IN OUT LPDWORD pcbDataLen)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	KEY_INFO *pKey = (KEY_INFO*) hKey;
	KEY_INFO *pPubKey = (KEY_INFO*) hPubKey;
	BLOBHEADER *pBlobHeader = (BLOBHEADER*) pbData;
	DWORD dwBlobLen; //< local copy of actual blob len

	DEBUG(1,"_-_-_-_-_-_-_-_-_Exporting key-_-_-_-_-_-_-_-_-\n");
	switch ( dwBlobType ){
		case PUBLICKEYBLOB:
			if(hPubKey != 0) {
				SetLastError(NTE_BAD_PUBLIC_KEY);
				return FALSE;
			}
			// get the public key length
			if ( !getPubKeyLen( pProvCtx, pKey, &dwBlobLen ) ){
				// Last error is set by getPubKey
				*pcbDataLen = 0;
				return FALSE;
			}
			dwBlobLen += sizeof(BLOBHEADER);
		default:
			SetLastError(NTE_BAD_TYPE);
			*pcbDataLen = 0;
			return FALSE;
	}

	// If it's first call.
	if ( pbData == NULL ){
		*pcbDataLen = dwBlobLen;
	} else {// That should be the second call.
		// Test buffer is length enough.
		if ( *pcbDataLen < dwBlobLen ){
			SetLastError( ERROR_MORE_DATA );
			return FALSE;
		}
		switch ( dwBlobType ){
			case PUBLICKEYBLOB:{

				// Fill in blob header.
				pBlobHeader->aiKeyAlg = pKey->algId;
				pBlobHeader->bType = PUBLICKEYBLOB;
				pBlobHeader->bVersion = CUR_BLOB_VERSION;
				pBlobHeader->reserved = 0;

				// Export key in proper.
				BYTE* pbKeyData = pbData + sizeof( BLOBHEADER );
				DWORD dwPubKeyBlobWithoutHeaderLen = dwBlobLen - sizeof(BLOBHEADER);
				if ( !exportPubKey( pProvCtx, pKey, pbKeyData, &dwPubKeyBlobWithoutHeaderLen ) ){
					// Last error is set by exportPubKey
					return FALSE;
				}
				// Now public key blob is ready.
				break;
							   }
			default:
				SetLastError( NTE_BAD_TYPE );
				return FALSE;
		}
	}

	DEBUG(1,"---------------Key has been exported---------------\n");
	return TRUE;

}


/*
 -  CPImportKey
 -
 *  Purpose:
 *                Import cryptographic keys
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the CSP user
 *               IN  pbData    -  Key blob data
 *               IN  dwDataLen -  Length of the key blob data
 *               IN  hPubKey   -  Handle to the exchange public key value of
 *                                the destination user
 *               IN  dwFlags   -  Flags values
 *               OUT phKey     -  Pointer to the handle to the key which was
 *                                Imported
 *
 *  Returns:
 */

BOOL WINAPI
CPImportKey(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	KEY_INFO *pPubKey = (KEY_INFO*) hPubKey;
	KEY_INFO *pImpKey = NULL;
	try {
		pImpKey = new KEY_INFO;
	}
	catch ( std::bad_alloc ){
		SetLastError( NTE_NO_MEMORY );
		return FALSE;
	}
	BLOBHEADER *pBlobHeader = (BLOBHEADER*) pbData;

	DEBUG(1,"_-_-_-_-_-_-_-_-_Importing key-_-_-_-_-_-_-_-_-\n");

	// Test if blob data is length enough
	if ( cbDataLen < sizeof( BLOBHEADER ) ){
		SetLastError( NTE_BAD_DATA );
		delete pImpKey;
		return FALSE;
	}

	BYTE* pbImpKeyData = LPBYTE(pBlobHeader) + sizeof( BLOBHEADER ); 
		//<imported key data without blob header
	DWORD dwImpKeyDataLen = cbDataLen - sizeof( BLOBHEADER ); 
		//< imported key data length without blob header

	// Initially fill key context.
	pImpKey->algId = pBlobHeader->aiKeyAlg;
	pImpKey->blockLen = 0;
	pImpKey->dwKeySpec = 0;
	pImpKey->exportable = dwFlags & CRYPT_EXPORTABLE;
	pImpKey->fLen = 0;
	pImpKey->hKeyInformation = NULL;
	pImpKey->iv = NULL;
	pImpKey->ivLen = 0;
	pImpKey->length = 0;
	pImpKey->mode = 0;
	pImpKey->oid = NULL;
	pImpKey->padding = 0;
	pImpKey->permissions = 0;
	pImpKey->salt = NULL;
	pImpKey->saltLen = 0;

	switch ( pBlobHeader->bType ){
		case PUBLICKEYBLOB:
			if ( hPubKey !=0 ){
				SetLastError( NTE_INVALID_PARAMETER );
				delete pImpKey;
				return FALSE;
			}
			// Proccess blob depending on blob's key alg.
			switch ( pBlobHeader->aiKeyAlg ){
				case CALG_GOST_SIGN :
					if ( !importPubKey( pProvCtx, pImpKey, pbImpKeyData,  dwImpKeyDataLen ) ){
						// last error is set by importPubKey
						delete pImpKey;
						return FALSE;
					}
					// now key is imported
					break;
				default: 
					SetLastError( NTE_BAD_DATA );
					delete pImpKey;
					return FALSE;
			}
		default:
			SetLastError( NTE_BAD_TYPE );
			delete pImpKey;
			return FALSE;
	}
	DEBUG(1,"---------------Key has been imported---------------\n");
	return TRUE;
}


/*
 -  CPEncrypt
 -
 *  Purpose:
 *                Encrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of plaintext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be encrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    encrypted
 *               IN dwBufLen       -  Size of Data buffer
 *
 *  Returns:
 */

BOOL WINAPI
CPEncrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD cbBufLen)
{
	DEBUG(1,"_-_-_-_-_-_-_-_-_Encrypting data-_-_-_-_-_-_-_-_-\n");
    *pcbDataLen = 0;
	DEBUG(1,"---------------Data has been encrypted---------------\n");
    return TRUE;
}


/*
 -  CPDecrypt
 -
 *  Purpose:
 *                Decrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of ciphertext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be decrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    decrypted
 *
 *  Returns:
 */

BOOL WINAPI
CPDecrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
	DEBUG(1,"_-_-_-_-_-_-_-_-_Encrypting data-_-_-_-_-_-_-_-_-\n");
    *pcbDataLen = 0;
	DEBUG(1,"---------------Data has been encrypted---------------\n");
    return TRUE;
}


/*
 -  CPCreateHash
 -
 *  Purpose:
 *                initate the hashing of a stream of data
 *
 *
 *  Parameters:
 *               IN  hUID    -  Handle to the user identifcation
 *               IN  Algid   -  Algorithm identifier of the hash algorithm
 *                              to be used
 *               IN  hKey   -   Optional handle to a key
 *               IN  dwFlags -  Flags values
 *               OUT pHash   -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPCreateHash(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	HASH_INFO *pHash = NULL;
	DEBUG(1,"_-_-_-_-_-_-_-_-_Creating hash context-_-_-_-_-_-_-_-_-\n");
	
	if ( dwFlags ){
		SetLastError( NTE_BAD_FLAGS );
		return FALSE;
	}

	try {
		pHash = new HASH_INFO;
	}
	catch (std::bad_alloc ){
		SetLastError( NTE_NO_MEMORY );
		return FALSE;
	}
	switch (Algid){
		case CALG_GOST_HASH:
			if ( hKey != 0 ){
				SetLastError( NTE_INVALID_PARAMETER );
				delete pHash;
				return FALSE;
			}

			pHash->algid = Algid;
			pHash->dwHashLen = GOST_HASH_BITS;
			if ( !createHash( pProvCtx, pHash ) ){
				// last error is set by createHash()
				delete pHash;
				return FALSE;
			}
			// hash created
			break;
		default:
			SetLastError( NTE_BAD_ALGID );
			delete pHash;
			return FALSE;
	}
	*phHash = (HCRYPTHASH) pHash;
	DEBUG(1,"-------------Hash context has been created-------------\n");
    return TRUE;
}


/*
 -  CPHashData
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a stream of data
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  pbData    -  Pointer to data to be hashed
 *               IN  dwDataLen -  Length of the data to be hashed
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPHashData(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	HASH_INFO *pHash = (HASH_INFO*) hHash;
	DEBUG(1,"_-_-_-_-_-_-_-_-_Hashing data-_-_-_-_-_-_-_-_-\n");
	if ( dwFlags & CRYPT_USERDATA ){
		// \todo Procceed CRYPT_USERDATA
	}
	if ( cbDataLen == 0 ){
		SetLastError( NTE_INVALID_PARAMETER );
		return FALSE;
	}
	if ( pbData == NULL ){
		SetLastError( NTE_INVALID_PARAMETER );
		return FALSE;
	}
	if ( !updateHash( pProvCtx, pHash, pbData, cbDataLen ) ){
		// Last error is set by updateHash(...)
		return FALSE;
	}
	DEBUG(1,"---------------Data has been hashed---------------\n");
    return TRUE;
}


/*
 -  CPHashSessionKey
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a key object.
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  hKey      -  Handle to a key object
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 *               CRYPT_FAILED
 *               CRYPT_SUCCEED
 */

BOOL WINAPI
CPHashSessionKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPSignHash
 -
 *  Purpose:
 *                Create a digital signature from a hash
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  dwKeySpec    -  Key pair to that is used to sign with
 *               IN  sDescription -  Description of data to be signed
 *               IN  dwFlags      -  Flags values
 *               OUT pbSignature  -  Pointer to signature data
 *               IN OUT dwHashLen -  Pointer to the len of the signature data
 *
 *  Returns:
 */

BOOL WINAPI
CPSignHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen)
{
	PROV_CTX *pProvCtx = (PROV_CTX*)hProv;
	KEY_INFO *pPrKey = NULL;
	DEBUG(1,"_-_-_-_-_-_-_-_-_Signing data-_-_-_-_-_-_-_-_-\n");
	// The only flag CRYPT_NOHASHOID is not supported 
	//		due to appliable only to RSA.
	if ( dwFlags ){
		SetLastError( NTE_BAD_FLAGS );
		return FALSE;
	}
	if ( dwKeySpec & AT_KEYEXCHANGE ){
		SetLastError( NTE_NO_KEY );
		return FALSE;
	}
	// szDescription is not supported
	if ( szDescription != NULL ){
		SetLastError( NTE_INVALID_PARAMETER );
		return FALSE;
	}
	// If first call
	if ( pbSignature == NULL ){
		*pcbSigLen = GOST_SIGN_BITS;
		return TRUE;
	} else {
		if ( *pcbSigLen < GOST_SIGN_BITS ){
			SetLastError( ERROR_MORE_DATA );
			return FALSE;
		}
		DWORD dwHashSize;
		DWORD dwHashSizeLen = sizeof(DWORD);
		// Get the hash size.
		if ( !CPGetHashParam( hProv, hHash, HP_HASHSIZE, LPBYTE(&dwHashSize), &dwHashSizeLen, 0 ) ){
			// Last Error is set by CPGetHashParam()
			return FALSE;
		}
		// Allocate buffer for hash.
		BYTE* pbHashValue = NULL;
		try {
			pbHashValue = new BYTE[dwHashSize];
		}
		catch (std::bad_alloc ){
			SetLastError( NTE_NO_MEMORY );
			return FALSE;
		}

		// Get the hash in propper.
		if ( !CPGetHashParam( hProv, hHash, HP_HASHVAL, pbHashValue, &dwHashSize, 0 ) ){
			// Last Error is set by CPGetHashParam().
			delete[] pbHashValue;
			return FALSE;
		}

		// Get the user key.
		HCRYPTKEY hUserKey;
		if ( !CPGetUserKey( hProv, AT_SIGNATURE, &hUserKey ) ){
			// Last error is set by CPGetUserKey.
			return FALSE;
		}
		KEY_INFO *pUserKey = (KEY_INFO *) hUserKey;
		
		// Sign the hash
		if ( !signHash( pProvCtx, pbHashValue, dwHashSize, pUserKey, pbSignature, pcbSigLen ) ){
			// Last error is set by signHash().
			delete[] pbHashValue;
			return FALSE;
		}
		CPDestroyKey( hProv, hUserKey );
		// Now hash is signed.
	}
	


	DEBUG(1,"---------------Data has been signed---------------\n");
    return TRUE;
}


/*
 -  CPDestroyHash
 -
 *  Purpose:
 *                Destroy the hash object
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	HASH_INFO *pHash = (HASH_INFO*) hHash;

	DEBUG(1,"_-_-_-_-_-_-_-_-_Destroying hash-_-_-_-_-_-_-_-_-\n");

	if ( !releaseHash( pProvCtx, pHash ) ){
		SetLastError( NTE_FAIL );
		delete pHash;
		return FALSE;
	}
	delete pHash;
	DEBUG(1,"-------------Hash has been destroyed-------------\n");
    return TRUE;
}


/*
 -  CPVerifySignature
 -
 *  Purpose:
 *                Used to verify a signature against a hash object
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  pbSignture   -  Pointer to signature data
 *               IN  dwSigLen     -  Length of the signature data
 *               IN  hPubKey      -  Handle to the public key for verifying
 *                                   the signature
 *               IN  sDescription -  String describing the signed data
 *               IN  dwFlags      -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPVerifySignature(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags)
{
	PROV_CTX *pProvCtx = (PROV_CTX*)hProv;
	HASH_INFO *pHash = (HASH_INFO*) hHash;
	KEY_INFO *pPubKey = (KEY_INFO*) hPubKey;

	BYTE* pbHashValue = NULL; //<contains extracted from the hash object hash value
	DWORD dwHashSizeLen; //<hash value size in bytes

	DEBUG(1,"_-_-_-_-_-_-_-_-_Verifying data-_-_-_-_-_-_-_-_-\n");
	if ( szDescription != NULL ){
		SetLastError( ERROR_INVALID_PARAMETER );
		return FALSE;
	}

	// CRYPT_NOHASHOID is supported only by RSA Providers.
	if ( dwFlags ){
		SetLastError( NTE_BAD_FLAGS );
		return FALSE;
	}
	
	
	if ( !CPGetHashParam( hProv, hHash, HP_HASHSIZE, LPBYTE(&dwHashSizeLen), &dwHashSizeLen, 0 ) ){
		// Last Error is set by CPGetHashParam()
		return FALSE;
	}
	// Allocate buffer for hash.
	try {
		pbHashValue = new BYTE[dwHashSizeLen];
	}
	catch (std::bad_alloc ){
		SetLastError( NTE_NO_MEMORY );
		return FALSE;
	}

	// Get the hash in propper.
	if ( !CPGetHashParam( hProv, hHash, HP_HASHVAL, pbHashValue, &dwHashSizeLen, 0 ) ){
		// Last Error is set by CPGetHashParam().
		delete[] pbHashValue;
		return FALSE;
	}
	// Verify the hash
	if ( !verifyHash( pProvCtx, pbHashValue, dwHashSizeLen, pPubKey, pbSignature, cbSigLen ) ){
			// Last error is set by verifyHash().
			delete[] pbHashValue;
			return FALSE;
		}

	return TRUE;
	DEBUG(1,"-------------Data has been verifyed-------------\n");
}


/*
 -  CPGenRandom
 -
 *  Purpose:
 *                Used to fill a buffer with random bytes
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the user identifcation
 *               IN  dwLen         -  Number of bytes of random data requested
 *               IN OUT pbBuffer   -  Pointer to the buffer where the random
 *                                    bytes are to be placed
 *
 *  Returns:
 */

BOOL WINAPI
CPGenRandom(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	DEBUG(1,"_-_-_-_-_-_-_-_-_Generating random-_-_-_-_-_-_-_-_-\n");
	if ( !genRandom( pProvCtx, cbLen, pbBuffer ) ){
		// LastError is set by genRandom
		return FALSE;
	}
	DEBUG(1,"-------------Random has been generated-------------\n");
    return TRUE;
}


/*
 -  CPGetUserKey
 -
 *  Purpose:
 *                Gets a handle to a permanent user key
 *
 *
 *  Parameters:
 *               IN  hProv      -  Handle to the user identifcation
 *               IN  dwKeySpec  -  Specification of the key to retrieve
 *               OUT phUserKey  -  Pointer to key handle of retrieved key
 *
 *  Returns:
 */

BOOL WINAPI
CPGetUserKey(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey)
{
	PROV_CTX *pProvCtx = (PROV_CTX*) hProv;
	KEY_INFO *pKey = NULL;
	DEBUG(1,"_-_-_-_-_-_-_-_-_Getting user key-_-_-_-_-_-_-_-_-\n");
	if ( pProvCtx->pContainer == NULL ){
		SetLastError( NTE_BAD_KEYSET );
		return FALSE;
	}
	if ( dwKeySpec & AT_KEYEXCHANGE ){
		SetLastError( ERROR_INVALID_PARAMETER );
		return FALSE;
	}
	try {
		pKey = new KEY_INFO;
	}
	catch( std::bad_alloc ){
		SetLastError( NTE_NO_MEMORY );
		return FALSE;
	}

	if ( !getUserKey( pProvCtx, pKey ) ){
		// LastError is set by getUserKey.
		return FALSE;
	}

	*phUserKey = (HCRYPTKEY) pKey;

	DEBUG(1,"----------------user key has been got-------------\n");
    return TRUE;
}


/*
 -  CPDuplicateHash
 -
 *  Purpose:
 *                Duplicates the state of a hash and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hHash          -  Handle to a hash
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phHash         -  Handle to the new hash
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
    *phHash = (HCRYPTHASH)NULL;  // Replace NULL with your own structure.
    return TRUE;
}


/*
 -  CPDuplicateKey
 -
 *  Purpose:
 *                Duplicates the state of a key and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hKey           -  Handle to a key
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phKey          -  Handle to the new key
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
    return TRUE;
}
