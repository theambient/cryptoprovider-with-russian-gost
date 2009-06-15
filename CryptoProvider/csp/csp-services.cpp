
#include "csp-services.h"
#include "gost.h"
#include "rand.h"

#define DEFAULT_CONTAINER_NAME "d:/keyset/EKEY/EKEY.INI"
#define DWORD MAX_CONTAINER_SIZE 512
	//<max size of the file EKEY.INI. 
	// if it greater this value assume the file is invalid.
	// normal file size is 110 bytes.

typedef struct _CONTAINER_IRZ {
	HANDLE hToken; //<handle to the file containing key pair.
	LPSTR szToken; //<handle to the file containing key pair.
	BYTE pbPrKey[GOST_SIGN_BITS]; //<PrivateKey.
	CHAR szUserID[20]; //<user ID, can be found under 
		//[IDENT] section of EKEY.INI.
	Rand rand;
} CONTAINER_IRZ;

typedef struct _KEY_SIGN {
	PUBLIC_KEY *pPubKey; //<Public key.
	PRIVATE_KEY *pPrKey; //<Private key.
	Params34102001 params; //<Key Params.
	bool bHasPrivate; //<true if key has private.
	bool bKeyModified;//<true if key was modified
} KEY_SIGN;

BOOL OpenContainer( PROV_CTX* pProvCtx, LPSTR szContainer ){
	LPSTR szToken = NULL;
	CONTAINER_IRZ *pContainerIRZ = NULL;
	if ( szContainer == NULL ){
		szToken = DEFAULT_CONTAINER_NAME;
	} else {
		szToken = szContainer;
	}

	HANDLE hToken = CreateFile( szToken, 
		GENERIC_READ||GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, NULL );

	if ( hToken == INVALID_HANDLE_VALUE ){
		SetLastError( NTE_BAD_KEYSET );
		return FALSE;
	}

	// \todo use GetFileSizeEx
	DWORD dwFileSize = GetFileSize(hToken, NULL );
	if ( dwFileSize > MAX_CONTAINER_SIZE ) {
		SetLastError( NTE_KEYSET_ENTRY_BAD );
		return FALSE;
	}
	
	try { 
		pContainerIRZ = new CONTAINER_IRZ;
	}
	catch (std::bad_alloc& e){
		SetLastError(NTE_NO_MEMORY);
		return FALSE;
	}

	strcpy( pContainerIRZ->szToken, szToken );
	pContainer->hToken = hToken;
	pProvCtx->pContainer->hServiceInformation = (HANDLE) pContainerIRZ;
	return TRUE;

}

BOOL getUserKey( PROV_CTX *pProvCtx, KEY_INFO *pKey ){

	if ( !pProvCtx->bSilent ){
		HANDLE hDialogBox;
		createDialogBox( hDialogBox );
		showModal( hDialogBox );

	showDialogBox( 
	getPrivateProfile
	return TRUE;
}

BOOL releaseContainer( PROV_CTX *pProvCtx ){
	CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ*) pProvCtx->pContainer->hServiceInformation;
	CloseHandle( pContainerIRZ->hToken );
	delete pContainerIRZ;
	return TRUE;
}

BOOL genKeyPair( PROV_CTX* pProvCtx, KEY_INFO* pKey ){
	if ( pKey->algId != CALG_GOST_SIGN ){
		SetLastError( NTE_BAD_ALG );
		return FALSE;
	}
	if ( pKey->hKeyInformation == NULL ){
		SetLastError( NTE_BAD_KEY_STATE );
		return FALSE;
	}
	CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ*) pProvCtx->pContainer->hServiceInformation;
	KEY_SIGN *pKeyInfo = (KEY_SIGN*) pKey->hKeyInformation;
	if ( !genKeyPair( pKeyInfo->pPubKey, pKeyInfo->pPrKey, pKeyInfo->params, pContainerIRZ->rand ) ){
		SetLastError( NTE_FAIL );
		return FALSE;
	}
	pKeyInfo->bHasPrivate = true;
	
	//Write key to the token.
	LPSTR szData = NULL;//< EKEY.INI file content.

	// Check the EKEY.INI file size.
	// If it's too big assume file as invalid.
	// \todo use GetFileSizeEx
	DWORD dwFileSize = GetFileSize(hToken, NULL );
	if ( dwFileSize > MAX_CONTAINER_SIZE ) {
		SetLastError( NTE_KEYSET_ENTRY_BAD );
		return FALSE;
	}

	// Get the file content.
	szData = new CHAR[dwFileSize];
	if ( !ReadFile( hToken, szData, dwFileSize, &dwFileSize, NULL ) ){
		SetLastError( NTE_KEYSET_ENTRY_BAD );
		delete[] szData;
		return FALSE;		
	}

	// Look up for PRIVATEKEY section.
	LPSTR szPrKeySec = strstr( szData, "[PRIVATEKEY]" );
	if ( szPrKeySec  == NULL ){
		SetLastError( NTE_KEYSET_ENTRY_BAD );
		delete[] szData;
		return FALSE;		
	}
	
	// Look up for PRIVATEKEY KEY 
	const LPSTR szPrKeyKey = "PRIVATEKEY="; //<Key under [PRIVATEKEY] section
		// with assosiated private key value.
	LPSTR szPrKeyValue = strstr( szPrKeySec, szPrKeyKey ) + strlen(szPrKeyKey);
	


	return TRUE;
}
