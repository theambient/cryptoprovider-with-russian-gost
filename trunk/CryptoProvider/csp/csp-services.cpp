
#include "csp-services.h"
#include "gost/gost.h"
#include "gost/hash.h"
#include "rand/rand.h"
#include "constants.h"
#include "csp-helpers.h"

#define DEFAULT_CONTAINER_NAME "d:/keyset/EKEY/EKEY.INI"
#define MAX_CONTAINER_SIZE 512
	//<max size of the file EKEY.INI. 
	// if it greater this value assume the file is invalid.
	// normal file size is 110 bytes.

typedef struct _CONTAINER_IRZ {
	//HANDLE hToken; //<handle to the file containing key pair.
	LPSTR szToken; //<handle to the file containing key pair.
	//BYTE pbPrKey[GOST_SIGN_BITS]; //<PrivateKey.
	CHAR szUserID[20]; //<user ID, can be found under 
		//[IDENT] section of EKEY.INI.
	//KEY_INFO pUserKey;
	Rand rand;
} CONTAINER_IRZ;

typedef struct _KEY_SIGN_INFO {
	PUBLIC_KEY *pPubKey; //<Public key.
	PRIVATE_KEY *pPrKey; //<Private key.
	PARAMS_GOST_SIGN params; //<Key Params.
	//bool bHasPrivate; //<true if key has private.
	//bool bKeyModified;//<true if key was modified
} KEY_SIGN_INFO;

typedef struct _HASH_SERVICE_INFO {
	BYTE bDataHashed[HASH_BYTE_LEN];//< contains already hashed data, var H from GOST.
	BYTE bDataRest[HASH_BYTE_LEN];	//< contains the rest of data from last feeding (updateHash)
									//		if feeded data len is not multiple of HASH_BYTE_LEN.
	BYTE bSum[HASH_BYTE_LEN];		//< the control sum of hashing data, var $\Sigma$ from GOST.
	BYTE bLen[HASH_BYTE_LEN];		//< the control length of hashing Data, var L from GOST.
	DWORD dwDataRestLen;			//< actual length of bDataRest.
} HASH_SERVICE_INFO;

BOOL OpenContainer( PROV_CTX* pProvCtx, LPCSTR szContainer ){
	LPSTR szToken = NULL;
	CONTAINER_IRZ *pContainerIRZ = NULL;
	if ( szContainer == NULL ){
		strcpy( szToken , DEFAULT_CONTAINER_NAME );
	} else {
		strcpy( szToken, szContainer );
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
	catch (std::bad_alloc){
		SetLastError(NTE_NO_MEMORY);
		return FALSE;
	}

	strcpy( pContainerIRZ->szToken, szToken );
	//pContainerIRZ->pUserKey = NULL;
	CloseHandle( hToken );
	pProvCtx->pContainer->hServiceInformation = (HANDLE) pContainerIRZ;
	return TRUE;

}

BOOL getUserKey( PROV_CTX *pProvCtx, KEY_INFO *pKey ){

	/*
	if ( !pProvCtx->bSilent ){
		HANDLE hDialogBox;
		createDialogBox( hDialogBox );
		showModal( hDialogBox );
	*/
	//showDialogBox( 

	CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ *) pProvCtx->pContainer->hServiceInformation;
	LPSTR szPrivateKey = new CHAR[PRIVATEKEY_CHAR_LEN+1];
	DWORD dwRes = GetPrivateProfileStringA(  "PRIVATEKEY", 
		"PRIVATEKEY",
		NULL,
		szPrivateKey,
		PRIVATEKEY_CHAR_LEN+1,
		pContainerIRZ->szToken);

	if ( dwRes != PRIVATEKEY_CHAR_LEN ){
		delete[] szPrivateKey;
		SetLastError(NTE_BAD_KEYSET);
		return FALSE;
	}

	
	pKey->algId = CALG_GOST_SIGN;
	pKey->blockLen = 0;
	pKey->dwKeySpec = AT_SIGNATURE;
	pKey->exportable = TRUE;
	pKey->fLen = 0;
	pKey->length = PRIVATEKEY_BYTE_LEN;

	KEY_SIGN_INFO *pKeyInfo = new KEY_SIGN_INFO;
	pKey->hKeyInformation = (HANDLE) pKeyInfo;

	pKeyInfo->params = PARAMSET_GOST_SIGN_1;
	if ( !derivePrivateKey( pKeyInfo->pPrKey, szPrivateKey ) ){
		SetLastError( NTE_BAD_KEYSET );
		return FALSE;
	}
	pKeyInfo->pPubKey = NULL;
	return TRUE;
}

BOOL releaseContainer( PROV_CTX *pProvCtx ){
	CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ*) pProvCtx->pContainer->hServiceInformation;
	//CloseHandle( pContainerIRZ->hToken );
	delete pContainerIRZ;
	return TRUE;
}

BOOL genKeyPair( PROV_CTX* pProvCtx, KEY_INFO* pKey ){
	if ( pKey->algId != CALG_GOST_SIGN ){
		SetLastError( NTE_BAD_ALGID );
		return FALSE;
	}
	if ( pKey->hKeyInformation == NULL ){
		SetLastError( NTE_BAD_KEY_STATE );
		return FALSE;
	}
	CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ*) pProvCtx->pContainer->hServiceInformation;
	KEY_SIGN_INFO *pKeyInfo = (KEY_SIGN_INFO*) pKey->hKeyInformation;

	// Generate key pair in proper.
	if ( !genKeyPair( &pKeyInfo->pPubKey, &pKeyInfo->pPrKey, &pKeyInfo->params, &pContainerIRZ->rand ) ){
		SetLastError( NTE_FAIL );
		return FALSE;
	}
	
	// Write the key to the token.
	LPSTR szPrKey = new CHAR[PRIVATEKEY_CHAR_LEN+1];
	LPSTR szPubKey = new CHAR[PUBLICKEY_CHAR_LEN+1];
	
	if ( !privateKeyToString( pKeyInfo->pPrKey, szPrKey ) ){
		/* \todo release resources.*/
		SetLastError( NTE_FAIL );
		return FALSE;
	}
	
	if ( !pubKeyToString( pKeyInfo->pPubKey, szPubKey ) ){
		/* \todo release resources.*/
		SetLastError( NTE_FAIL );
		return FALSE;
	}

	WritePrivateProfileStringA( 
		"PRIVATEKEY",
		"PRIVATEKEY",
		szPrKey,
		pContainerIRZ->szToken);

	WritePrivateProfileStringA( 
		"PUBLICKEY",
		"PUBLICKEY",
		szPrKey,
		pContainerIRZ->szToken);

	delete[] szPrKey;
	delete[] szPubKey;

	return TRUE;

}

DWORD getKeyLen( ALG_ID algid ){
	extern PROV_ENUMALGS_EX algorithms[];
	extern const unsigned algorithms_count;
	for (unsigned i=0; i<algorithms_count; i++){
		if ( algorithms[i].aiAlgid == algid ){
			return algorithms[i].dwDefaultLen;
		}
	}
	return 0;
}

BOOL releaseKey( PROV_CTX *pProvCtx, KEY_INFO *pKey ){
	delete pKey->hKeyInformation;
	return TRUE;
}

BOOL setHash( PROV_CTX* pProvCtx, HASH_INFO *pHash, const BYTE *pbHashValue){

#ifdef _VERBOSE_VERBOSE
	if ( pHash == NULL )
		return FALSE;
#endif

	if ( pHash->hHashInformation == NULL )
		return FALSE;

	HASH_SERVICE_INFO *pHashInfo = (HASH_SERVICE_INFO *)pHash->hHashInformation;
	switch ( pHash->algid ){
		case CALG_GOST_HASH:
			memcpy(pHashInfo->bDataHashed, pbHashValue, HASH_BYTE_LEN );
		default:
			SetLastError( NTE_BAD_ALGID );
			return FALSE;
	}
	return TRUE;
}

BOOL createHash(PROV_CTX* pProvCtx, HASH_INFO* pHash ){
	HASH_SERVICE_INFO *pHashInfo = (HASH_SERVICE_INFO *) pHash->hHashInformation;
	try {
		pHashInfo = new HASH_SERVICE_INFO;
	} catch (std::bad_alloc ){
		return FALSE;
	}

	memset( pHashInfo->bDataHashed, 0, HASH_BYTE_LEN );
	memset( pHashInfo->bDataRest, 0, HASH_BYTE_LEN );
	memset( pHashInfo->bLen, 0, HASH_BYTE_LEN );
	memset( pHashInfo->bLen, 0, HASH_BYTE_LEN );
	return TRUE;
}

BOOL updateHash(PROV_CTX *PRpProvCtx,
				HASH_INFO *pHash,
				const BYTE *pbData,
				DWORD cbDataLen ){
	HASH_SERVICE_INFO *pHashInfo = (HASH_SERVICE_INFO *) pHash->hHashInformation;
	DWORD dwRestLen = cbDataLen; //< length of  data rest to be feeded.
	const BYTE *pbRest = pbData;//< rest of data to be feeded.

	if ( pHashInfo == NULL ){
		SetLastError( NTE_BAD_HASH );
		return FALSE;
	}

	// feed first bDataRest concatenating with pbData.
	if ( pHashInfo->dwDataRestLen > 0 ){
		const DWORD dwPaddingLen = HASH_BYTE_LEN - pHashInfo->dwDataRestLen;
		//< Number of bytes to pad the pHash->bDataRest
		for(unsigned i=0; (i<dwPaddingLen)&&(i<dwRestLen); i++)
			pHashInfo->bDataRest[pHashInfo->dwDataRestLen+i] = pbData[i];
		// if there is enough data to pad the block length of 256 bit.
		if ( dwRestLen >= dwPaddingLen ){
			stephash( pHashInfo->bDataHashed, pHashInfo->bDataRest, pHashInfo->bDataHashed );
			// calculate control length.

			// note that the loop starts from 1 cause 
			//	(256) = 2^8 = (10)_256 where (X)_b is 
			//	the number X in numerical sytem with base b.
			int c = 1;
			for (unsigned j = 1; j < HASH_BYTE_LEN; j++) {
				c += pHashInfo->bLen[j];
				pHashInfo->bLen[j] = c & 0xFF;
				c >>= 8;
			}
			// calculate control sum.
			c = 0;
			for (unsigned j = 0; j < HASH_BYTE_LEN; j++) {
				c += pHashInfo->bDataHashed[j] + pHashInfo->bSum[j];
				pHashInfo->bSum[j] = c & 0xFF;
				c >>= 8;
			}
			dwRestLen-=dwPaddingLen;
			pbRest+=dwPaddingLen;
			pHashInfo->dwDataRestLen = 0;
		} else { // Data was not length enough to pad to full block.
			pHashInfo->dwDataRestLen += dwRestLen;
			return TRUE;
		}
	}
	
	while ( dwRestLen > HASH_BYTE_LEN ){
		stephash( pHashInfo->bDataHashed, pbRest, pHashInfo->bDataHashed );
		// calculate control length.

		// note that the loop starts from 1 cause 
		//	(256) = 2^8 = (10)_256 where (X)_b is 
		//	the number X in numerical sytem with base b.
		int c = 1;
		for (unsigned j = 1; j < HASH_BYTE_LEN; j++) {
			c += pHashInfo->bLen[j];
			pHashInfo->bLen[j] = c & 0xFF;
			c >>= 8;
		}
		// calculate control sum.
		c = 0;
		for (unsigned j = 0; j < HASH_BYTE_LEN; j++) {
			c += pbRest[j] + pHashInfo->bSum[j];
			pHashInfo->bSum[j] = c & 0xFF;
			c >>= 8;
		}	
		dwRestLen-= HASH_BYTE_LEN;
		pbRest+=HASH_BYTE_LEN;
	}
	
	// Write not feeded data to the rest.
	if ( dwRestLen >0 ){
		for (unsigned j=0;j<dwRestLen;j++){
			pHashInfo->bDataRest[j] = pbRest[j];
		}
		pHashInfo->dwDataRestLen = dwRestLen;
	}
	return TRUE;
}

BOOL getHash( PROV_CTX *pProvCtx,
				HASH_INFO *pHash,
				BYTE *pbHashValue,
				DWORD *pcbHashLen ){

	HASH_SERVICE_INFO *pHashInfo = (HASH_SERVICE_INFO *) pHash->hHashInformation;
	// if there is unfeeded data then feed it, pad if require.
	if ( pHashInfo->dwDataRestLen > 0 ){
		const DWORD dwPaddingLen = HASH_BYTE_LEN - pHashInfo->dwDataRestLen;
		//< Number of bytes to pad the pHash->bDataRest
		for(unsigned i=pHashInfo->dwDataRestLen-1; i<HASH_BYTE_LEN; i++)
			pHashInfo->bDataRest[i] = 0;
		stephash( pHashInfo->bDataHashed, pHashInfo->bDataRest, pHashInfo->bDataHashed );
		// calculate control length.

		int c = pHashInfo->dwDataRestLen;
		for (unsigned j = 0; j < HASH_BYTE_LEN; j++){
			c += pHashInfo->bLen[j];
			pHashInfo->bLen[j] = c & 0xFF;
			c >>= 8;
		}
		// calculate control sum.
		c = 0;
		for (unsigned j = 0; j < HASH_BYTE_LEN; j++) {
			c += pHashInfo->bDataHashed[j] + pHashInfo->bSum[j];
			pHashInfo->bSum[j] = c & 0xFF;
			c >>= 8;
		}
	}
	if ( *pcbHashLen < HASH_BYTE_LEN ){
		SetLastError( ERROR_MORE_DATA );
		return FALSE;
	}
	memcpy( pbHashValue, pHashInfo->bDataHashed, HASH_BYTE_LEN );
	*pcbHashLen = HASH_BYTE_LEN;
	pHash->finished = true;
	return TRUE;
}

BOOL releaseHash( PROV_CTX *pProvCtx, HASH_INFO *pHash ){
	delete pHash->hHashInformation;
	return TRUE;
}

BOOL exportPubKey(IN PROV_CTX* pProvCtx,
			 IN KEY_INFO* pKey,
			 OUT BYTE* pbData,
			 OUT DWORD* pdwDataLen ){

	KEY_SIGN_INFO *pKeyInfo = (KEY_SIGN_INFO*) pKey->hKeyInformation;
	if ( pKeyInfo->pPubKey == NULL ){
		SetLastError( NTE_NO_KEY );
		return FALSE;
	}
	if ( *pdwDataLen < PUBLICKEY_BYTE_LEN + sizeof (DWORD) ){
		SetLastError( ERROR_MORE_DATA );
		return FALSE;
	}
	
	if ( !extractPublicKey( pKeyInfo->pPubKey, pbData ) ){
		SetLastError( NTE_FAIL );
		return FALSE;
	}
	*LPDWORD( pbData + PUBLICKEY_BYTE_LEN ) = pKeyInfo->params.dwParamSet;
	*pdwDataLen = PUBLICKEY_BYTE_LEN + sizeof( DWORD );
	return TRUE;
}

BOOL getPubKeyLen( PROV_CTX *pProvCtx, KEY_INFO *pKey, DWORD *pdwLen ){

	switch ( pKey->algId ){
		case CALG_GOST_SIGN:
			*pdwLen = PUBLICKEY_BYTE_LEN+sizeof(DWORD);
			break;
		default:
			SetLastError( NTE_BAD_ALGID );
			return FALSE;
	}
	return TRUE;
}

BOOL importPubKey(
	PROV_CTX* pProvCtx,
	KEY_INFO* pKey,
	BYTE* pbData,
	DWORD dwDataLen )
{
	
	KEY_SIGN_INFO *pKeyInfo = (KEY_SIGN_INFO *) pKey->hKeyInformation;
	pKeyInfo = NULL;
	pKeyInfo = new KEY_SIGN_INFO;

	if ( dwDataLen != PUBLICKEY_BYTE_LEN + sizeof(DWORD) ){
		SetLastError( NTE_BAD_DATA );
		return FALSE;
	}

	if ( !derivePubKey( pKeyInfo->pPubKey, pbData ) ){
		SetLastError( NTE_BAD_DATA );
		return FALSE;
	}

	DWORD dwParamSet = *LPDWORD( pbData + PUBLICKEY_BYTE_LEN );
	pKeyInfo->params = PARAMS_GOST_SIGN( dwParamSet );
	pKeyInfo->pPrKey = NULL;
	return TRUE;
}

BOOL signHash(PROV_CTX *pProvCtx, 
		 BYTE* pbHashValue,
		 DWORD dwHashSize,
		 KEY_INFO *pKey,
		 BYTE* pbSignature,
		 DWORD* pcbSigLen )
{
	CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ *) pProvCtx->pContainer->hServiceInformation;
	KEY_SIGN_INFO *pKeyInfo = (KEY_SIGN_INFO *)pKey->hKeyInformation;
	if ( pKeyInfo->pPrKey == NULL ){
		SetLastError( NTE_NO_KEY );
		return FALSE;
	}


	if ( !sign( pbHashValue, pKeyInfo->pPrKey, pbSignature, 
		pKeyInfo->params, pContainerIRZ->rand ) )
	{
			SetLastError( NTE_FAIL );
			return FALSE;
	}

	return TRUE;
}

BOOL verifyHash(PROV_CTX *pProvCtx,
		   BYTE* pbHashValue, 
		   DWORD dwHashSize, 
		   KEY_INFO *pPubKey, 
		   const BYTE* pbSignature, 
		   DWORD cbSigLen )
{
	//CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ *) pProvCtx->pContainer->hServiceInformation;
	KEY_SIGN_INFO *pKeyInfo = (KEY_SIGN_INFO *)pPubKey->hKeyInformation;
	if ( pKeyInfo->pPubKey == NULL ){
		SetLastError( NTE_BAD_KEY_STATE );
		return FALSE;
	}
	return verify( pbHashValue, pKeyInfo->pPubKey, pbSignature, pKeyInfo->params );
}

BOOL genRandom(PROV_CTX *pProvCtx, 
		  DWORD dwLen,
		  BYTE* pbData )
{
	CONTAINER_IRZ * pContainerIRZ = (CONTAINER_IRZ *) pProvCtx->pContainer->hServiceInformation;
	return genRandom( dwLen, pbData, pContainerIRZ->rand );
}