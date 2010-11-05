
#include "csp-services.h"
#include "gost/gost.h"
#include "gost/hash.h"
#include "gost/crypt.h"
#include "rand/rand.h"
#include "constants.h"
#include "csp-helpers.h"
#include "csp-debug.h"

#define DEFAULT_CONTAINER_NAME "d:/keyset/EKEY/EKEY.INI"
#define MAX_CONTAINER_SIZE 512
	//<max size of the file EKEY.INI. 
	// if it greater this value assume the file is invalid.
	// normal file size is 110 bytes.

BOOL OpenContainer( PROV_CTX* pProvCtx, LPCSTR szContainer ){
	CHAR szToken[200];
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
	CHAR szPrivateKey[PRIVATEKEY_CHAR_LEN+1];
	CHAR szPublicKey[PUBLICKEY_CHAR_LEN+1];
	DWORD dwRes = GetPrivateProfileStringA(  
		"PRIVATEKEY",
		"PRIVATEKEY",
		NULL,
		szPrivateKey,
		PRIVATEKEY_CHAR_LEN+1,
		pContainerIRZ->szToken);

	if ( dwRes != PRIVATEKEY_CHAR_LEN ){
		SetLastError(NTE_BAD_KEYSET);
		return FALSE;
	}

	dwRes = GetPrivateProfileStringA(  
		"PUBLICKEY", 
		"PUBLICKEY",
		NULL,
		szPublicKey,
		PUBLICKEY_CHAR_LEN+1,
		pContainerIRZ->szToken);
	
	pKey->algId = CALG_GOST_SIGN;
	pKey->blockLen = 0;
	pKey->dwKeySpec = AT_SIGNATURE;
	pKey->exportable = TRUE;
	pKey->fLen = 0;
	pKey->length = PRIVATEKEY_BYTE_LEN;

	KEY_SIGN_INFO *pKeyInfo = (KEY_SIGN_INFO *) pKey->hKeyInformation;

	//pKeyInfo->params = PARAMS_GOST_SIGN( PARAMSET_GOST_SIGN_1 );
	if ( !derivePrivateKey( pKeyInfo, szPrivateKey ) ){
		SetLastError( NTE_BAD_KEYSET );
		return FALSE;
	}
	if ( szPublicKey != NULL ){
		if ( !derivePubKey( pKeyInfo, szPublicKey ) ){
			SetLastError( NTE_BAD_KEYSET );
			return FALSE;
		}		
	} else 
		pKeyInfo->pPubKey = NULL;

	return TRUE;
}

BOOL releaseContainer( PROV_CTX *pProvCtx ){
	CONTAINER_IRZ *pContainerIRZ = (CONTAINER_IRZ*) pProvCtx->pContainer->hServiceInformation;
	//CloseHandle( pContainerIRZ->hToken );
	delete pContainerIRZ;
	return TRUE;
}

BOOL createKey( PROV_CTX *pProvCtx, KEY_INFO **ppKey ){
		
	*ppKey = new KEY_INFO;

	KEY_INFO *pKey = *ppKey;

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

	KEY_SIGN_INFO *pKeyInfo = new KEY_SIGN_INFO;
	pKeyInfo->pPrKey = NULL;
	pKeyInfo->pPubKey = NULL;
	pKey->hKeyInformation = (HANDLE) pKeyInfo;

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
	if ( pKeyInfo->pPrKey != NULL || pKeyInfo->pPubKey != NULL ){
		DEBUG( 1, "While generating key pair: Key already exists." );
	}
	if ( !genKeyPair( &pKeyInfo->pPubKey, &(pKeyInfo->pPrKey), &pKeyInfo->params, &pContainerIRZ->rand ) ){
		SetLastError( NTE_FAIL );
		return FALSE;
	}
	
	// Write the key to the token.
	LPSTR szPrKey = new CHAR[PRIVATEKEY_CHAR_LEN+1];
	LPSTR szPubKey = new CHAR[PUBLICKEY_CHAR_LEN+1];
	
	if ( !privateKeyToString( pKeyInfo, szPrKey ) ){
		/* \todo release resources.*/
		SetLastError( NTE_FAIL );
		return FALSE;
	}
	
	if ( !pubKeyToString( pKeyInfo, szPubKey ) ){
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
		szPubKey,
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
	delete (KEY_SIGN_INFO*) pKey->hKeyInformation;
	return TRUE;
}

BOOL setHash( PROV_CTX* pProvCtx, HASH_INFO *pHash, const BYTE *pbHashValue){

#ifdef _VERBOSE_VERBOSE
	if ( pHash == NULL )
		return FALSE;
#endif

	if ( pHash->hHashInformation == NULL ){
		SetLastError(NTE_BAD_HASH_STATE);
		return FALSE;
	}

	HASH_SERVICE_INFO *pHashInfo = (HASH_SERVICE_INFO *)pHash->hHashInformation;
	switch ( pHash->algid ){
		case CALG_GOST_HASH:
			memcpy(pHashInfo->bDataHashed, pbHashValue, HASH_BYTE_LEN );
			pHashInfo->bValueIsSet = TRUE;
			break;
		default:
			SetLastError( NTE_BAD_ALGID );
			return FALSE;
	}
	return TRUE;
}

BOOL createHash(PROV_CTX* pProvCtx, HASH_INFO **ppHash ){

	HASH_SERVICE_INFO *pHashInfo = NULL;

	try {
		*ppHash = new HASH_INFO;
		pHashInfo = new HASH_SERVICE_INFO;
	} catch (std::bad_alloc ){
		SetLastError( NTE_NO_MEMORY );
		return FALSE;
	}
	(*ppHash)->algid = CALG_GOST_HASH;
	(*ppHash)->dwHashLen = GOST_HASH_BITS/CHAR_BIT;
	(*ppHash)->finished = FALSE;
	(*ppHash)->hHashInformation = pHashInfo;

	memset( pHashInfo->bDataHashed, 0, HASH_BYTE_LEN );
	memset( pHashInfo->bDataRest, 0, HASH_BYTE_LEN );
	memset( pHashInfo->bLen, 0, HASH_BYTE_LEN );
	memset( pHashInfo->bSum, 0, HASH_BYTE_LEN );
	pHashInfo->dwDataRestLen = 0;
	pHashInfo->bValueIsSet = FALSE;
	return TRUE;
}

BOOL updateHash(PROV_CTX *PRpProvCtx,
				HASH_INFO *pHash,
				const BYTE *pbData,
				DWORD cbDataLen ){
	HASH_SERVICE_INFO *pHashInfo = (HASH_SERVICE_INFO *) pHash->hHashInformation;
	DWORD dwRestLen = cbDataLen; //< length of  data rest to be feeded.
	const BYTE *pbRest = pbData;//< rest of data to be feeded.

	if ( pHashInfo->bValueIsSet == TRUE ){
		SetLastError( NTE_BAD_HASH_STATE );
		return FALSE;
	}

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
	
	while ( dwRestLen >= HASH_BYTE_LEN ){
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

	if ( *pcbHashLen < HASH_BYTE_LEN ){
		SetLastError( ERROR_MORE_DATA );
		return FALSE;
	}

	// if there is unfeeded data then feed it, pad if require.
	if ( !pHashInfo->bValueIsSet && pHashInfo->dwDataRestLen > 0 ){
		const DWORD dwPaddingLen = HASH_BYTE_LEN - pHashInfo->dwDataRestLen;
		//< Number of bytes to pad the pHash->bDataRest
		for(unsigned i=pHashInfo->dwDataRestLen; i<HASH_BYTE_LEN; i++)
			pHashInfo->bDataRest[i] = 0;
		//memmove( pHashInfo->bDataRest+dwPaddingLen, pHashInfo->bDataRest, pHashInfo->dwDataRestLen );
		//memset( pHashInfo->bDataRest, 0, dwPaddingLen );
		stephash( pHashInfo->bDataHashed, pHashInfo->bDataRest, pHashInfo->bDataHashed );
		// calculate control length.

		int c = pHashInfo->dwDataRestLen*8;
		for (unsigned j = 0; j < HASH_BYTE_LEN; j++){
			c += pHashInfo->bLen[j];
			pHashInfo->bLen[j] = c & 0xFF;
			c >>= 8;
		}
		// calculate control sum.
		c = 0;
		for (unsigned j = 0; j < HASH_BYTE_LEN; j++) {
			c += pHashInfo->bDataRest[j] + pHashInfo->bSum[j];
			pHashInfo->bSum[j] = c & 0xFF;
			c >>= 8;
		}
	}
	if ( !pHashInfo->bValueIsSet ){
		// Feed control length.
		stephash( pHashInfo->bDataHashed, pHashInfo->bLen, pHashInfo->bDataHashed );
		// Feed control sum.
		stephash( pHashInfo->bDataHashed, pHashInfo->bSum, pHashInfo->bDataHashed );
		for (unsigned i=0; i< HASH_BYTE_LEN; i++ )
			pbHashValue[i] = pHashInfo->bDataHashed[HASH_BYTE_LEN - i - 1];
	} else {
		memcpy( pbHashValue, pHashInfo->bDataHashed, HASH_BYTE_LEN );
	}

	*pcbHashLen = HASH_BYTE_LEN;
	pHash->finished = true;
	return TRUE;
}

BOOL releaseHash( PROV_CTX *pProvCtx, HASH_INFO *pHash ){
	delete pHash->hHashInformation;
	delete pHash;
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
	
	if ( !extractPublicKey( pKeyInfo, pbData ) ){
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

	if ( dwDataLen != PUBLICKEY_BYTE_LEN + sizeof(DWORD) ){
		SetLastError( NTE_BAD_DATA );
		return FALSE;
	}

	if ( !derivePubKey( pKeyInfo, pbData ) ){
		SetLastError( NTE_BAD_DATA );
		return FALSE;
	}
	// \todo handle paramset.
	//DWORD dwParamSet = *LPDWORD( pbData + PUBLICKEY_BYTE_LEN );
	//pKeyInfo->params = PARAMS_GOST_SIGN( dwParamSet );
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

BOOL createSimmKey( PROV_CTX *pProvCtx, KEY_INFO **ppKey ){

	KEY_INFO *pKey = new KEY_INFO;
	*ppKey = pKey;

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

	KEY_CRYPT_INFO *pKeyInfo = new KEY_CRYPT_INFO;
	//pKeyInfo->dwDataRestLen = 0;
	pKey->hKeyInformation = (HANDLE) pKeyInfo;
	return TRUE;
}

BOOL genSimmKey( PROV_CTX *pProvCtx, KEY_INFO *pKey ){

	KEY_CRYPT_INFO *pKeyInfo = ( KEY_CRYPT_INFO *) pKey->hKeyInformation;
	// \todo Fix the explicit using intel library. 
	Rand rand;
	IppsBigNumState *pBN = rand( CRYPTKEY_BYTE_LEN );
	bnGet( pBN, pKeyInfo->bKey, CRYPTKEY_BYTE_LEN );
	bnRelease( pBN );
	return TRUE;
}

BOOL releaseSimmKey( PROV_CTX *pProvCtx, KEY_INFO *pKey ){
	delete (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	return TRUE;
}

DWORD getCryptDataLen( PROV_CTX *pProvCtx, const KEY_INFO *pKey, const DWORD dwDataLen, const BOOL bFinal ){

	KEY_CRYPT_INFO *pKeyInfo = ( KEY_CRYPT_INFO *) pKey->hKeyInformation;

	if ( dwDataLen == 0 )
		return CRYPTBLOCK_BYTE_LEN;

	switch ( pKeyInfo->params.dwMode ){
		
		case GOST_CRYPT_ECB:
			if ( dwDataLen%CRYPTBLOCK_BYTE_LEN == 0 )
				return dwDataLen;
			else
				return  (dwDataLen/CRYPTBLOCK_BYTE_LEN + bFinal)*CRYPTBLOCK_BYTE_LEN;
			break;
		case GOST_CRYPT_CBC:
			// The only difference with ECB in IV storring in ciphertext. 
			if ( dwDataLen%CRYPTBLOCK_BYTE_LEN == 0 )
				return dwDataLen + CRYPTBLOCK_BYTE_LEN;
			else
				return  (dwDataLen/CRYPTBLOCK_BYTE_LEN + bFinal+1)*CRYPTBLOCK_BYTE_LEN;
			break;
		case GOST_CRYPT_OFB:
		case GOST_CRYPT_MAC:
			return CRYPTBLOCK_BYTE_LEN;
		default:
			SetLastError(NTE_KEYSET_ENTRY_BAD);
			return 0;
	}

}



BOOL encryptGOST_ECB( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, DWORD *pdwDataLen, const BOOL bFinal ){

	KEY_CRYPT_INFO *pKeyInfo = ( KEY_CRYPT_INFO *) pKey->hKeyInformation;

	BYTE bCipherText[CRYPTBLOCK_BYTE_LEN];
	const DWORD dwDataLen = *pdwDataLen; //<Local copy of plaintext size.

	if ( !bFinal && dwDataLen % CRYPTBLOCK_BYTE_LEN != 0  ){
		SetLastError( NTE_BAD_LEN );
		return FALSE;
	}

	BYTE* pbBlockToEncrypt = pbData; //< Next block to encrypt.
	const BYTE* pbLastBlockBegin = pbData + dwDataLen - CRYPTBLOCK_BYTE_LEN; 
	//< Last possible block to encrypt, actually convenient boundary for the while loop.
	
	BYTE* pbBlockToWrite = pbData; //< Block to which write encrypted data.
	
	// Encrypt data block by block until exhaust.
	while( pbBlockToEncrypt <= pbLastBlockBegin ){
		encryptECB( pbBlockToEncrypt, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
		pbBlockToEncrypt += CRYPTBLOCK_BYTE_LEN;
	}
	if ( !bFinal ){
		if ( pbBlockToEncrypt - pbData != dwDataLen ){
			SetLastError( NTE_FAIL );
			return FALSE;
		}
	} else {
		// Pad the rest data and encrypt it.
		BYTE bFinalBlock[CRYPTBLOCK_BYTE_LEN];
		DWORD dwFinalDataLen = dwDataLen - (pbBlockToEncrypt - pbData);
		memcpy( bFinalBlock, pbBlockToEncrypt, dwFinalDataLen );
		memset( bFinalBlock + dwFinalDataLen, 0, CRYPTBLOCK_BYTE_LEN - dwFinalDataLen );
		// Encrypt data in proper and write it.
		encryptECB( bFinalBlock, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
	}

	*pdwDataLen = pbBlockToWrite - pbData;
	return TRUE;

}

BOOL decryptGOST_ECB( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, DWORD *pdwDataLen, const BOOL bFinal ){

	KEY_CRYPT_INFO *pKeyInfo = (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	BYTE bPlainText[CRYPTBLOCK_BYTE_LEN];

	const DWORD dwDataLen = *pdwDataLen; //<Local copy of ciphertext size.

	if ( dwDataLen % CRYPTBLOCK_BYTE_LEN != 0  ){
		SetLastError( NTE_BAD_LEN );
		return FALSE;
	}

	
	BYTE* pbBlockToDecrypt = pbData; //< Next block to decrypt.
	const BYTE* pbLastBlockBegin = pbData + dwDataLen - CRYPTBLOCK_BYTE_LEN; 
	//< Last possible block to decrypt, actually convenient boundary for the while loop.
	
	BYTE* pbBlockToWrite = pbData; //< Block to which write decrypted data.
	BYTE* pbPrevCipherText = pbData;

	// Decrypt data block by block until exhaust.
	while( pbBlockToDecrypt <= pbLastBlockBegin ){

		decryptECB( pbBlockToDecrypt, pKeyInfo->bKey, bPlainText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bPlainText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
		pbBlockToDecrypt += CRYPTBLOCK_BYTE_LEN;
	}
	if ( !bFinal ){
		if ( pbBlockToDecrypt - pbData != dwDataLen ){
			SetLastError( NTE_FAIL );
			return FALSE;
		}
	} else {
		// Pad the rest data and decrypt it.
		BYTE bFinalBlock[CRYPTBLOCK_BYTE_LEN];
		DWORD dwFinalDataLen = dwDataLen - (pbBlockToDecrypt - pbData);
		memcpy( bFinalBlock, pbBlockToDecrypt, dwFinalDataLen );
		memset( bFinalBlock + dwFinalDataLen, 0, CRYPTBLOCK_BYTE_LEN - dwFinalDataLen );
		// Decrypt data in proper and write it.
		decryptECB( bFinalBlock, pKeyInfo->bKey, bPlainText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bPlainText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
	}

	//*pdwDataLen = pbBlockToWrite - pbData;

	return TRUE;

}

BOOL encryptGOST_CBC( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, DWORD *pdwDataLen, const BOOL bFinal ){

	KEY_CRYPT_INFO *pKeyInfo = (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	BYTE bCipherText[CRYPTBLOCK_BYTE_LEN];
	const DWORD dwDataLen = *pdwDataLen; //<Local copy of plaintext size.

	if ( !bFinal && dwDataLen % CRYPTBLOCK_BYTE_LEN != 0  ){
		SetLastError( NTE_BAD_LEN );
		return FALSE;
	}

	BYTE* pbBlockToEncrypt = pbData; //< Next block to encrypt.
	const BYTE* pbLastBlockBegin = pbData + dwDataLen - CRYPTBLOCK_BYTE_LEN; 
	//< Last possible block to encrypt, actually convenient boundary for the while loop.
	
	BYTE* pbBlockToWrite = pbData; //< Block to which write encrypted data.
	
	// Encrypt data block by block until exhaust.
	// Generate random IV.
	BYTE bIV[CRYPTBLOCK_BYTE_LEN];
	genRandom( pProvCtx, CRYPTBLOCK_BYTE_LEN, bIV );
	memcpy( bCipherText, bIV, CRYPTBLOCK_BYTE_LEN ); 
	while( pbBlockToEncrypt <= pbLastBlockBegin ){
		// Note that upon encryptCBC bCipherText contains new encrypted data. 
		encryptCBC( pbBlockToEncrypt, pKeyInfo->bKey, bCipherText, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
		pbBlockToEncrypt += CRYPTBLOCK_BYTE_LEN;
	}
	if ( !bFinal ){
		if ( pbBlockToEncrypt - pbData != dwDataLen ){
			SetLastError( NTE_FAIL );
			return FALSE;
		}
	} else {
		// Pad the rest data and encrypt it.
		BYTE bFinalBlock[CRYPTBLOCK_BYTE_LEN];
		DWORD dwFinalDataLen = dwDataLen - (pbBlockToEncrypt - pbData);
		memcpy( bFinalBlock, pbBlockToEncrypt, dwFinalDataLen );
		memset( bFinalBlock + dwFinalDataLen, 0, CRYPTBLOCK_BYTE_LEN - dwFinalDataLen );
		// Encrypt data in proper and write it.
		encryptCBC( bFinalBlock, pKeyInfo->bKey, bCipherText, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
	}

	// Add IV.
	memcpy( pbBlockToWrite, bIV, CRYPTBLOCK_BYTE_LEN );
	pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;

	*pdwDataLen = pbBlockToWrite - pbData;
	return TRUE;

}



BOOL decryptGOST_CBC( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, DWORD *pdwDataLen, const BOOL bFinal ){

	KEY_CRYPT_INFO *pKeyInfo = (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	BYTE bPlainText[CRYPTBLOCK_BYTE_LEN];

	const DWORD dwDataLen = *pdwDataLen; //<Local copy of ciphertext size.

	if ( dwDataLen % CRYPTBLOCK_BYTE_LEN != 0  ){
		SetLastError( NTE_BAD_LEN );
		return FALSE;
	}

	
	BYTE* pbBlockToDecrypt = pbData; //< Next block to decrypt.
	const BYTE* pbLastBlockBegin = pbData + dwDataLen - CRYPTBLOCK_BYTE_LEN; 
	//< Last possible block to decrypt, actually convenient boundary for the while loop.
	
	BYTE* pbBlockToWrite = pbData; //< Block to which write decrypted data.
	BYTE* pbPrevCipherText = pbData;
	// In CBC mode process first block separately due to IV.
	if ( pKeyInfo->params.dwMode == GOST_CRYPT_CBC ){
		BYTE* bIV = pbData + dwDataLen - CRYPTBLOCK_BYTE_LEN;
		decryptCBC( pbBlockToDecrypt, pKeyInfo->bKey, bIV, bPlainText, pKeyInfo->params );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
		pbBlockToDecrypt += CRYPTBLOCK_BYTE_LEN;

	}	
	// Decrypt data block by block until exhaust.
	while( pbBlockToDecrypt <= pbLastBlockBegin ){
		//BYTE bTemp[CRYPTBLOCK_BYTE_LEN];
		//memcpy( bTemp, bCipherText, CRYPTBLOCK_BYTE_LEN );
		decryptCBC( pbBlockToDecrypt, pKeyInfo->bKey, pbPrevCipherText, bPlainText, pKeyInfo->params );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
		pbBlockToDecrypt += CRYPTBLOCK_BYTE_LEN;
	}
	if ( !bFinal ){
		if ( pbBlockToDecrypt - pbData != dwDataLen ){
			SetLastError( NTE_FAIL );
			return FALSE;
		}
	} else {
		// Pad the rest data and decrypt it.
		BYTE bFinalBlock[CRYPTBLOCK_BYTE_LEN];
		DWORD dwFinalDataLen = dwDataLen - (pbBlockToDecrypt - pbData);
		memcpy( bFinalBlock, pbBlockToDecrypt, dwFinalDataLen );
		memset( bFinalBlock + dwFinalDataLen, 0, CRYPTBLOCK_BYTE_LEN - dwFinalDataLen );
		// Decrypt data in proper and write it.
		decryptCBC( bFinalBlock, pKeyInfo->bKey, pbPrevCipherText, bPlainText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bPlainText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
	}

	*pdwDataLen = pbBlockToWrite - pbData;

	return TRUE;

}

BOOL encryptGOST( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, DWORD *pdwDataLen, const BOOL bFinal ){
	KEY_CRYPT_INFO *pKeyInfo = (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	switch( pKeyInfo->params.dwMode ){
		case GOST_CRYPT_ECB:
			encryptGOST_ECB( pProvCtx, pKey, pbData, pdwDataLen, bFinal );
			break;
		case GOST_CRYPT_CBC:
			encryptGOST_CBC( pProvCtx, pKey, pbData, pdwDataLen, bFinal );
			break;
		default:
			SetLastError( NTE_BAD_KEYSET_PARAM );
			return FALSE;
	}
}

BOOL decryptGOST( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, DWORD *pdwDataLen, const BOOL bFinal ){
	KEY_CRYPT_INFO *pKeyInfo = (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	switch( pKeyInfo->params.dwMode ){
		case GOST_CRYPT_ECB:
			decryptGOST_ECB( pProvCtx, pKey, pbData, pdwDataLen, bFinal );
			break;
		case GOST_CRYPT_CBC:
			decryptGOST_CBC( pProvCtx, pKey, pbData, pdwDataLen, bFinal );
			break;
		default:
			SetLastError( NTE_BAD_KEYSET_PARAM );
			return FALSE;
	}
}


/*
BOOL encryptGOST( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, const DWORD dwDataLen, const BOOL bFinal ){

	KEY_CRYPT_INFO *pKeyInfo = (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	DWORD dwLenToPad;
	BYTE bCipherText[CRYPTBLOCK_BYTE_LEN];
	
	if ( pKeyInfo->dwDataRestLen > 0 ){
		dwLenToPad = CRYPTBLOCK_BYTE_LEN - pKeyInfo->dwDataRestLen;
		if ( dwDataLen < dwLenToPad ){
			memcpy( pKeyInfo->bDataRest, pbData, dwDataLen );
			if ( !bFinal )
				return TRUE;
			else {
				// Pad the block with zero.
				memset( pKeyInfo->bDataRest + pKeyInfo->dwDataRestLen + dwDataLen, 0 , dwLenToPad - dwDataLen );
			}

		} else
			memcpy( pKeyInfo->bDataRest, pbData, dwLenToPad );
		encryptECB( pKeyInfo->bDataRest, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		pKeyInfo->dwDataRestLen = 0;
	}
	BYTE* pbBlockToEncrypt = pbData + dwLenToPad; //< Next block to encrypt.
	const BYTE* pbLastBlockBegin = pbData + dwDataLen - CRYPTBLOCK_BYTE_LEN; 
	//< Last possible block to encrypt, actually convenient boundary for the while loop.
	
	BYTE* pbBlockToWrite = pbData; //< Block to which write encrypted data.
	
	// Encrypt data block by block until exhaust.
	while( pbBlockToEncrypt <= pbLastBlockBegin ){
		BYTE bTemp[CRYPTBLOCK_BYTE_LEN];
		memcpy( bTemp, bCipherText, CRYPTBLOCK_BYTE_LEN );
		encryptECB( pbBlockToEncrypt, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bTemp, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
	}
	if ( !bFinal ){
		pKeyInfo->dwDataRestLen = dwDataLen - (pbBlockToEncrypt - pbData);
		memcpy( pKeyInfo->bDataRest, pbBlockToEncrypt, pKeyInfo->dwDataRestLen );
		// Write last encrypted block.
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
	} else {
		// Pad the rest data and encrypt it.
		BYTE bFinalBlock[CRYPTBLOCK_BYTE_LEN];
		DWORD dwFinalDataLen = dwDataLen - (pbBlockToEncrypt - pbData);
		memcpy( bFinalBlock, pbBlockToEncrypt, dwFinalDataLen );
		memset( bFinalBlock + dwFinalDataLen, 0, CRYPTBLOCK_BYTE_LEN - dwFinalDataLen );
		// Write last encrypted block.
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
		// Encrypt Data in proper and write it.
		encryptECB( bFinalBlock, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
	}

	return TRUE;

}

BOOL decryptGOST( PROV_CTX *pProvCtx, KEY_INFO *pKey, BYTE* pbData, const DWORD dwDataLen, const BOOL bFinal ){

	KEY_CRYPT_INFO *pKeyInfo = (KEY_CRYPT_INFO*) pKey->hKeyInformation;
	DWORD dwLenToPad;
	BYTE bCipherText[CRYPTBLOCK_BYTE_LEN];
	
	if ( pKeyInfo->dwDataRestLen > 0 ){
		dwLenToPad = CRYPTBLOCK_BYTE_LEN - pKeyInfo->dwDataRestLen;
		if ( dwDataLen < dwLenToPad ){
			memcpy( pKeyInfo->bDataRest, pbData, dwDataLen );
			if ( !bFinal )
				return TRUE;
			else {
				// Pad the block with zero.
				memset( pKeyInfo->bDataRest + pKeyInfo->dwDataRestLen + dwDataLen, 0 , dwLenToPad - dwDataLen );
			}

		} else
			memcpy( pKeyInfo->bDataRest, pbData, dwLenToPad );
		decryptECB( pKeyInfo->bDataRest, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		pKeyInfo->dwDataRestLen = 0;
	}
	BYTE* pbBlockToDecrypt = pbData + dwLenToPad; //< Next block to decrypt.
	const BYTE* pbLastBlockBegin = pbData + dwDataLen - CRYPTBLOCK_BYTE_LEN; 
	//< Last possible block to decrypt, actually convenient boundary for the while loop.
	
	BYTE* pbBlockToWrite = pbData; //< Block to which write decrypted data.
	
	// Encrypt data block by block until exhaust.
	while( pbBlockToDecrypt <= pbLastBlockBegin ){
		BYTE bTemp[CRYPTBLOCK_BYTE_LEN];
		memcpy( bTemp, bCipherText, CRYPTBLOCK_BYTE_LEN );
		decryptECB( pbBlockToDecrypt, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bTemp, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
	}
	if ( !bFinal ){
		pKeyInfo->dwDataRestLen = dwDataLen - (pbBlockToDecrypt - pbData);
		memcpy( pKeyInfo->bDataRest, pbBlockToDecrypt, pKeyInfo->dwDataRestLen );
		// Write last decrypted block.
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
	} else {
		// Pad the rest data and decrypt it.
		BYTE bFinalBlock[CRYPTBLOCK_BYTE_LEN];
		DWORD dwFinalDataLen = dwDataLen - (pbBlockToDecrypt - pbData);
		memcpy( bFinalBlock, pbBlockToDecrypt, dwFinalDataLen );
		memset( bFinalBlock + dwFinalDataLen, 0, CRYPTBLOCK_BYTE_LEN - dwFinalDataLen );
		// Write last decrypted block.
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
		pbBlockToWrite += CRYPTBLOCK_BYTE_LEN;
		// Encrypt Data in proper and write it.
		decryptECB( bFinalBlock, pKeyInfo->bKey, bCipherText, pKeyInfo->params );
		memcpy( pbBlockToWrite, bCipherText, CRYPTBLOCK_BYTE_LEN );
	}

	return TRUE;

}
*/