
#ifndef _CSPSERVICES_HEADER_FILE
#define _CSPSERVICES_HEADER_FILE

#include <windows.h>
#include "csp.h"
#include "rand/rand.h"
#include "csp-helpers.h"
#include "csp-struct.h"



/*	\brief Open a container with the name szContainer.
 *	
 *	\param	pProvCtx	pointer to the CSP context.
 *	\param	szContainer	name of the container to open
 *
 *	\return	TRUE if open succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL OpenContainer( PROV_CTX* pProvCtx, LPCSTR szContainer );

/*	\brief release the container context.
 *	
 *	\param	pProvCtx	pointer to the CSP context.
 *
 *	\return	TRUE if release succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL releaseContainer( PROV_CTX *pProvCtx );

/*	\brief	Generate public/private key pair
 *	
 *	\param	pProvCtx	pointer to the CSP context.
 *	\param	pKey		pointer to the key context to store 
 *						the generated key pair.
 *
 *	\return	TRUE if generation succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL genKeyPair( PROV_CTX* pProvCtx, KEY_INFO* pKey );

/*	\brief	Gets a key length by ALG_ID
 *	
 *	\param	algid	ALG_ID of a key.
 *
 *	\return	Key length in bites without 
 *		any additional information (context)
 *		E.G. 256 for GOST R 34.10-2001 
 *
 */
DWORD getKeyLen( ALG_ID algid );

/*	\brief	Create the key context.
 *	
 *	\param	pProvCtx	Pointer to the a CSP context.
 *	\param	pKey		pointer to pointer to key to release.
 *
 *	\return	TRUE if release succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL createKey( PROV_CTX *pProvCtx, KEY_INFO **pKey );

/*	\brief	Release the key context.
 *	
 *	\param	pProvCtx	Pointer to the a CSP context.
 *	\param	pKey		Key to release.
 *
 *	\return	TRUE if release succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL releaseKey( PROV_CTX *pProvCtx, KEY_INFO *pKey );

/*	\brief	Get public key len with all additional context to be exported.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pKey		pointer to a public key.
 *	\param	pdwLen		pointer to adress where length will be stored.
 *
 *	\return	TRUE if length has been got, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL getPubKeyLen( PROV_CTX *pProvCtx, KEY_INFO *pKey, DWORD *pdwLen );

/*	\brief	Export the public key from the key.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pKey		pointer to the key to import.
 *	\param	pbData		buffer data to store the exported key.
 *	\param	pdwDataLen	upon succeed export contains actual 
		length of exported data, 0 otherwise.
 *
 *	\return	TRUE if export succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL exportPubKey(IN PROV_CTX* pProvCtx,
			 IN KEY_INFO* pKey,
			 OUT BYTE* pbData,
			 OUT DWORD* pdwDataLen );

/*	\brief	Import a public key from key data.
 *	
 *	\param	pProvCtx	pointer to the CSP context.
 *	\param	pKey		pointer to the key to import.
 *	\param	pbData		key data to be imported.
 *	\param	dwDataLen	key data length.
 *
 *	\return	TRUE if import succeeded, FALSE otherwise;
 *		more in last error
 *
 */
BOOL importPubKey(PROV_CTX* pProvCtx,
			 KEY_INFO* pKey,
			 BYTE* pbData,
			 DWORD dwDataLen );

/*	\brief	Sign the hash using container's key.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pbHashValue	buffer containing pure hash with no context.
 *	\param	dwHashSize	size of the buffer pbHashValue.
 *	\param	pUserKey	user key (should contain private).
 *	\param	pbSignature buffer where signature will be stored.
 *	\param	pcbSigLen	pointer to address where actual signature 
 *							length in bytes will be stored.
 *
 *	\return	TRUE if signing succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL signHash(PROV_CTX *pProvCtx, 
		 BYTE* pbHashValue,
		 DWORD dwHashSize,
		 KEY_INFO *pKey,
		 BYTE* pbSignature,
		 DWORD* pcbSigLen );

/*	\brief	Verify the hash with respect to given public key.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pbHashValue	buffer containing pure hash with no context.
 *	\param	dwHashSize	size of the buffer pbHashValue.
 *	\param	pPubKey		public key to verify the signature.
 *	\param	pbSignature buffer where signature is stored.
 *
 *	\return	TRUE if verifying succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL verifyHash(PROV_CTX *pProvCtx,
		   BYTE* pbHashValue, 
		   DWORD dwHashSize, 
		   KEY_INFO *pPubKey, 
		   const BYTE* pbSignature, 
		   DWORD cbSigLen );

/*	\brief	Generate random data of requested length.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	dwLen		required random data len.
 *	\param	pbData		buffer to store generated data.
 *
 *	\return	TRUE if generation succeeded, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL genRandom(PROV_CTX *pProvCtx, 
		  DWORD dwLen,
		  BYTE* pbData );

/*	\brief	Create hash context.
 *
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	ppHash		pointer to the (pointer to the) Hash context.
 *
 *	\return	TRUE if hash has been created, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL createHash(PROV_CTX* pProvCtx, HASH_INFO** ppHash );

/*	\brief	Feed to a hash data block.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pHash		Hash context.
 *	\param	pbData		data block to feed.
 *	\param	cbDataLen	length of pbData.
 *
 *	\return	TRUE if data has been feeded, FALSE otherwise;
 *		more in last error.
 *	
 */
BOOL updateHash(PROV_CTX *PRpProvCtx,
				HASH_INFO *pHash,
				const BYTE *pbData,
				DWORD cbDataLen );

/*	\brief	Finilize and get hash value.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pHash		Hash context.
 *	\param	pbHashValue	buffer where hash value will be stored.
 *	\param	pcbDataLen	address where hash len will be stored.
 *
 *	\return	TRUE if data has been feeded, FALSE otherwise;
 *		more in last error.
 *	
 */
BOOL getHash( PROV_CTX *pProvCtx,
				HASH_INFO *pHash,
				BYTE *pbHashValue,
				DWORD *pcbHashLen );

/*	\brief	Set the hash value in hash object context.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pHash		pointer to hash context.
 *	\param	pbHashValue	value of a hash to be set.
 *
 *	\return	TRUE if hash has been set, FALSE otherwise;
 *		more in last error.
 *
 */
BOOL setHash( PROV_CTX* pProvCtx, HASH_INFO *pHash, const BYTE *pbHashValue);

/*	\brief	release hash object service information but leave the HASH_INFO object.
 *	
 *	\param	pProvCtx	pointer to a CSP context.
 *	\param	pHash		Hash context.
 *
 *	\return	TRUE if data has been feeded, FALSE otherwise;
 *		more in last error.
 *	
 */
BOOL releaseHash( PROV_CTX *pProvCtx,
				HASH_INFO *pHash );

/*	\brief	Read user (signature) key  from container.
 *	
 *	\param	pProvCtx	pointer to the CSP context.
 *	\param	pKey		address where the key will be stored.
 *
 *	\return	TRUE if key obtained, FALSE otherwise;
 *		more in last error
 *
 */
BOOL getUserKey( PROV_CTX *pProvCtx, KEY_INFO *pKey );

#endif //_CSPSERVICES_HEADER_FILE