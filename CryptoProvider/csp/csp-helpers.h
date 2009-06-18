
#ifndef _CSP_HELPERS_HEADER_FILE
#define _CSP_HELPERS_HEADER_FILE

#include "rand/rand.h"
#include <windows.h>
#include "gost/params.h"
#include "ecc/ecc.h"
#include "constants.h"

typedef IppsBigNumState	PRIVATE_KEY;
typedef IppsECCPState	PUBLIC_KEY;

/*	\brief Convert private key to string representation.
 *	
 *	\param pPrKey	- private key.
 *	\param szPrKey	- buffer to store the private key 
 *								string representation.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function DOES NOT allocate memory.
 *
 */
BOOL privateKeyToString( const PRIVATE_KEY *pPrKey, LPSTR szPrKey );

/*	\brief Convert public key to string representation.
 *	
 *	\param pPubKey	- public key.
 *	\param szPubKey	- buffer to store the public key 
 *								string representation.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function DOES NOT allocate memory.
 *
 */
BOOL pubKeyToString( const PUBLIC_KEY *pPubKey, LPSTR szPubKey );

/*	\brief Extract PURE public key from PUBLIC_KEY struc.
 *	
 *	\param pPubKey		- public key.
 *	\param pbData		- buffer to store the public key.
 *	\param pdwDataLen	- contains length of supplied buffer, 
 *							upon succeed contains number of copied bytes.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function DOES NOT allocate memory.
 *
 */
BOOL extractPublicKey( const PUBLIC_KEY *pPubKey, BYTE *pbData, DWORD *pdwDataLen );

/*	\brief Derive PUBLIC_KEY struc from key DATA.
 *	
 *	\param pPubKey		- adress where to allocate memory and place the public key.
 *	\param pbData		- buffer containing the pure public key data.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function ALLOCATES memory.
 *
 */
BOOL derivePubKey( PUBLIC_KEY *&pPubKey, const BYTE *pbData );

/*	\brief Derive PUBLIC_KEY struc from key STRING.
 *	
 *	\param pPubKey		- adress where to allocate memory and place the public key.
 *	\param szKey		- string containing the pure hex-encoded public key.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function ALLOCATES memory.
 *
 */
BOOL derivePubKey( PUBLIC_KEY *&pPubKey, const LPSTR szKey );

/*	\brief Derive PRIVATE_KEY struc from key DATA.
 *	
 *	\param pPrKey		- adress where to allocate memory and place the private key.
 *	\param pbData		- buffer containing the pure public key data.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function ALLOCATES memory.
 *
 */
BOOL derivePrivateKey( PRIVATE_KEY *&pPrKey, const BYTE *pbData );

/*	\brief Derive PRIVATE_KEY struc from key STRING.
 *	
 *	\param pPrKey		- adress where to allocate memory and place the private key.
 *	\param szKey		- string containing the pure hex-encoded public key.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function ALLOCATES memory.
 *
 */
BOOL derivePrivateKey( PRIVATE_KEY *&pPrKey, const LPSTR szKey );

/*	\brief Generate key pair.
 *	
 *	\param pPubKey		- public key.
 *	\param pbData		- buffer to store the public key.
 *	\param pdwDataLen	- contains length of supplied buffer, 
 *							upon succeed contains number of copied bytes.
 *
 *	\return TRUE if conversation and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function DOES NOT allocate memory.
 *
 */
BOOL genKeyPair( PUBLIC_KEY *&pPubKey, PRIVATE_KEY *&pPrKey, const PARAMS_GOST_SIGN &params, Rand &rand );


/*	\brief Sign the hash.
 *	
 *	\param	pbHash		- pure hash (with no context).
 *	\param	pPrKey		- private key struct.
 *	\param	pbSignature	- buffer to store the signature.
 *	\param	params		- signature params.
 *	\params	rand		- random number generator.
 *
 *	\return TRUE if signing and storing succeeded,
 *			FALSE otherwise.
 *
 *	\note	The function DOES NOT allocate memory.
 *
 */
BOOL sign( const BYTE* pbHash, const PRIVATE_KEY *pPrKey, BYTE *pbSignature, const PARAMS_GOST_SIGN &params, Rand &rand );

/*	\brief Sign the hash.
 *	
 *	\param	pbHash		- pure hash (with no context).
 *	\param	pPubKey		- public key for verifying.
 *	\param	pbSignature	- buffer to store the signature.
 *	\param	params		- signature params.
 *
 *	\return TRUE if the signature is valid.
 *			FALSE otherwise.
 *
 *	\note	The function DOES NOT allocate memory.
 *
 */
BOOL verify( const BYTE* pbHash, const PUBLIC_KEY *pPubKey, const BYTE *pbSignature, const PARAMS_GOST_SIGN &params);

/*	\brief Generate random data of requested length.
 *	
 *	\param	dwLen		- length of random data in bytes.
 *	\param	pbData		- buffer to store the random data.
 *	\param	rand		- Random number generator (PRNG).
 *	\param	params		- signature params.
 *
 *	\return TRUE if the data was generated.
 *			FALSE otherwise.
 *
 *	\note	The function DOES NOT allocate memory.
 *
 */
BOOL genRandom( const DWORD dwLen, BYTE* pbData, Rand &rand );

////////////////////////////////////////////////////////////////////////////////////////////////
///////////																	////////////////////
///////////					INLINE FUNCTION IMPLEMENTATION					////////////////////
///////////																	////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////


inline BOOL privateKeyToString( const PRIVATE_KEY *pPrKey, LPSTR szPrKey ){
	return bnConvertToString( pPrKey, szPrKey );
}

inline BOOL pubKeyToString( const PUBLIC_KEY *pPubKey, LPSTR szPubKey ){
	eccPointToString( (const IppsECCPPointState*)pPubKey, szPubKey );
	return TRUE;
}

inline BOOL extractPublicKey( const PUBLIC_KEY *pPubKey, BYTE *pbData ){
	eccPointToOctet( (const IppsECCPPointState*)pPubKey, pbData );
	return TRUE;
}

inline BOOL derivePubKey( PUBLIC_KEY *&pPubKey, const BYTE *pbData ){
	DWORD dwParamSet = *LPDWORD( pbData + PUBLICKEY_BYTE_LEN );
	PARAMS_GOST_SIGN params( dwParamSet );
	pPubKey = (PUBLIC_KEY*) eccPointNew( pbData, PUBLICKEY_BYTE_LEN, params.pECC );
	if ( pPubKey != NULL )
		return TRUE;
	else
		return FALSE;
}

inline BOOL genKeyPair( PUBLIC_KEY **ppPubKey, PRIVATE_KEY **ppPrKey, const PARAMS_GOST_SIGN *pParams, Rand *pRand ){
	return genKeyPair( 
		(IppsECCPPointState**)	ppPubKey,
		(IppsBigNumState**)		ppPrKey,
								pParams, 
								pRand);
		
}


inline BOOL sign( const BYTE* pbHash,
				 const PRIVATE_KEY *pPrKey,
				 BYTE *pbSignature,
				 const PARAMS_GOST_SIGN &params,
				 Rand &rand )
{
	 sign(
		pbHash,
		(const IppsBigNumState*) pPrKey,
		pbSignature,
		&params,
		rand );
	 return TRUE;
}


inline BOOL verify( 
			const BYTE* pbHash, 
			const PUBLIC_KEY *pPubKey,
			const BYTE *pbSignature,
			const PARAMS_GOST_SIGN &params)
{
	return verify(
		pbHash,
		(const IppsECCPPointState*) pPubKey,
		pbSignature,
		&params);		
}

inline BOOL derivePrivateKey( PRIVATE_KEY *&pPrKey, const LPSTR szKey ){
	pPrKey = (PRIVATE_KEY*) bnNew( szKey, iBNSize );
	if ( pPrKey != NULL )
		return TRUE;
	else 
		return FALSE;
}

inline BOOL genRandom( const DWORD dwLen, BYTE* pbData, Rand &rand ){

	IppsBigNumState *pBN = rand( dwLen );
	IppStatus res = ippsGetOctString_BN( pbData, dwLen, pBN );
	if ( res != ippStsNoErr )
		return FALSE;
	return TRUE;
}

#endif //_CSP_HELPERS_HEADER_FILE