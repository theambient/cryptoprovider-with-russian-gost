
#ifndef _CSP_STRUCT_HEADER_FILE
#define _CSP_STRUCT_HEADER_FILE

typedef IppsBigNumState	PRIVATE_KEY;
typedef IppsECCPState	PUBLIC_KEY;

typedef struct _CONTAINER_IRZ {
	CHAR szToken[200];				//< handle to the file containing key pair.
	CHAR szUserID[20];				//< user ID, can be found under [IDENT] section of EKEY.INI.
	Rand rand;
} CONTAINER_IRZ;

typedef struct _KEY_SIGN_INFO {
	PUBLIC_KEY *pPubKey;			//< Public key.
	PRIVATE_KEY *pPrKey;			//< Private key.
	PARAMS_GOST_SIGN params;		//< Key params.
} KEY_SIGN_INFO;

typedef struct _KEY_CRYPT_INFO {
	BYTE bKey[CRYPTKEY_BYTE_LEN];	//< simmetric key 256 bits length.
	//BYTE bDataRest[CRYPTBLOCK_BYTE_LEN]; //< contains the last block of not encrypted data 
										// if data length are not divisable by CRYPTBLOCK_BYTE_LEN.
	//DWORD dwDataRestLen;			//< actual length of bDataRest.
	PARAMS_GOST_CRYPT params;		//< Key params.
} KEY_CRYPT_INFO;

typedef struct _HASH_SERVICE_INFO {
	BYTE bDataHashed[HASH_BYTE_LEN];//< contains already hashed data, var H from GOST.
	BYTE bDataRest[HASH_BYTE_LEN];	//< contains the rest of data from last feeding (updateHash)
									//		if feeded data len is not multiple of HASH_BYTE_LEN.
	BYTE bSum[HASH_BYTE_LEN];		//< the control sum of hashing data, var $\Sigma$ from GOST.
	BYTE bLen[HASH_BYTE_LEN];		//< the control length of hashing Data, var L from GOST.
	DWORD dwDataRestLen;			//< actual length of bDataRest.
	BOOL bValueIsSet;				//< TRUE if value was loaded by CPSetHashParam.
} HASH_SERVICE_INFO;


#endif // _CSP_STRUCT_HEADER_FILE