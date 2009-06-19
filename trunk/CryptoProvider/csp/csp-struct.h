
#ifndef _CSP_STRUCT_HEADER_FILE
#define _CSP_STRUCT_HEADER_FILE

typedef IppsBigNumState	PRIVATE_KEY;
typedef IppsECCPState	PUBLIC_KEY;

typedef struct _CONTAINER_IRZ {
	//HANDLE hToken; //<handle to the file containing key pair.
	CHAR szToken[200]; //<handle to the file containing key pair.
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
	BOOL bValueIsSet;				//< TRUE if value was loaded by CPSetHashParam.
} HASH_SERVICE_INFO;


#endif // _CSP_STRUCT_HEADER_FILE