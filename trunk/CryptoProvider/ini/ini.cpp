
#include "ini.h"


#include <windows.h>
#include <cstdio>

const DWORD MAX_FILE_SIZE = 1024*1024;

BOOL iniGetString(HANDLE hFile,
				  LPSTR szSection,
				  LPSTR szKey, 
				  LPSTR szValue, 
				  DWORD* pdwValLen ){

	LPSTR szData = NULL;//< EKEY.INI file content.
	DWORD dwBufLen = *pdwValLen;
	*pdwValLen = 0;
	// Get the file size.
	DWORD dwFileSize = GetFileSize(hFile, NULL );

	if ( dwFileSize > MAX_FILE_SIZE )
		return FALSE;

	SetFilePointer( hFile, 0, 0, FILE_BEGIN );
	// Get the file content.
	szData = new CHAR[dwFileSize];
	if ( !ReadFile( hFile, szData, dwFileSize, &dwFileSize, NULL ) ){
		SetLastError( NTE_KEYSET_ENTRY_BAD );
		delete[] szData;
		return FALSE;		
	}

	// Look up for szSection.
	CHAR szFormated[100];//<contains section name with square bracket
		// E.G. [section]
	sprintf( szFormated, "[%s]", szSection );
	LPSTR szSecBegin = strstr( szData, szFormated );
	if ( szSecBegin == NULL ){
		delete[] szData;
		return FALSE;		
	} else {
		szSecBegin += strlen( szFormated ) + strlen("\n");
	}
	LPSTR szSecEnd = strchr( szSecBegin, '[' );
	if ( szSecEnd == NULL ){
		szSecEnd = szSecBegin + strlen( szSecBegin );
	}
	// Look up for szKey 
	sprintf( szFormated, "%s=", szKey );
	LPSTR szKeyPos = strstr( szSecBegin, szFormated );
	LPSTR szValBegin = NULL;
	LPSTR szValEnd = NULL;
	if ( szKeyPos == NULL ){
		delete[] szData;
		return FALSE;		
	} 
	if ( szKeyPos > szSecEnd ){
		delete[] szData;
		return FALSE;
	} else {
		szValBegin = szKeyPos + strlen( szFormated );
	}
	// locate the key value
	szValEnd = strchr( szValBegin, '\n' );
	if ( szValEnd == NULL ){
		delete[] szData;
		return FALSE;
	}
	DWORD dwLen = szValEnd - szValBegin-1;
	if ( dwLen > dwBufLen ){
		delete[] szData;
		return FALSE;
	}
	// read the key value
	memcpy( szValue, szValBegin, dwLen );
	*pdwValLen = dwLen;
	return TRUE;	
}

