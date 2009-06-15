
#ifndef _INI_HEADER_FILE
#define _INI_HEADER_FILE

#include <windows.h>

/*	\bried	Find section in INI file.
 *
 *	\param	hFile		handle of INI file to be scaned.
 *	\param	szSection	section to be looked up.
 *
 *	\return TRUE if section found, FALSE otherwise.
 *
 *	\ingroup INIFiles
 */
BOOL iniGetSection(HANDLE hFile, LPSTR szSection );

/*	\bried	Look up for a key in INI file and read value 
 *		assosiated with ths key in case of success. 
 *		The function removes leading and trailing spaces.
 *
 *	\param	hFile		handle of INI file to be scaned.
 *	\param	szSection	section to be looked up for a key.
 *	\param	szKey		key to be looked up within szSection.
 *	\param	szValue		buffer to store value assosiated with the key.
 *	\param	pdwValLen	adress storing length of supplied buffer szValue,
 *							and to store upon succeed actual data copyed length.
 *
 *	\return TRUE if key found and buffer was length enough to store the one,
 *			FALSE otherwise.
 *	\return szValue = NULL if value is not defined in INI file (E.G. 'key=<empty>')
 *
 */
BOOL iniGetString(HANDLE hFile,
				   LPSTR szSection,
				   LPSTR szKey, 
				   LPSTR szValue, 
				   DWORD* pdwValLen );

/*	\bried	Write down a key and assosiated key value in INI file. 
 *		The function removes leading and trailing spaces.
 *
 *	\param	hFile		handle of INI file to write.
 *	\param	szSection	section to write a key.
 *	\param	szKey		key to write within szSection.
 *	\param	szValue		buffer containing value assosiated with the key.
 *
 *	\return TRUE if key has been written down,
 *			FALSE otherwise.
 *	\return szValue = NULL if value is not defined in INI file (E.G. 'key=<empty>')
 *
 */
BOOL iniSetString(HANDLE hFile,
				   LPSTR szSection,
				   LPSTR szKey, 
				   LPSTR szValue);

#endif