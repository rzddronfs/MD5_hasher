/******************************************************************************/
#define NDEBUG
/******************************************************************************/
#include <stdio.h>
#include <assert.h>
#include <Windows.h>
#include <Wincrypt.h>
#pragma hdrstop
/******************************************************************************/

#define READ_BLOCK_SIZE 4096 /* Bytes. */
#define MD5_LEN 16 /* Bytes. */

/******************************************************************************/
char * GetSrcPath( int argc, char* argv[] )
/******************************************************************************/
{
  char * szResult = NULL;

  if( argc > 1 )
  {
    szResult = argv[1];
  }

  return szResult;
}

/******************************************************************************/
int GetFirstErrno( int argc, ... )
/******************************************************************************/
{
  int iResult = (int) ERROR_INTERNAL_ERROR;

  va_list ap;
  va_start(ap, argc);

  int iIdx = 0;
  int iErrno = 0;
  while( iIdx < argc && iErrno == 0 )
  {
    iErrno = va_arg(ap,int);
    iResult = iErrno;
    ++iIdx;
  }

  va_end(ap);

  return iResult;
}

#pragma argsused
/******************************************************************************/
int main( int argc, char* argv[] )
/******************************************************************************/
{
  char * szPath = GetSrcPath( argc, argv );   assert( szPath != NULL );

  FILE * hFile = fopen( szPath, "rb" );   assert( hFile != NULL );

  BOOL fFileOpened = ( hFile != NULL );

  HCRYPTPROV hProv = NULL;
  {
    LPCTSTR pszContainer = NULL;
    LPCTSTR pszProvider = MS_DEF_PROV;
    DWORD dwProvType = PROV_RSA_FULL;
    DWORD dwFlags = CRYPT_VERIFYCONTEXT;

    BOOL fContextAcquired = CryptAcquireContext( & hProv, pszContainer, pszProvider, dwProvType, dwFlags );  assert( fContextAcquired );
  }
    DWORD dwGetContextError = GetLastError();

  HCRYPTHASH hHash = NULL;
  {
    ALG_ID Algid = CALG_MD5;
    HCRYPTKEY hKey = 0;
    DWORD dwFlags = 0;

    BOOL fHashCreated = CryptCreateHash( hProv, Algid, hKey, dwFlags, & hHash );    assert( fHashCreated );
  }
    DWORD dwHashCreateError = GetLastError();

  BYTE abData[ READ_BLOCK_SIZE ];

    assert( !feof( hFile ) );

  DWORD dwHashFragmentError = ERROR_SUCCESS;

  while( fFileOpened && !feof( hFile ) )
  {
    long lOffset = ftell( hFile );    assert( errno == 0 );
    size_t nBlkRead = fread( abData, sizeof( abData ), 1, hFile );    assert( nBlkRead == 1 || lOffset > 0 );

    DWORD dwDataLen = sizeof( abData );

    if( nBlkRead == 0 )
    {
      int iSeekErr = fseek( hFile, lOffset, SEEK_SET	);  assert( iSeekErr == 0 );
      nBlkRead = fread( abData, 1, sizeof( abData ), hFile );    assert( nBlkRead > 0 );
      dwDataLen = nBlkRead;
    }

    DWORD dwFlags = 0;

    BOOL fDataAdded = CryptHashData( hHash, abData, dwDataLen, dwFlags );   assert( fDataAdded );

    if( dwHashFragmentError == 0 )
      dwHashFragmentError = GetLastError();
  }

  BYTE abHash[ MD5_LEN ];
  {
    DWORD dwParam = HP_HASHVAL;
    DWORD dwDataLen = MD5_LEN;
    DWORD dwFlags = 0;

    BOOL fHashRetrived = CryptGetHashParam( hHash, dwParam, abHash, & dwDataLen, dwFlags );   assert( fHashRetrived );
  }
    DWORD dwGetHashError = GetLastError();

  if( fHashRetrived )
   printf(
    "\nFile: %s, MD5: %.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x"
    "\n",
    szPath,
    abHash[ 0 ],
    abHash[ 1 ],
    abHash[ 2 ],
    abHash[ 3 ],
    abHash[ 4 ],
    abHash[ 5 ],
    abHash[ 6 ],
    abHash[ 7 ],
    abHash[ 8 ],
    abHash[ 9 ],
    abHash[ 10 ],
    abHash[ 11 ],
    abHash[ 12 ],
    abHash[ 13 ],
    abHash[ 14 ],
    abHash[ 15 ]
   );

  BOOL fHashReleased = CryptDestroyHash( hHash );   assert( fHashReleased );

  {
    DWORD dwFlags = 0;

    BOOL fCtxtReleased = CryptReleaseContext( hProv, dwFlags );   assert( fCtxtReleased );
  }

  int iCloseErr = fclose( hFile );    assert( iCloseErr == 0 );

  DWORD dwWinErrno = GetFirstErrno(
    4,
    dwGetContextError,
    dwHashCreateError,
    dwHashFragmentError,
    dwGetHashError
  );

  if( szPath == NULL )
  {
    printf(
      "\n(c) Andrew Minenkov, 2012."
      "\n\tThe program calculates MD5 hash for the given file."
      "\n\tUsage: Hasher <filename>"
      "\n"
    );
  }
  else
  {
    if( errno != 0 )
      perror( "\nStdlib error" );
    if( dwWinErrno != 0 )
      fprintf( stderr, "\n The hashing failed with error: (%d)", dwWinErrno );
  }

  return errno;
}
//---------------------------------------------------------------------------
