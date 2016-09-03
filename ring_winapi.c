/* 
Extension Name : Ring WIN APIs
Ext. Purpose : Its an easy bridge for ring developers to use WIN APIs
               Its just a transparent mirror that should bring all of WIN API functionality into RING
			   
Ext. Rules : There are some rules that have been followed in here to make this library neat, clean and understandable
1) Locally used functions should be defined at the beginning at the section of "Locally used functions"
2) There are two types of this library functions as follow:
	1 - Totally WIN API mirroring Functions : these needs to be named following their Original names preceded by 'r' as "rShellExecute()"
		This will make it easier for developers to seek the documentation of their original functions
	2 - Functions that has special purpose depending on WIN APIs like "rwaElevate()"
		This type of functions is better to be preceded by 'rwa' (short for RING WIN APIs) as this will
		a make it kind of native and in the same time distinguish it from the other type of functions
3) There's no rule in specifying locally used functions names but it will be nice to have some native touch
4) Each function has to be registered using the function of registration at the end of this library (This is an essential ring extensions rule)

                Enjoy :)

									Copyright (c) 2016 
*/


#include "ring.h"
#include "windows.h"
#include "Sddl.h"		// added to get User SID by ConvertSidToStringSid()


/*
===================================================================================== 
							Locally used functions
		Note: These functions have to be at the beginning of this library
=====================================================================================
*/


/*
Function Name : GetErrorMsg
Func. Purpose : Return System error message
Func. Auther  : Majdi Sobain <MajdiSobain@Gmail.com>
*/
LPSTR rwaGetErrorMsg(LONG ErrorId , LPSTR pMsg, size_t pMsgsize){
    LPSTR pBuffer = NULL;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, 
                  ErrorId,
				  // if next para set to zero the msg will be according to the user's locale
                  MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                  (LPSTR)&pBuffer, 
                  0, 
                  NULL);
    if (pBuffer)
    {
		sprintf_s(pMsg, pMsgsize, "Error ID (%d) : %s", ErrorId, pBuffer);
		HeapFree(GetProcessHeap(), 0, pBuffer);
     }
    else
    {
		sprintf_s(pMsg, pMsgsize, "Format message failed with : %d", GetLastError());
    } 
	return pMsg;
}

/* 
===================================================================================== 
=====================================================================================
*/



//------------------------------------------------------------------------------------



/*===================================================================================
                             Library Functions
===================================================================================*/


/*
Function Name : rwaIsRunAsAdmin
Func. Purpose : Check whether this process (ring.exe) is running as administrator or not
Func. Params  : () Nothing
Func. Return  : True or False
Func. Auther  : Majdi Sobain <MajdiSobain@Gmail.com>
Func. Source  : Created with help from SpaceWorm's post at http://www.cplusplus.com/forum/windows/101207/
*/
RING_FUNC(ring_winapi_rwaisrunasadmin) {
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	
	if ( RING_API_PARACOUNT != 0 ) {
		RING_API_ERROR("Error: No parameters are needed in this method");
		return ;
	}
  
    if (!AllocateAndInitializeSid(
        &NtAuthority, 
        2, 
        SECURITY_BUILTIN_DOMAIN_RID, 
        DOMAIN_ALIAS_RID_ADMINS, 
        0, 0, 0, 0, 0, 0, 
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:

    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    if (ERROR_SUCCESS != dwError)
    {
		char errmsg[200];
		RING_API_ERROR(rwaGetErrorMsg(GetLastError(),errmsg,200));
		RING_API_RETNUMBER(0);
		return;
    }

    RING_API_RETNUMBER(fIsRunAsAdmin);
	return;
}



/*
Function Name : rwaElevate
Func. Purpose : Elevate to ask administrator rights for the process
Func. Params  : Either (String exepath) for running a particular app as administrator
				/Or/   (String exepath, String params) to run a particular app with some parameters
Func. Return  : Nothing
Func. Auther  : Majdi Sobain <MajdiSobain@Gmail.com>
Func. Source  : Created with help from SpaceWorm's post at http://www.cplusplus.com/forum/windows/101207/
*/
RING_FUNC(ring_winapi_rwaelevate) {
	if ( RING_API_PARACOUNT != 1 && RING_API_PARACOUNT != 2 ) {
		RING_API_ERROR("Error: Bad parameter count, this function expects one\\two parameters");
		return ;
	}
	if ( RING_API_PARACOUNT == 1 ) {
		if ( RING_API_ISSTRING(1) ) {
			SHELLEXECUTEINFOA sei = { sizeof(sei) };
			sei.lpVerb = "runas";
			sei.lpFile = RING_API_GETSTRING(1);
			sei.hwnd = NULL;
			sei.nShow = SW_NORMAL;
			if (!ShellExecuteExA(&sei)) {
				char errmsg[200];
				RING_API_ERROR(rwaGetErrorMsg(GetLastError(),errmsg,200));
			}
		} else RING_API_ERROR(RING_API_BADPARATYPE);
	} else {
		if ( RING_API_ISSTRING(1) && RING_API_ISSTRING(2) ) {
			SHELLEXECUTEINFOA sei = { sizeof(sei) };
			sei.lpVerb = "runas";
			sei.lpFile = RING_API_GETSTRING(1);
			sei.lpParameters = RING_API_GETSTRING(2);
			sei.hwnd = NULL;
			sei.nShow = SW_NORMAL;
			if (!ShellExecuteExA(&sei)) {
				char errmsg[200];
				RING_API_ERROR(rwaGetErrorMsg(GetLastError(),errmsg,200));
			}
		} else RING_API_ERROR(RING_API_BADPARATYPE);
	}
	return;
}



/*
Function Name : rShellExecute
Func. Purpose : Execute\Open an application or file with specific action
Func. Params  : (HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)
Func. Return  : the value that returned by ShellExecute() function
Func. Auther  : Majdi Sobain <MajdiSobain@Gmail.com>
*/
RING_FUNC(ring_winapi_rshellexecute) {
	HWND hwnd = NULL;
	LPCSTR lpOperation = NULL;
	LPCSTR lpFile = NULL;
	LPCSTR lpParameters = NULL;
	LPCSTR lpDirectory = NULL;
	INT nShowCmd = 0;
	int lresult;
	if ( RING_API_PARACOUNT != 6 ) {
		RING_API_ERROR("Error: Bad parameter count, this function expects six parameters");
		return ;
	}
	if ( !RING_API_ISSTRING(1) && !RING_API_ISPOINTER(1) ) {
		RING_API_ERROR("Error: The first (hwnd) parameter should be either HWND pointer or NULL");
		return ;
	} else {
		if ( RING_API_ISSTRING(1) ) {
			if ( strcmp(RING_API_GETSTRING(1), "") ) {
				RING_API_ERROR("Error: The first (hwnd) parameter should be either HWND pointer or NULL");
				return ;
			}
		}
		if ( RING_API_ISPOINTER(1) ) {
			hwnd = (HWND) RING_API_GETCPOINTER(1, "HWND");
		}
	}
	if ( !RING_API_ISSTRING(2) ) {
		RING_API_ERROR("Error: The second (lpOperation) parameter should be String or NULL");
		return ;
	} else {
		if ( strcmp(RING_API_GETSTRING(2), "") ) lpOperation = RING_API_GETSTRING(2);
	}
	if ( !RING_API_ISSTRING(3) ) {
		RING_API_ERROR("Error: The third (lpFile) parameter should be String or NULL");
		return ;
	} else {
		if ( strcmp(RING_API_GETSTRING(3), "") ) lpFile = RING_API_GETSTRING(3);
	}
	if ( !RING_API_ISSTRING(4) ) {
		RING_API_ERROR("Error: The fourth (lpParameters) parameter should be String or NULL");
		return ;
	} else {
		if ( strcmp(RING_API_GETSTRING(4), "") ) lpParameters = RING_API_GETSTRING(4);
	}
	if ( !RING_API_ISSTRING(5) ) {
		RING_API_ERROR("Error: The fifth (lpDirectory) parameter should be String or NULL");
		return ;
	} else {
		if ( strcmp(RING_API_GETSTRING(5), "") ) lpDirectory = RING_API_GETSTRING(5);
	}
	if ( !RING_API_ISNUMBER(6) ) {
		RING_API_ERROR("Error: The sixth (nShowCmd) parameter should be numerical flag");
		return ;
	} else nShowCmd = RING_API_GETNUMBER(6);
	lresult = (int) ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
	RING_API_RETNUMBER(lresult);
	return;
}



/*
Function Name : rwaIsWow64Process
Func. Purpose : Check whether this process (ring.exe) is a Wow64 process or not
Func. Params  : () Nothing
Func. Return  : (1) if True or (0) if False or (-1) if function failed
Func. Auther  : Majdi Sobain <MajdiSobain@Gmail.com>
*/
RING_FUNC(ring_winapi_rwaiswow64process) {
	PBOOL IsWOW = (PBOOL) malloc(sizeof(BOOL));
	if ( RING_API_PARACOUNT != 0 ) {
		RING_API_ERROR("Error: No parameters are needed in this method");
		return ;
	}
	assert(IsWOW);
	if (IsWow64Process(GetCurrentProcess(),IsWOW)) { 
		if (IsWOW[0]) {
			free(IsWOW); 
			RING_API_RETNUMBER(1);
			return; 
		} else {
			free(IsWOW); 
			RING_API_RETNUMBER(0);
			return; 
		}
	} else {
		free(IsWOW); 
		RING_API_RETNUMBER(-1);
		return; 
	}
}



/*
Function Name : rwaUserSID
Func. Purpose : Return User SID
Func. Params  : Either (HANDLE handle) of a process /Or/ () Nothing for the current process
Func. Return  : User SID in a string format
Func. Auther  : Majdi Sobain <MajdiSobain@Gmail.com>
Func. Source  : Created with help from Rose's post at http://www.codeexperts.com/showthread.php?1220-Getting-a-user-SID-in-term-of-string-from-a-process-handle-process-id
*/
RING_FUNC(ring_winapi_rwausersid) { 
	BOOL bResult = FALSE ;
	char szUserSID[1024];
	HANDLE hTokenHandle = NULL ;
	HANDLE hProcess = NULL;
	if ( RING_API_PARACOUNT > 1 ) {
		RING_API_ERROR("Error: This function expects no or one parameter");
		return ;
	}
	if ( RING_API_PARACOUNT == 1 ) {
		if ( RING_API_ISPOINTER(1) ) {
			hProcess = (HANDLE) RING_API_GETCPOINTER(1, "HANDLE");
			if (!hProcess) {
				RING_API_ERROR("Error: No valid process handle");
				return;
			}
		} else {
			RING_API_ERROR("Error: No valid process handle");
			return;
		}
	} else hProcess = GetCurrentProcess();
	if(OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenHandle))
	{
		PTOKEN_USER pUserToken = NULL ;
		DWORD dwRequiredLength = 0 ;
		if(!GetTokenInformation(hTokenHandle, TokenUser, pUserToken, 0, &dwRequiredLength))
		{
			pUserToken = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredLength) ;
			if(NULL != pUserToken)
			{
				if(GetTokenInformation(hTokenHandle, TokenUser, pUserToken, dwRequiredLength, &dwRequiredLength))
				{
					LPSTR pszSID ;
					ConvertSidToStringSidA(pUserToken->User.Sid, &pszSID) ;
					strcpy(szUserSID, pszSID) ; 
					LocalFree(pszSID) ;
				}
				HeapFree(GetProcessHeap(), 0, pUserToken) ;
			}
		}

		CloseHandle(hTokenHandle) ;
	}
	RING_API_RETSTRING(szUserSID);
	return;
}



/*
Function Name : rwaSysErrorMsg
Func. Purpose : Return the string error message from the passed error code
Func. Params  : Either (Number ID) to return a message in English
				/Or/ (Number ID, BOOL allowlocale) to return a message in the user locale
Func. Return  : Error message
Func. Auther  : Majdi Sobain <MajdiSobain@Gmail.com>
*/
RING_FUNC(ring_winapi_rwasyserrormsg) {
	BOOL allowlocale = FALSE;
	DWORD ErrId;
    LPSTR pBuffer = NULL;
	BOOL lresult;
	if ( RING_API_PARACOUNT != 1 && RING_API_PARACOUNT != 2 ) {
		RING_API_ERROR("Error: Bad parameter count, this function expects one\\two parameters");
		return ;
	}
	if ( RING_API_PARACOUNT == 1 ) {
		if ( RING_API_ISNUMBER(1) ) {
			if ( RING_API_GETNUMBER(1) < 0 ) {
				RING_API_ERROR("Error: Error ID is not correct");
				return;
			}
			ErrId = RING_API_GETNUMBER(1);
		} else {
			RING_API_ERROR(RING_API_BADPARATYPE);
			return;
		}
	} else {
		if ( RING_API_ISNUMBER(1) && RING_API_ISNUMBER(2) ) {
			if ( RING_API_GETNUMBER(1) < 0 ) {
				RING_API_ERROR("Error: Error ID is not correct");
				return;
			}
			ErrId = RING_API_GETNUMBER(1);
			allowlocale = RING_API_GETNUMBER(2);
		} else {
			RING_API_ERROR(RING_API_BADPARATYPE);
			return;
		}
	}
	if (allowlocale) {
		lresult = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
						NULL, 
						ErrId,
						0,
						(LPSTR)&pBuffer, 
						0, 
						NULL);
	} else {
		lresult = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
						NULL, 
						ErrId,
						MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
						(LPSTR)&pBuffer, 
						0, 
						NULL);
	}
	if ( lresult ) {
		RING_API_RETSTRING(pBuffer);
	} else {
		RING_API_ERROR("Error : FormatMessage() function ended with unexpected result");
	}
	HeapFree(GetProcessHeap(), 0, pBuffer);
	return;
}



/*
=================================================================================================
			This Function Is Needed for Registration Of This Library 
			Functions Into Ring
			Note: This function has to be at the bottom of this library				
=================================================================================================
*/
RING_API void ringlib_init ( RingState *pRingState ) {
	ring_vm_funcregister("rwaisrunasadmin", ring_winapi_rwaisrunasadmin);
	ring_vm_funcregister("rwaelevate", ring_winapi_rwaelevate);
	ring_vm_funcregister("rwasyserrormsg", ring_winapi_rwasyserrormsg);
	ring_vm_funcregister("rshellexecute", ring_winapi_rshellexecute);
	ring_vm_funcregister("rwaiswow64process", ring_winapi_rwaiswow64process);
	ring_vm_funcregister("rwausersid", ring_winapi_rwausersid);

}
