// setpriority.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <winternl.h>


#pragma comment(lib, "advapi32.lib")
#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);

// 特権の設定
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}
	printf("last error=%d\n", GetLastError());

	return TRUE;
}

int main(int argc, char * argv[])
{
	DWORD procid;
	HANDLE hToken;
	//PTOKEN_PRIVILEGES pTokenPrivileges;
	//char szPrivilegeName[256];
	//char szDisplayName[256];
	//DWORD dwLength;
	//DWORD dwLanguageId;
	ULONG ioPriority;

	// 特権の付与
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("プロセストークンが取得できません\n");
		return -1;
	}
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
		printf("OSの実行権限が設定できません\n");
		return - 1;
	}

	// 現在のプロセスの権限を知る
	/*GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);

	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);
	if (pTokenPrivileges == NULL) {
		CloseHandle(hToken);
		return 1;
	}

	GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwLength, &dwLength);


	for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {

		dwLength = sizeof(szPrivilegeName) / sizeof(szPrivilegeName[0]);

		LookupPrivilegeNameA(NULL,
			&pTokenPrivileges->Privileges[i].Luid,
			szPrivilegeName,
			&dwLength);

		dwLength = sizeof(szDisplayName) / sizeof(szPrivilegeName[0]);

		LookupPrivilegeDisplayNameA(NULL,
			szPrivilegeName,
			szDisplayName,
			&dwLength,
			&dwLanguageId);

		puts("----------------------------------------------------------------------");
		printf("PrivilegeName: %s\n", szPrivilegeName);
		printf("DisplayName: %s\n", szDisplayName);
		printf("Enable: %s\n\n", pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED ? "True" : "False");
	}

	CloseHandle(hToken);
	LocalFree(pTokenPrivileges);
	*/

	// プロセスIDを取得
	for (int i = 1; i < argc; i++) {
		sscanf_s(argv[i], "%ld", &procid);
		//printf("pid=%d\n", procid);
		HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_SET_INFORMATION, FALSE, procid);
		if (proc == NULL) {
			DWORD dwError = GetLastError();
			printf("プロセスハンドルが取得できません PID=%ld err=%d\n", procid, dwError);
			return 0;
		}
		// バックグラウンドモードに移行
		/*//if (!SetPriorityClass(proc, PROCESS_MODE_BACKGROUND_BEGIN))
		if (!SetPriorityClass(proc, IDLE_PRIORITY_CLASS))
		{
			DWORD dwError = GetLastError();
			if (ERROR_PROCESS_MODE_ALREADY_BACKGROUND == dwError) {
				CloseHandle(proc);
				return 0;
			}
			else {
				CloseHandle(proc);
				printf("Failed to enter background mode (%d)\n", dwError);
				return -1;
			}
		}
		if (!SetPriorityClass(proc, PROCESS_MODE_BACKGROUND_BEGIN))
		{
			DWORD dwError = GetLastError();
			if (ERROR_PROCESS_MODE_ALREADY_BACKGROUND == dwError) {
				CloseHandle(proc);
				return 0;
			}
			else {
				CloseHandle(proc);
				printf("Failed to enter background mode (%d)\n", dwError);
				return -1;
			}
		}
		*/
		ioPriority = 0; // very low
		NTSTATUS status;
		//status = NtSetInformationProcess(proc, 0x1d, &ioPriority, sizeof(ULONG));
		// PROCESS_INFORMATION_CLASS.ProcessIoPriority = 0x21
		status = NtSetInformationProcess(proc, 0x21, &ioPriority, sizeof(ULONG));
		if( status != 0)
		{
			CloseHandle(proc);
			printf("IO優先度の設定に失敗しました (%d)\n", status);
			return -1;
		}
		CloseHandle(proc);

	}
	return 0;

}

