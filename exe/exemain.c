#include <stdint.h>
#include <stdbool.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>

static int find_char_reverse(const wchar_t* s, wchar_t ch1, wchar_t ch2)
{
	int pos = -1;
	for (int i = 0; s[i]; ++i)
	{
		if (s[i] == ch1 || s[i] == ch2) {
			pos = i;
		}
	}
	return pos;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
	wchar_t s[MAX_PATH] = { 0 };
	DWORD r = GetModuleFileNameW(NULL, s, MAX_PATH);
	int y = find_char_reverse(s, '\\', '/');
	if (r == 0 || r == MAX_PATH || y == -1 || y + 11 > MAX_PATH) {
		MessageBoxW(NULL, L"Initialization failed.", L"asas", MB_ICONERROR);
		return 1;
	}
	s[y + 1] = '\0';
	if (!SUCCEEDED(StringCchCatW(s, MAX_PATH, L"asas32.dll"))) {
		MessageBoxW(NULL, L"Initialization failed.", L"asas", MB_ICONERROR);
		return 1;
	}
	HMODULE dll = LoadLibraryW(s);
	if (dll == NULL) {
		MessageBoxW(NULL, L"Initialization failed.", L"asas", MB_ICONERROR);
		return 1;
	}
	BOOL(CALLBACK * MyCreateProcess)(
		LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory,
		LPSTARTUPINFOW lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
		) = (void*)GetProcAddress(dll, MAKEINTRESOURCEA(2));
	if (!MyCreateProcess) {
		MessageBoxW(NULL, L"Initialization failed.", L"asas", MB_ICONERROR);
		return 1;
	}

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	SetLastError(0);
	if (!MyCreateProcess(NULL, lpCmdLine, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi)) {
		r = GetLastError();
		if (r != ERROR_SUCCESS) {
			wchar_t msg[1024] = { 0 };
			wchar_t* errmsg = NULL;
			DWORD rr = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, r, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errmsg, 0, NULL);
			if (!SUCCEEDED(StringCchPrintfW(msg, 1024, L"Failed to start process.\n\nError(%d): %s", r, errmsg)) || rr == 0) {
				MessageBoxW(NULL, L"Failed to compose error message.", L"asas", MB_ICONERROR);
			}
			else {
				MessageBoxW(NULL, msg, L"asas", MB_ICONERROR);
			}
			LocalFree(errmsg);
		}
		return 1;
	}
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}
