#include <windows.h>

#include <wchar.h>

#include "version.h"

static wchar_t *extract_filename(wchar_t *const str) {
  if (!str) {
    return NULL;
  }
  wchar_t *const s = wcsrchr(str, '/');
  wchar_t *const bs = wcsrchr(str, '\\');
  if (s && bs) {
    return (s > bs ? s : bs) + 1;
  }
  if (s) {
    return s + 1;
  }
  if (bs) {
    return bs + 1;
  }
  return str;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
  (void)hInstance;
  (void)hPrevInstance;
  (void)nCmdShow;

  static wchar_t const dll_name[] = L"asas32.dll";
  wchar_t s[MAX_PATH] = {0};
  DWORD r = GetModuleFileNameW(NULL, s, MAX_PATH);
  if (r == 0 || r == MAX_PATH) {
    MessageBoxW(NULL, L"Failed to get module filename.", APPNAME_WIDE, MB_ICONERROR);
    return 1;
  }
  wchar_t *const filename = extract_filename(s);
  if (filename == NULL || filename + wcslen(dll_name) + 1 > s + MAX_PATH) {
    MessageBoxW(NULL, L"Initialization failed.", APPNAME_WIDE, MB_ICONERROR);
    return 1;
  }
  *filename = L'\0';
  wcscat(s, dll_name);
  HMODULE dll = LoadLibraryW(s);
  if (dll == NULL) {
    MessageBoxW(NULL, L"Initialization failed.", APPNAME_WIDE, MB_ICONERROR);
    return 1;
  }
  typedef BOOL(CALLBACK * MyCreateProcessFunc)(LPCWSTR lpApplicationName,
                                               LPWSTR lpCommandLine,
                                               LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                               LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                               BOOL bInheritHandles,
                                               DWORD dwCreationFlags,
                                               LPVOID lpEnvironment,
                                               LPCWSTR lpCurrentDirectory,
                                               LPSTARTUPINFOW lpStartupInfo,
                                               LPPROCESS_INFORMATION lpProcessInformation);
  MyCreateProcessFunc MyCreateProcess = (MyCreateProcessFunc)GetProcAddress(dll, MAKEINTRESOURCEA(2));
  if (!MyCreateProcess) {
    MessageBoxW(NULL, L"Initialization failed.", APPNAME_WIDE, MB_ICONERROR);
    return 1;
  }

  STARTUPINFOW si = {
      .cb = sizeof(STARTUPINFOW),
  };
  PROCESS_INFORMATION pi = {0};
  SetLastError(0);
  if (!MyCreateProcess(NULL, lpCmdLine, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi)) {
    r = GetLastError();
    if (r != ERROR_SUCCESS) {
      wchar_t msg[1024] = {0};
      wchar_t *errmsg = NULL;
      DWORD rr =
          FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                         NULL,
                         r,
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                         (LPWSTR)&errmsg,
                         0,
                         NULL);
      if (rr == 0) {
        MessageBoxW(NULL, L"Error occurred but failed to retrieve error message.", APPNAME_WIDE, MB_ICONERROR);
        return 1;
      }
      wsprintfW(msg, L"Failed to start process.\n\nError(%d): %s", r, errmsg);
      MessageBoxW(NULL, msg, APPNAME_WIDE, MB_ICONERROR);
      LocalFree(errmsg);
    }
    return 1;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return 0;
}
