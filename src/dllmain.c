#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <windows.h>

#include <commdlg.h>
#include <shlobj.h>
#include <shobjidl.h>

#include "version.h"

#ifdef __GNUC__
#  pragma GCC diagnostic push
#  if __has_warning("-Wreserved-macro-identifier")
#    pragma GCC diagnostic ignored "-Wreserved-macro-identifier"
#  endif
#  if __has_warning("-Wreserved-identifier")
#    pragma GCC diagnostic ignored "-Wreserved-identifier"
#  endif
#  if __has_warning("-Wundef")
#    pragma GCC diagnostic ignored "-Wundef"
#  endif
#  if __has_warning("-Wpadded")
#    pragma GCC diagnostic ignored "-Wpadded"
#  endif
#  include <detours.h>
#  pragma GCC diagnostic pop
#else
#  define _HRESULT_DEFINED
#endif // __GNUC__

#ifdef __GNUC__
#  if __has_warning("-Wpadded")
#    pragma GCC diagnostic ignored "-Wpadded"
#  endif
#endif // __GNUC__

#define ARRAY_SIZE(x) (sizeof(x) / (sizeof(x[0])))

enum {
  asas_flags_active = 1,
  asas_flags_use_given_filename = 2,
  asas_flags_confirm = 4,
};

struct asas_setting {
  uint32_t api_version;
  uint32_t flags;
  wchar_t filter[MAX_PATH];
  wchar_t folder[MAX_PATH];
  wchar_t format[MAX_PATH];
};

static HANDLE g_mutex = NULL;
static HANDLE g_fmo = NULL;

static HRESULT(WINAPI *TrueCoInitializeEx)(LPVOID pvReserved, DWORD dwCoInit) = CoInitializeEx;
static ULONG(WINAPI *TrueIFileDialog_Release)(IFileDialog *This) = NULL;
static HRESULT(WINAPI *TrueIFileDialog_Show)(IFileDialog *This, HWND hwndOwner) = NULL;
static HRESULT(WINAPI *TrueIFileDialog_SetFileTypes)(IFileDialog *This,
                                                     UINT cFileTypes,
                                                     COMDLG_FILTERSPEC const *rgFilterSpec) = NULL;
static HRESULT(WINAPI *TrueIFileDialog_Advise)(IFileDialog *This, IFileDialogEvents *pfde, DWORD *pdwCookie) = NULL;
static HRESULT(WINAPI *TrueIFileDialog_Unadvise)(IFileDialog *This, DWORD dwCookie) = NULL;
static HRESULT(WINAPI *TrueIFileDialog_GetResult)(IFileDialog *This, IShellItem **ppsi) = NULL;

static BOOL(WINAPI *TrueGetSaveFileNameA)(LPOPENFILENAMEA lpofna) = GetSaveFileNameA;
static BOOL(WINAPI *TrueGetSaveFileNameW)(LPOPENFILENAMEW lpofnw) = GetSaveFileNameW;

static int(WINAPI *TrueEntryPoint)(VOID) = NULL;

enum {
  debug_info = 0,
  debug_warn = 1,
  debug_error = 2,
};

static int g_log_level = 2;
static wchar_t g_log_filename[MAX_PATH] = {0};

static void debug(const int level, const wchar_t *fmt, ...) {
  if (level < g_log_level) {
    return;
  }
  wchar_t s[1024];
  va_list list;
  va_start(list, fmt);
  wvsprintfW(s, fmt, list);
  va_end(list);
  OutputDebugStringW(s);
  if (g_log_filename[0] != '\0') {
    char u8[2048];
    int u8len = WideCharToMultiByte(CP_UTF8, 0, s, -1, u8, ARRAY_SIZE(u8), NULL, NULL);
    if (!u8len) {
      return;
    }
    HANDLE h = CreateFileW(g_log_filename, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
      return;
    }
    if (SetFilePointer(h, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
      CloseHandle(h);
      return;
    }
    DWORD written = 0;
    if (!WriteFile(h, u8, (DWORD)(u8len - 1), &written, NULL)) {
      CloseHandle(h);
      return;
    }
    if (!WriteFile(h, "\r\n", 2, &written, NULL)) {
      CloseHandle(h);
      return;
    }
    CloseHandle(h);
  }
}
#ifndef DETOURS_BITS
#  define DETOURS_BITS 99
#endif
#define DBG(lv, fmt, ...) debug(lv, L"asas%d(%d): %hs: " fmt, DETOURS_BITS, __LINE__, __func__, __VA_ARGS__)

static bool atou32(wchar_t const *const ptr, uint32_t *const dest) {
  if (!ptr || !dest) {
    return false;
  }
  uint32_t r = 0, pr;
  wchar_t const *p = ptr;
  while (L'0' <= *p && *p <= L'9') {
    pr = r;
    r = r * 10 + (uint32_t)(*p++ - L'0');
    if (r < pr) {
      return false;
    }
  }
  if (ptr == p) {
    return false;
  }
  *dest = r;
  return true;
}

static bool is_same_i(wchar_t const *const s1, wchar_t const *const s2) {
  for (size_t i = 0; s1[i] && s2[i]; ++i) {
    if (s1[i] == s2[i]) {
      continue;
    }
    if ((s1[i] >= 'A' && s1[i] <= 'Z') || (s1[i] >= 'a' && s1[i] <= 'z')) {
      if ((s1[i] ^ 32) == s2[i]) {
        continue;
      }
    }
    return false;
  }
  return true;
}

static bool is_valid_filename(wchar_t const *const s) {
  if (s == NULL || s[0] == '\0') {
    return false;
  }
  for (size_t i = 0; s[i]; ++i) {
    if (s[i] <= 0x1f || s[i] == 0x22 || s[i] == 0x2a || s[i] == 0x2f || s[i] == 0x3a || s[i] == 0x3c || s[i] == 0x3e ||
        s[i] == 0x3f || s[i] == 0x7c || s[i] == 0x7f) {
      return false;
    }
  }
  return true;
}

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

static wchar_t *extract_file_extension(wchar_t *const str) {
  if (!str) {
    return NULL;
  }
  wchar_t *const fn = extract_filename(str);
  if (!fn) {
    return NULL;
  }
  wchar_t *const p = wcsrchr(fn, L'.');
  if (!p) {
    return fn + wcslen(fn);
  }
  return p;
}

static bool get_module_name(wchar_t *const s, size_t const len) {
  wchar_t m[MAX_PATH] = {0};
  DWORD const r = GetModuleFileNameW(NULL, m, ARRAY_SIZE(m));
  if (r == 0 || r == ARRAY_SIZE(m)) {
    return false;
  }
  wchar_t *const fn = extract_filename(m);
  if (!fn) {
    return false;
  }
  wchar_t *const ext = wcsrchr(fn, L'.');
  if (ext) {
    *ext = L'\0';
  }
  if (wcslen(fn) >= len) {
    return false;
  }
  wcscpy(s, fn);
  return true;
}

static bool get_shared_setting(struct asas_setting *const setting) {
  if (!g_fmo || !g_mutex) {
    DBG(debug_warn, L"%s", L"fmo is not ready");
    return false;
  }
  DWORD const r = WaitForSingleObject(g_mutex, INFINITE);
  if (r != WAIT_OBJECT_0) {
    DBG(debug_error, L"%s", L"WaitForSingleObject failed");
    return false;
  }
  struct asas_setting *const p = (struct asas_setting *)MapViewOfFile(g_fmo, FILE_MAP_READ, 0, 0, 0);
  if (p == NULL) {
    DBG(debug_error, L"%s", L"MapViewOfFile failed");
    ReleaseMutex(g_mutex);
    return false;
  }
  *setting = *p;
  UnmapViewOfFile(p);
  ReleaseMutex(g_mutex);
  return true;
}

static bool build_filename(wchar_t *const dest,
                           size_t const destlen,
                           wchar_t const *const folder,
                           wchar_t const *const fmt,
                           wchar_t const *const given_filename) {
  size_t written = 0;
  *dest = L'\0';

  size_t srclen = wcslen(folder);
  if (written + srclen >= destlen) {
    DBG(debug_error, L"%s", L"not sufficient buffer");
    return false;
  }
  wcscat(dest, folder);
  written += srclen;

  if (dest[written] != L'\\' && dest[written] != L'/') {
    if (written + 1 >= destlen) {
      DBG(debug_error, L"%s", L"not sufficient buffer");
      return false;
    }
    dest[written] = L'\\';
    dest[++written] = L'\0';
  }

  if (given_filename != NULL && is_valid_filename(given_filename)) {
    srclen = wcslen(given_filename);
    if (written + srclen >= destlen) {
      DBG(debug_error, L"%s", L"not sufficient buffer");
      return false;
    }
    wcscat(dest, given_filename);
    written += srclen;
    return true;
  }

  wchar_t timestr[16] = {0};
  {
    SYSTEMTIME st = {0};
    GetLocalTime(&st);
    wsprintfW(timestr,
              L"%04d%02d%02d%02d%02d%02d",
              (int)st.wYear,
              (int)st.wMonth,
              (int)st.wDay,
              (int)st.wHour,
              (int)st.wMinute,
              (int)st.wSecond);
  }

  size_t fmtpos = 0;
  size_t filenamepos = written;
  while (fmt[fmtpos] != L'\0') {
    if (fmt[fmtpos] == '*') {
      srclen = wcslen(timestr);
      if (written + srclen >= destlen) {
        DBG(debug_error, L"%s", L"not sufficient buffer");
        return false;
      }
      wcscat(dest, timestr);
      written += srclen;
      ++fmtpos;
      continue;
    }
    if (written + 1 > destlen) {
      DBG(debug_error, L"%s", L"not sufficient buffer");
      return false;
    }
    dest[written] = fmt[fmtpos];
    dest[++written] = L'\0';
    ++fmtpos;
  }
  if (!is_valid_filename(dest + filenamepos)) {
    DBG(debug_error, L"%s is not valid filename", dest);
    return false;
  }
  return true;
}

struct my_file_system_bind_data {
  const struct IFileSystemBindDataVtbl *lpVtbl;
  LONG ref;
  WIN32_FIND_DATAW fd;
};

static HRESULT WINAPI my_file_system_bind_data_QueryInterface(IFileSystemBindData *This, REFIID riid, void **ppv) {
  if (memcmp(riid, &IID_IFileSystemBindData, sizeof(IID)) == 0 || memcmp(riid, &IID_IUnknown, sizeof(IID)) == 0) {
    This->lpVtbl->AddRef(This);
    *ppv = This;
    return S_OK;
  }
  *ppv = NULL;
  return E_NOINTERFACE;
}

static ULONG WINAPI my_file_system_bind_data_AddRef(IFileSystemBindData *This) {
  struct my_file_system_bind_data *const t = (struct my_file_system_bind_data *)This;
  return (ULONG)InterlockedIncrement(&t->ref);
}

static ULONG WINAPI my_file_system_bind_data_Release(IFileSystemBindData *This) {
  struct my_file_system_bind_data *const t = (struct my_file_system_bind_data *)This;
  ULONG r = (ULONG)InterlockedDecrement(&t->ref);
  if (r == 0) {
    CoTaskMemFree(This);
  }
  return r;
}

static HRESULT WINAPI my_file_system_bind_data_SetFindData(IFileSystemBindData *This, const WIN32_FIND_DATAW *pfd) {
  struct my_file_system_bind_data *const t = (struct my_file_system_bind_data *)This;
  t->fd = *pfd;
  return S_OK;
}

static HRESULT WINAPI my_file_system_bind_data_GetFindData(IFileSystemBindData *This, WIN32_FIND_DATAW *pfd) {
  struct my_file_system_bind_data *const t = (struct my_file_system_bind_data *)This;
  *pfd = t->fd;
  return S_OK;
}

static const struct IFileSystemBindDataVtbl my_file_system_bind_data_vtbl = {
    .QueryInterface = my_file_system_bind_data_QueryInterface,
    .AddRef = my_file_system_bind_data_AddRef,
    .Release = my_file_system_bind_data_Release,
    .SetFindData = my_file_system_bind_data_SetFindData,
    .GetFindData = my_file_system_bind_data_GetFindData,
};

enum {
  num_state = 4,
  num_events = 4,
};

static struct save_dialog_state {
  IFileDialog *This;
  ULONGLONG at;
  bool is_save;
  bool skip_dialog;
  wchar_t filename[MAX_PATH];
  struct {
    IFileDialogEvents *file_dialog_events;
    DWORD cookie;
  } events[num_events];
} g_states[num_state] = {0};
static DWORD g_no_interrupt = 0;

static bool is_save_dialog(interface IFileDialog *This) {
  interface IFileSaveDialog *fsd = NULL;
  HRESULT hr = This->lpVtbl->QueryInterface(This, &IID_IFileSaveDialog, (void **)&fsd);
  if (!SUCCEEDED(hr)) {
    return false;
  }
  fsd->lpVtbl->Release(fsd);
  return true;
}

static struct save_dialog_state *set_state(IFileDialog *This) {
  int found = -1;
  int found_oldest = -1;
  ULONGLONG at = GetTickCount64();
  for (int i = 0; i < num_state; ++i) {
    if (g_states[i].This == NULL) {
      found = i;
      break;
    }
    if (g_states[i].at < at) {
      found_oldest = i;
      at = g_states[i].at;
    }
  }
  if (found == -1) {
    found = found_oldest;
    ZeroMemory(&g_states[found_oldest], sizeof(struct save_dialog_state));
  }
  g_states[found].This = This;
  g_states[found].at = GetTickCount64();
  g_states[found].is_save = is_save_dialog(This);
  g_states[found].skip_dialog = false;
  for (int j = 0; j < num_events; ++j) {
    g_states[found].events[j].file_dialog_events = NULL;
    g_states[found].events[j].cookie = 0;
  }
  return &g_states[found];
}

static struct save_dialog_state *get_state(IFileDialog *This) {
  for (int i = 0; i < num_state; ++i) {
    if (g_states[i].This == This) {
      g_states[i].at = GetTickCount64();
      return &g_states[i];
    }
  }
  return set_state(This);
}

static ULONG WINAPI MyIFileDialog_Release(IFileDialog *This) {
  ULONG r = TrueIFileDialog_Release(This);
  if (r == 0) {
    for (int i = 0; i < num_state; ++i) {
      if (g_states[i].This == This) {
        struct save_dialog_state *s = g_states + i;
        ZeroMemory(s, sizeof(struct save_dialog_state));
        break;
      }
    }
  }
  return r;
}

static HRESULT WINAPI MyIFileDialog_SetFileTypes(IFileDialog *This,
                                                 UINT cFileTypes,
                                                 const COMDLG_FILTERSPEC *rgFilterSpec) {
  struct save_dialog_state *s = NULL;
  struct asas_setting setting = {0};
  DBG(debug_info, L"%s", L"begin");
  if (g_no_interrupt > 0) {
    DBG(debug_info, L"%s", L"currently no active by internal reason");
    goto call;
  }
  s = get_state(This);
  if (s == NULL) {
    DBG(debug_error, L"%s", L"cannot get state");
    goto call;
  }
  if (!s->is_save) {
    DBG(debug_info, L"%s", L"is not save dialog");
    goto call;
  }
  if (!get_shared_setting(&setting)) {
    DBG(debug_error, L"%s", L"cannot get current setting");
    goto call;
  }
  s->skip_dialog = false;
  for (UINT i = 0; i < cFileTypes; ++i) {
    DBG(debug_info, L"filter #%d %s", i + 1, rgFilterSpec[i].pszSpec);
    if (is_same_i(rgFilterSpec[i].pszSpec, setting.filter)) {
      DBG(debug_info, L"%s", L"found matched filter");
      s->skip_dialog = true;
      goto call;
    }
  }
  DBG(debug_info, L"%s", L"matched filter not found");
call:
  return TrueIFileDialog_SetFileTypes(This, cFileTypes, rgFilterSpec);
}

static HRESULT WINAPI MyIFileDialog_Show(IFileDialog *This, HWND hwndOwner) {
  struct save_dialog_state *s = NULL;
  struct asas_setting setting = {0};
  wchar_t given_filename[MAX_PATH] = {0};
  DBG(debug_info, L"%s", L"begin");
  if (g_no_interrupt > 0) {
    DBG(debug_info, L"%s", L"currently no active by internal reason");
    goto call;
  }
  s = get_state(This);
  if (s == NULL || !s->is_save || !s->skip_dialog) {
    goto call;
  }

  if (!get_shared_setting(&setting)) {
    DBG(debug_error, L"%s", L"cannot get current setting");
    goto call;
  }
  if (!(setting.flags & asas_flags_active)) {
    DBG(debug_info, L"%s", L"asas is not active");
    goto call;
  }
  if (setting.flags & asas_flags_use_given_filename) {
    LPWSTR str = NULL;
    if (SUCCEEDED(This->lpVtbl->GetFileName(This, &str))) {
      if (wcslen(str) >= ARRAY_SIZE(given_filename)) {
        DBG(debug_error, L"%s", L"not sufficient buffer");
        goto call;
      }
      wcscpy(given_filename, str);
      CoTaskMemFree(str);
    }
  }
  if (!build_filename(s->filename,
                      ARRAY_SIZE(s->filename),
                      setting.folder,
                      setting.format,
                      given_filename[0] != L'\0' ? given_filename : NULL)) {
    MessageBoxW(hwndOwner, L"failed to build filename.", APPNAME_WIDE, MB_ICONERROR);
    return HRESULT_FROM_WIN32(ERROR_CANCELLED);
  }
  if (setting.flags & asas_flags_confirm) {
    wchar_t str[1024];
    if (!SUCCEEDED(wsprintfW(str, L"Are you sure you want to save with the following filename?\n\n%s", s->filename))) {
      MessageBoxW(hwndOwner, L"failed to build confirm message.", APPNAME_WIDE, MB_ICONERROR);
      return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    }
    switch (MessageBoxW(hwndOwner, str, APPNAME_WIDE, MB_ICONQUESTION | MB_YESNOCANCEL)) {
    case IDYES:
      break;
    case IDNO:
      s->skip_dialog = false;
      goto call;
    case IDCANCEL:
      DBG(debug_info, L"%s", L"aborted by user");
      return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    }
  }
  for (int i = 0; i < num_events; ++i) {
    if (s->events[i].file_dialog_events != NULL) {
      if (!SUCCEEDED(s->events[i].file_dialog_events->lpVtbl->OnFileOk(s->events[i].file_dialog_events, This))) {
        DBG(debug_info, L"%s", L"aborted by IFileDialogEvent");
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
      }
    }
  }
  return S_OK;
call:
  return TrueIFileDialog_Show(This, hwndOwner);
}

static HRESULT WINAPI MyIFileDialog_Advise(IFileDialog *This, IFileDialogEvents *pfde, DWORD *pdwCookie) {
  DBG(debug_info, L"%s", L"begin");
  HRESULT hr = TrueIFileDialog_Advise(This, pfde, pdwCookie);
  if (!SUCCEEDED(hr)) {
    return hr;
  }
  if (g_no_interrupt > 0) {
    DBG(debug_info, L"%s", L"currently no active by internal reason");
    return hr;
  }
  struct save_dialog_state *const s = get_state(This);
  if (s == NULL || !s->is_save) {
    return hr;
  }
  for (int i = 0; i < num_events; ++i) {
    if (s->events[i].file_dialog_events == NULL) {
      s->events[i].file_dialog_events = pfde;
      s->events[i].cookie = *pdwCookie;
      return hr;
    }
  }
  DBG(debug_warn, L"%s", L"failed to register IFileDialogEvents");
  return hr;
}

static HRESULT WINAPI MyIFileDialog_Unadvise(IFileDialog *This, DWORD dwCookie) {
  DBG(debug_info, L"%s", L"begin");
  HRESULT hr = TrueIFileDialog_Unadvise(This, dwCookie);
  if (!SUCCEEDED(hr)) {
    return hr;
  }
  if (g_no_interrupt > 0) {
    DBG(debug_info, L"%s", L"currently no active by internal reason");
    return hr;
  }
  struct save_dialog_state *const s = get_state(This);
  if (s == NULL || !s->is_save) {
    return hr;
  }
  for (int i = 0; i < num_events; ++i) {
    if (s->events[i].cookie == dwCookie) {
      s->events[i].file_dialog_events = NULL;
      s->events[i].cookie = 0;
      return hr;
    }
  }
  return hr;
}

static HRESULT WINAPI MyIFileDialog_GetResult(IFileDialog *This, IShellItem **ppsi) {
  struct save_dialog_state *s = NULL;
  IShellFolder *shell_folder = NULL;
  LPITEMIDLIST pidl = NULL;
  IBindCtx *bctx = NULL;
  HRESULT hr;
  DBG(debug_info, L"%s", L"begin");
  if (g_no_interrupt > 0) {
    DBG(debug_info, L"%s", L"currently no active by internal reason");
    goto call;
  }
  s = get_state(This);
  if (s == NULL || !s->is_save || !s->skip_dialog) {
    goto call;
  }
  if (s->filename[0] == '\0') {
    return S_FALSE;
  }
  hr = SHGetDesktopFolder(&shell_folder);
  if (!SUCCEEDED(hr)) {
    DBG(debug_error, L"SHGetDesktopFolder failed %08x", hr);
    return S_FALSE;
  }
  hr = CreateBindCtx(0, &bctx);
  if (!SUCCEEDED(hr)) {
    DBG(debug_error, L"CreateBindCtx failed %08x", hr);
    return S_FALSE;
  }
  {
    struct my_file_system_bind_data *fsbd = CoTaskMemAlloc(sizeof(struct my_file_system_bind_data));
    if (fsbd == NULL) {
      DBG(debug_error, L"CoTaskMemAlloc failed %08x", hr);
      return S_FALSE;
    }
    *fsbd = (struct my_file_system_bind_data){
        .lpVtbl = &my_file_system_bind_data_vtbl,
        .ref = 1,
        .fd =
            (WIN32_FIND_DATAW){
                .dwFileAttributes = FILE_ATTRIBUTE_NORMAL,
            },
    };
    if (wcslen(s->filename) >= ARRAY_SIZE(fsbd->fd.cFileName)) {
      DBG(debug_error, L"%s", L"cannot copy filename to WIN32_FIND_DATAW");
      return S_FALSE;
    }
    wcscpy(fsbd->fd.cFileName, s->filename);
    bctx->lpVtbl->RegisterObjectParam(bctx, L"File System Bind Data", (IUnknown *)fsbd);
    fsbd->lpVtbl->Release((IFileSystemBindData *)fsbd);
    fsbd = NULL;
  }
  hr = shell_folder->lpVtbl->ParseDisplayName(shell_folder, NULL, bctx, s->filename, NULL, &pidl, NULL);
  if (!SUCCEEDED(hr)) {
    DBG(debug_error, L"ParseDisplayName failed %08x", hr);
    return S_FALSE;
  }
  hr = SHCreateShellItem(NULL, NULL, pidl, ppsi);
  if (!SUCCEEDED(hr)) {
    DBG(debug_error, L"SHCreateShellItem failed %08x", hr);
    return S_FALSE;
  }
  return S_OK;
call:
  return TrueIFileDialog_GetResult(This, ppsi);
}

static bool attach_interface(IFileDialog *fd) {
  if (DetourTransactionBegin() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to begin transaction");
    return false;
  }
  if (TrueIFileDialog_Show) {
    goto abort;
  }
  TrueIFileDialog_Release = fd->lpVtbl->Release;
  TrueIFileDialog_Show = fd->lpVtbl->Show;
  TrueIFileDialog_SetFileTypes = fd->lpVtbl->SetFileTypes;
  TrueIFileDialog_Advise = fd->lpVtbl->Advise;
  TrueIFileDialog_Unadvise = fd->lpVtbl->Unadvise;
  TrueIFileDialog_GetResult = fd->lpVtbl->GetResult;
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to update thread");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueIFileDialog_Release, (void *)MyIFileDialog_Release) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach Release ");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueIFileDialog_Show, (void *)MyIFileDialog_Show) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach Show");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueIFileDialog_SetFileTypes, (void *)MyIFileDialog_SetFileTypes) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach SetFileTypes");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueIFileDialog_Advise, (void *)MyIFileDialog_Advise) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach Advise");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueIFileDialog_Unadvise, (void *)MyIFileDialog_Unadvise) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach Undvise");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueIFileDialog_GetResult, (void *)MyIFileDialog_GetResult) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach GetResult");
    goto abort;
  }
  if (DetourTransactionCommit() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to commit");
    goto abort;
  }
  return true;
abort:
  if (DetourTransactionAbort() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to abort");
  }
  return false;
}

static char const *find_next_filter_a(LPOPENFILENAMEA const lpofn, char const *const last) {
  char const *p = NULL;
  if (last == NULL) {
    p = lpofn->lpstrFilter;
  } else {
    // skip founded filter
    p = last;
    while (*p != '\0') {
      ++p;
    }
    ++p;
  }
  if (*p == '\0') {
    return NULL;
  }
  // skip caption
  while (*p != '\0') {
    ++p;
  }
  ++p;
  if (*p == '\0') {
    return NULL;
  }
  return p;
}

static wchar_t const *find_next_filter_w(LPOPENFILENAMEW const lpofn, wchar_t const *const last) {
  wchar_t const *p = NULL;
  if (last == NULL) {
    p = lpofn->lpstrFilter;
  } else {
    // skip founded filter
    p = last;
    while (*p != '\0') {
      ++p;
    }
    ++p;
  }
  if (*p == '\0') {
    return NULL;
  }
  // skip caption
  while (*p != '\0') {
    ++p;
  }
  ++p;
  if (*p == '\0') {
    return NULL;
  }
  return p;
}

static bool to_wide(char const *const s, wchar_t *const d, int const dlen) {
  return MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, s, -1, d, dlen) != 0;
}

static bool to_mbcs(wchar_t const *const s, char *const d, int const dlen) {
  return WideCharToMultiByte(CP_ACP, 0, s, -1, d, dlen, NULL, NULL) != 0;
}

static BOOL WINAPI MyGetSaveFileNameA(LPOPENFILENAMEA lpofn) {
  struct asas_setting setting = {0};
  wchar_t w[MAX_PATH] = {0};
  DWORD filter_index = 0;
  char const *cur = NULL;
  DBG(debug_info, L"%s", L"begin");
  if (lpofn == NULL) {
    goto call;
  }
  if (!get_shared_setting(&setting)) {
    DBG(debug_error, L"%s", L"cannot get current setting");
    goto call;
  }
  if (!(setting.flags & asas_flags_active)) {
    DBG(debug_info, L"%s", L"asas is not active");
    goto call;
  }
  cur = find_next_filter_a(lpofn, NULL);
  while (cur != NULL) {
    ++filter_index;
    if (!to_wide(cur, w, ARRAY_SIZE(w))) {
      DBG(debug_error, L"%s", L"failed to convert to widestring");
      goto call;
    }
    DBG(debug_info, L"filter #%d %s", (int)filter_index, w);
    if (is_same_i(w, setting.filter)) {
      goto autosave;
    }
    cur = find_next_filter_a(lpofn, cur);
  }
  DBG(debug_info, L"%s", L"matched filter not found");
  goto call;
autosave : {
  wchar_t filename[MAX_PATH] = {0};
  {
    wchar_t buf[MAX_PATH] = {0};
    wchar_t *given_filename = NULL;
    if (setting.flags & asas_flags_use_given_filename) {
      if (!to_wide(lpofn->lpstrFile, buf, ARRAY_SIZE(buf))) {
        DBG(debug_error, L"%s", L"failed to convert to widestring");
        goto call;
      }
      wchar_t *fn = extract_filename(buf);
      if (fn) {
        given_filename = fn;
      }
    }
    if (!build_filename(filename, ARRAY_SIZE(filename), setting.folder, setting.format, given_filename)) {
      MessageBoxW(lpofn->hwndOwner, L"Failed to compose filename.", APPNAME_WIDE, MB_ICONERROR);
      return FALSE;
    }
  }
  if (setting.flags & asas_flags_confirm) {
    wchar_t str[1024];
    if (!SUCCEEDED(wsprintfW(str, L"Are you sure you want to save with the following filename?\n\n%s", filename))) {
      MessageBoxW(lpofn->hwndOwner, L"Failed to compose confirm message.", APPNAME_WIDE, MB_ICONERROR);
      return FALSE;
    }
    switch (MessageBoxW(lpofn->hwndOwner, str, APPNAME_WIDE, MB_ICONQUESTION | MB_YESNOCANCEL)) {
    case IDYES:
      break;
    case IDNO: {
      ++g_no_interrupt;
      BOOL r = TrueGetSaveFileNameA(lpofn);
      --g_no_interrupt;
      return r;
    }
    case IDCANCEL:
      DBG(debug_info, L"%s", L"aborted by user");
      return FALSE;
    }
  }

  {
    wchar_t *const ext = extract_file_extension(filename);
    if (!ext) {
      // If no extension is given and lpofn->lpstrDefExt is not null, add the default extension.
      if (lpofn->lpstrDefExt) {
        wchar_t defext[MAX_PATH] = {0};
        if (!to_wide(lpofn->lpstrDefExt, defext, ARRAY_SIZE(defext))) {
          MessageBoxW(lpofn->hwndOwner, L"Failed to convert string to wide.", APPNAME_WIDE, MB_ICONERROR);
          return FALSE;
        }
        if (wcslen(filename) + wcslen(defext) + 1 >= ARRAY_SIZE(filename)) {
          MessageBoxW(lpofn->hwndOwner, L"asas internal buffer is too small", APPNAME_WIDE, MB_ICONERROR);
          return FALSE;
        }
        wcscat(filename, L".");
        wcscat(filename, defext);
      }
    }
  }

  if (!to_mbcs(filename, lpofn->lpstrFile, (int)lpofn->nMaxFile)) {
    MessageBoxW(lpofn->hwndOwner, L"lpstrFile buffer is too small.", APPNAME_WIDE, MB_ICONERROR);
    return FALSE;
  }

  size_t const fulllen = strnlen(lpofn->lpstrFile, lpofn->nMaxFile);
  char fnansi[MAX_PATH] = {0};
  wchar_t *fnwide = extract_filename(filename);
  if (!fnwide) {
    MessageBoxW(lpofn->hwndOwner, L"Failed to extract filename from fullpath.", APPNAME_WIDE, MB_ICONERROR);
    return FALSE;
  }
  if (!to_mbcs(fnwide, fnansi, ARRAY_SIZE(fnansi))) {
    MessageBoxW(lpofn->hwndOwner, L"Failed to convert string to mbcs.", APPNAME_WIDE, MB_ICONERROR);
    return FALSE;
  }
  size_t len = strnlen(fnansi, ARRAY_SIZE(fnansi));
  lpofn->nFileOffset = (WORD)(fulllen - len);

  if (lpofn->lpstrFileTitle != NULL) {
    if (len >= lpofn->nMaxFileTitle) {
      MessageBoxW(lpofn->hwndOwner, L"lpstrFileTitle buffer is too small", APPNAME_WIDE, MB_ICONERROR);
      return FALSE;
    }
    strncpy(lpofn->lpstrFileTitle, fnansi, len);
    lpofn->lpstrFileTitle[len] = L'\0';
  }

  if (filename[wcslen(filename) - 1] == L'.') {
    lpofn->nFileExtension = 0;
  } else {
    wchar_t *const ext = extract_file_extension(filename);
    if (!ext) {
      lpofn->nFileExtension = (WORD)(strnlen(fnansi, ARRAY_SIZE(fnansi)));
    } else {
      char extansi[MAX_PATH] = {0};
      if (!to_mbcs(ext + 1, extansi, ARRAY_SIZE(extansi))) {
        MessageBoxW(lpofn->hwndOwner, L"Failed to convert string to mbcs.", APPNAME_WIDE, MB_ICONERROR);
        return FALSE;
      }
      lpofn->nFileExtension = (WORD)(strnlen(fnansi, ARRAY_SIZE(fnansi)) - strnlen(extansi, ARRAY_SIZE(extansi)));
    }
  }

  lpofn->nFilterIndex = filter_index;
  return TRUE;
}
call:
  return TrueGetSaveFileNameA(lpofn);
}

static BOOL WINAPI MyGetSaveFileNameW(LPOPENFILENAMEW lpofn) {
  struct asas_setting setting = {0};
  DWORD filter_index = 0;
  wchar_t const *cur = NULL;
  DBG(debug_info, L"%s", L"begin");
  if (lpofn == NULL) {
    goto call;
  }
  if (!get_shared_setting(&setting)) {
    DBG(debug_error, L"%s", L"cannot get current setting");
    goto call;
  }
  if (!(setting.flags & asas_flags_active)) {
    DBG(debug_info, L"%s", L"asas is not active");
    goto call;
  }
  cur = find_next_filter_w(lpofn, NULL);
  while (cur != NULL) {
    ++filter_index;
    DBG(debug_info, L"filter #%d %s", (int)filter_index, cur);
    if (is_same_i(cur, setting.filter)) {
      goto autosave;
    }
    cur = find_next_filter_w(lpofn, cur);
  }
  DBG(debug_info, L"%s", L"matched filter not found");
  goto call;
autosave : {
  wchar_t filename[MAX_PATH] = {0};
  {
    wchar_t *given_filename = NULL;
    if (setting.flags & asas_flags_use_given_filename) {
      wchar_t *fn = extract_filename(lpofn->lpstrFile);
      if (fn) {
        given_filename = fn;
      }
    }
    if (!build_filename(filename, ARRAY_SIZE(filename), setting.folder, setting.format, given_filename)) {
      MessageBoxW(lpofn->hwndOwner, L"Failed to compose filename.", APPNAME_WIDE, MB_ICONERROR);
      return FALSE;
    }
  }
  if (setting.flags & asas_flags_confirm) {
    wchar_t str[1024];
    if (!SUCCEEDED(wsprintfW(str, L"Are you sure you want to save with the following filename?\n\n%s", filename))) {
      MessageBoxW(lpofn->hwndOwner, L"Failed to compose confirm message.", APPNAME_WIDE, MB_ICONERROR);
      return FALSE;
    }
    switch (MessageBoxW(lpofn->hwndOwner, str, APPNAME_WIDE, MB_ICONQUESTION | MB_YESNOCANCEL)) {
    case IDYES:
      break;
    case IDNO: {
      ++g_no_interrupt;
      BOOL r = TrueGetSaveFileNameW(lpofn);
      --g_no_interrupt;
      return r;
    }
    case IDCANCEL:
      DBG(debug_info, L"%s", L"aborted by user");
      return FALSE;
    }
  }

  {
    wchar_t *const ext = extract_file_extension(filename);
    if (!ext) {
      // If no extension is given and lpofn->lpstrDefExt is not null, add the default extension.
      if (lpofn->lpstrDefExt) {
        if (wcslen(filename) + wcslen(lpofn->lpstrDefExt) + 1 >= ARRAY_SIZE(filename)) {
          MessageBoxW(lpofn->hwndOwner, L"asas internal buffer is too small", APPNAME_WIDE, MB_ICONERROR);
          return FALSE;
        }
        wcscat(filename, L".");
        wcscat(filename, lpofn->lpstrDefExt);
      }
    }
  }

  if (wcslen(filename) >= lpofn->nMaxFile) {
    MessageBoxW(lpofn->hwndOwner, L"lpstrFile buffer is too small", APPNAME_WIDE, MB_ICONERROR);
    return FALSE;
  }
  wcscpy(lpofn->lpstrFile, filename);

  wchar_t *const fn = extract_filename(filename);
  lpofn->nFileOffset = (WORD)(fn - filename);

  if (lpofn->lpstrFileTitle != NULL) {
    size_t const len = wcsnlen(fn, ARRAY_SIZE(filename) - (size_t)(fn - filename));
    if (len >= lpofn->nMaxFileTitle) {
      MessageBoxW(lpofn->hwndOwner, L"lpstrFileTitle is too small", APPNAME_WIDE, MB_ICONERROR);
      return FALSE;
    } else {
      wcsncpy(lpofn->lpstrFileTitle, fn, len);
      lpofn->lpstrFileTitle[len] = L'\0';
    }
  }

  if (filename[wcslen(filename) - 1] == L'.') {
    lpofn->nFileExtension = 0;
  } else {
    wchar_t *const ext = extract_file_extension(filename);
    if (!ext) {
      lpofn->nFileExtension = (WORD)(wcslen(filename));
    } else {
      lpofn->nFileExtension = (WORD)(ext - filename + 1);
    }
  }

  lpofn->nFilterIndex = filter_index;
  return TRUE;
}
call:
  return TrueGetSaveFileNameW(lpofn);
}

static HRESULT WINAPI MyCoInitializeEx(LPVOID pvReserved, DWORD dwCoInit) {
  const HRESULT hr = TrueCoInitializeEx(pvReserved, dwCoInit);
  if (TrueIFileDialog_Show != NULL) {
    return hr;
  }
  IFileDialog *fd = NULL;
  if (!SUCCEEDED(CoCreateInstance(&CLSID_FileSaveDialog, NULL, CLSCTX_ALL, &IID_IFileDialog, (LPVOID *)&fd))) {
    DBG(debug_error, L"%s", L"failed to get IFileDialog");
    return hr;
  }
  attach_interface(fd);
  fd->lpVtbl->Release(fd);
  fd = NULL;
  return hr;
}

int WINAPI MyEntryPoint(VOID);

static bool attach_process(void) {
  if (DetourTransactionBegin() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to begin transaction");
    return false;
  }
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to update thread");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueCoInitializeEx, (void *)MyCoInitializeEx) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach CoInitializeEx");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueGetSaveFileNameW, (void *)MyGetSaveFileNameW) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach GetSaveFileNameW");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueGetSaveFileNameA, (void *)MyGetSaveFileNameA) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach GetSaveFileNameA");
    goto abort;
  }
  if (DetourTransactionCommit() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to commit");
    goto abort;
  }
  return true;
abort:
  if (DetourTransactionAbort() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to abort");
  }
  return false;
}

static bool detach_process(void) {
  if (DetourTransactionBegin() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to begin transaction");
    return false;
  }
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to update thread");
    goto abort;
  }
  DetourDetach((PVOID *)&TrueEntryPoint, (void *)MyEntryPoint);
  DetourDetach((PVOID *)&TrueCoInitializeEx, (void *)MyCoInitializeEx);
  if (TrueIFileDialog_Show != NULL) {
    DetourDetach((PVOID *)&TrueIFileDialog_Release, (void *)MyIFileDialog_Release);
    DetourDetach((PVOID *)&TrueIFileDialog_Show, (void *)MyIFileDialog_Show);
    DetourDetach((PVOID *)&TrueIFileDialog_SetFileTypes, (void *)MyIFileDialog_SetFileTypes);
    DetourDetach((PVOID *)&TrueIFileDialog_Advise, (void *)MyIFileDialog_Advise);
    DetourDetach((PVOID *)&TrueIFileDialog_Unadvise, (void *)MyIFileDialog_Unadvise);
    DetourDetach((PVOID *)&TrueIFileDialog_GetResult, (void *)MyIFileDialog_GetResult);
  }
  DetourDetach((PVOID *)&TrueGetSaveFileNameW, (void *)MyGetSaveFileNameW);
  DetourDetach((PVOID *)&TrueGetSaveFileNameA, (void *)MyGetSaveFileNameA);
  if (DetourTransactionCommit() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to commit");
    goto abort;
  }
  return true;
abort:
  if (DetourTransactionAbort() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to abort");
  }
  return false;
}

static bool init_shared_memory(void) {
  struct asas_setting *p = NULL;
  enum { slen = 128 };
  wchar_t s[slen] = {0};
  {
    wchar_t s2[slen] = {0};
    DWORD r = GetEnvironmentVariableW(L"ASAS", s2, 64);
    if (r == 0 || r >= 64) {
      // generate fmo name because valid fmo name is not present
      wsprintfW(s, L"ASAS%d", GetCurrentProcessId());
    } else {
      wsprintfW(s, L"ASAS-%s", s2);
    }
  }
  uint32_t flags = 0;
  DBG(debug_info, L"fmo name: %s", s);
  g_fmo = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(struct asas_setting), s);
  if (g_fmo != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
    DBG(debug_error, L"%s", L"CreateFileMapping failed");
    goto fail;
  }
  wcscat(s, L"-Mutex");
  DBG(debug_info, L"mutex name: %s", s);
  g_mutex = CreateMutexW(NULL, TRUE, s);
  if (g_mutex == NULL) {
    DBG(debug_error, L"%s", L"CreateMutex failed");
    goto fail;
  }

  p = (struct asas_setting *)MapViewOfFile(g_fmo, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
  if (p == NULL) {
    DBG(debug_error, L"%s", L"MapViewOfFile failed");
    goto fail;
  }
  p->api_version = 0;

  DWORD n, r;
  n = ARRAY_SIZE(p->folder);
  r = GetEnvironmentVariableW(L"ASAS_FOLDER", p->folder, n);
  if (r == 0 || r >= n) {
    if (!SHGetSpecialFolderPathW(NULL, p->folder, CSIDL_PERSONAL, FALSE)) {
      goto fail;
    }
  }
  DBG(debug_info, L"folder: %s", p->folder);

  n = ARRAY_SIZE(p->filter);
  r = GetEnvironmentVariableW(L"ASAS_FILTER", p->filter, n);
  if (r == 0 || r >= n) {
    wcscpy(p->filter, L"*.txt");
  }
  DBG(debug_info, L"filter: %s", p->filter);

  n = ARRAY_SIZE(p->format);
  r = GetEnvironmentVariableW(L"ASAS_FORMAT", p->format, n);
  if (r == 0 || r >= n) {
    if (!get_module_name(p->format, n)) {
      wcscpy(p->format, L"asas");
    }

    size_t written = wcsnlen(p->format, n);

    wchar_t const *part = L"_*";
    size_t partlen = wcslen(part);
    if (written + partlen >= n) {
      DBG(debug_error, L"%s", L"cannot append string");
      goto fail;
    }
    wcscat(p->format, part);
    written += partlen;

    part = extract_file_extension(p->filter);
    if (!part) {
      part = L".asas";
    }
    partlen = wcslen(part);
    if (written + partlen >= n) {
      DBG(debug_error, L"%s", L"cannot append string");
      goto fail;
    }
    wcscat(p->format, part);
  }
  DBG(debug_info, L"format: %s", p->format);

  p->flags = asas_flags_active | asas_flags_confirm;
  r = GetEnvironmentVariableW(L"ASAS_FLAGS", s, slen);
  if (0 < r && r < slen && atou32(s, &flags)) {
    p->flags = flags;
  }
  DBG(debug_info, L"flags: %d", p->flags);
  DBG(debug_info, L"  1 FLAGS_ACTIVE: %s", (p->flags & asas_flags_active) ? L"Yes" : L"No");
  DBG(debug_info, L"  2 FLAGS_USE_GIVEN_FILENAME: %s", (p->flags & asas_flags_use_given_filename) ? L"Yes" : L"No");
  DBG(debug_info, L"  4 FLAGS_CONFIRM: %s", (p->flags & asas_flags_confirm) ? L"Yes" : L"No");

  UnmapViewOfFile(p);
  p = NULL;
  ReleaseMutex(g_mutex);
  return true;

fail:
  if (p != NULL) {
    UnmapViewOfFile(p);
    p = NULL;
  }
  if (g_fmo != NULL) {
    CloseHandle(g_fmo);
    g_fmo = NULL;
  }
  if (g_mutex != NULL) {
    CloseHandle(g_mutex);
    g_mutex = NULL;
  }
  return false;
}

static void free_shared_memory(void) {
  if (g_fmo != NULL) {
    CloseHandle(g_fmo);
    g_fmo = NULL;
  }
  if (g_mutex != NULL) {
    CloseHandle(g_mutex);
    g_mutex = NULL;
  }
}

static void init_logger(void) {
  wchar_t buf[MAX_PATH] = {0};
  uint32_t u = 0;
  DWORD r = GetEnvironmentVariableW(L"ASAS_LOG", buf, ARRAY_SIZE(buf));
  if (0 < r && r < ARRAY_SIZE(buf)) {
    wcscpy(g_log_filename, buf);
  }
  r = GetEnvironmentVariableW(L"ASAS_LOGLEVEL", buf, ARRAY_SIZE(buf));
  if (0 < r && r < ARRAY_SIZE(buf) && atou32(buf, &u)) {
    g_log_level = (int)u;
  }
}

int WINAPI MyEntryPoint(VOID) {
  init_logger();
  DBG(debug_info, L"asas %s", VERSION_WIDE);
  if (!init_shared_memory()) {
    DBG(debug_error, L"%s", L"failed to initialize shared memory");
  }
  if (attach_process()) {
    DBG(debug_info, L"%s", L"ready");
  } else {
    DBG(debug_warn, L"%s", L"initialization failed");
  }
  return TrueEntryPoint();
}

static HMODULE g_instance = NULL;

BOOL APIENTRY MyCreateProcess(LPCWSTR lpApplicationName,
                              LPWSTR lpCommandLine,
                              LPSECURITY_ATTRIBUTES lpProcessAttributes,
                              LPSECURITY_ATTRIBUTES lpThreadAttributes,
                              BOOL bInheritHandles,
                              DWORD dwCreationFlags,
                              LPVOID lpEnvironment,
                              LPCWSTR lpCurrentDirectory,
                              LPSTARTUPINFOW lpStartupInfo,
                              LPPROCESS_INFORMATION lpProcessInformation);
BOOL APIENTRY MyCreateProcess(LPCWSTR lpApplicationName,
                              LPWSTR lpCommandLine,
                              LPSECURITY_ATTRIBUTES lpProcessAttributes,
                              LPSECURITY_ATTRIBUTES lpThreadAttributes,
                              BOOL bInheritHandles,
                              DWORD dwCreationFlags,
                              LPVOID lpEnvironment,
                              LPCWSTR lpCurrentDirectory,
                              LPSTARTUPINFOW lpStartupInfo,
                              LPPROCESS_INFORMATION lpProcessInformation) {
  char dllpath[MAX_PATH] = {0};
  DWORD r = GetModuleFileNameA(g_instance, dllpath, ARRAY_SIZE(dllpath));
  if (r == 0 || r >= ARRAY_SIZE(dllpath)) {
    SetLastError(ERROR_BUFFER_OVERFLOW);
    return false;
  }
  return DetourCreateProcessWithDllExW(lpApplicationName,
                                       lpCommandLine,
                                       lpProcessAttributes,
                                       lpThreadAttributes,
                                       bInheritHandles,
                                       dwCreationFlags,
                                       lpEnvironment,
                                       lpCurrentDirectory,
                                       lpStartupInfo,
                                       lpProcessInformation,
                                       dllpath,
                                       NULL);
}

static bool g_attached = false;

static bool attach_entry_point(void) {
  TrueEntryPoint = (int(WINAPI *)(VOID))DetourGetEntryPoint(NULL);
  if (DetourTransactionBegin() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to begin transaction");
    return false;
  }
  if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to update thread");
    goto abort;
  }
  if (DetourAttach((PVOID *)&TrueEntryPoint, (void *)MyEntryPoint) != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to attach EntryPoint");
    goto abort;
  }
  if (DetourTransactionCommit() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to commit");
    goto abort;
  }
  return true;
abort:
  if (DetourTransactionAbort() != NO_ERROR) {
    DBG(debug_error, L"%s", L"failed to abort");
  }
  return false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  (void)lpReserved;
  if (g_instance == NULL) {
    g_instance = hModule;
  }
  if (DetourIsHelperProcess()) {
    return TRUE;
  }
  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    if (DetourRestoreAfterWith()) {
      g_attached = attach_entry_point();
    }
  } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    if (g_attached) {
      detach_process();
    }
    free_shared_memory();
    DBG(debug_info, L"%s", L"shutdown");
  }
  return TRUE;
}
