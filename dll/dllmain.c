#include "pch.h"

enum {
	FLAGS_ACTIVE = 1,
	FLAGS_USE_GIVEN_FILENAME = 2,
	FLAGS_CONFIRM = 4,
};
struct asas_setting {
	uint32_t APIVer;
	uint32_t Flags;
	wchar_t Filter[MAX_PATH];
	wchar_t Folder[MAX_PATH];
	wchar_t Format[MAX_PATH];
};

static HANDLE mutex = NULL;
static HANDLE fmo = NULL;

static HRESULT(WINAPI* TrueCoInitializeEx)(LPVOID pvReserved, DWORD dwCoInit) = CoInitializeEx;
static ULONG(WINAPI* TrueIFileDialog_Release)(IFileDialog* This) = NULL;
static HRESULT(WINAPI* TrueIFileDialog_Show)(IFileDialog* This, HWND hwndOwner) = NULL;
static HRESULT(WINAPI* TrueIFileDialog_SetFileTypes)(IFileDialog* This, UINT cFileTypes, const COMDLG_FILTERSPEC* rgFilterSpec) = NULL;
static HRESULT(WINAPI* TrueIFileDialog_Advise)(IFileDialog* This, IFileDialogEvents* pfde, DWORD* pdwCookie) = NULL;
static HRESULT(WINAPI* TrueIFileDialog_Unadvise)(IFileDialog* This, DWORD dwCookie) = NULL;
static HRESULT(WINAPI* TrueIFileDialog_GetResult)(IFileDialog* This, IShellItem** ppsi) = NULL;

static BOOL(WINAPI* TrueGetSaveFileNameA)(LPOPENFILENAMEA lpofna) = GetSaveFileNameA;
static BOOL(WINAPI* TrueGetSaveFileNameW)(LPOPENFILENAMEW lpofnw) = GetSaveFileNameW;

enum {
	DEBUG_INFO = 0,
	DEBUG_WARN = 1,
	DEBUG_ERROR = 2,
};

static int log_level = 2;
static wchar_t log_filename[MAX_PATH] = { 0 };

static void WINAPI Debug(const int level, const wchar_t* fmt, ...)
{
	if (level < log_level) {
		return;
	}
	wchar_t s[2048] = { 0 };
	va_list list;
	va_start(list, fmt);
	StringCchVPrintfW(s, 2048, fmt, list);
	va_end(list);
	OutputDebugStringW(s);
	if (log_filename[0] != '\0') {
		StringCchCatW(s, 2048, L"\r\n");
		char u8[4096] = { 0 };
		int u8len = WideCharToMultiByte(CP_UTF8, 0, s, -1, u8, 4096, NULL, NULL);
		if (!u8len) {
			return;
		}
		HANDLE h = CreateFileW(log_filename, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h == INVALID_HANDLE_VALUE) {
			return;
		}
		if (SetFilePointer(h, 0, 0, FILE_END) == INVALID_SET_FILE_POINTER) {
			CloseHandle(h);
			return;
		}
		DWORD written = 0;
		if (!WriteFile(h, u8, u8len-1, &written, NULL)) {
			CloseHandle(h);
			return;
		}
		CloseHandle(h);
	}
}
#define Dbg(lv, fmt, ...) Debug(lv, L"asas%d(%d): %s: " fmt, DETOURS_BITS, __LINE__, __FUNCTIONW__, __VA_ARGS__)

static bool atou32(wchar_t* s, uint32_t* ret)
{
	uint64_t r = 0;
	for (size_t i = 0; s[i]; ++i) {
		if (i >= 10 || '0' > s[i] || s[i] > '9') {
			return false;
		}
		r = r * 10 + s[i] - '0';
	}
	if (r > 0xffffffff) {
		return false;
	}
	*ret = r & 0xffffffff;
	return true;
}

static bool is_same(const void* p1, const void* p2, size_t n)
{
	uint8_t* pp1 = (void*)p1, * pp2 = (void*)p2;
	while (n)
	{
		if (*pp1++ != *pp2++) {
			return false;
		}
		--n;
	}
	return true;
}

static bool is_same_stringi(const wchar_t* s1, const wchar_t* s2) {
	for (size_t i = 0; s1[i] && s2[i]; ++i)
	{
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

static bool is_valid_filename(const wchar_t* s)
{
	if (s == NULL || s[0] == '\0') {
		return false;
	}
	for (size_t i = 0; s[i]; ++i)
	{
		if (s[i] <= 0x1f ||
			s[i] == 0x22 || s[i] == 0x2a || s[i] == 0x2f ||
			s[i] == 0x3a || s[i] == 0x3c || s[i] == 0x3e || s[i] == 0x3f ||
			s[i] == 0x7c || s[i] == 0x7f
			) {
			return false;
		}
	}
	return true;
}

static wchar_t last_char(const wchar_t* s)
{
	size_t i = 0;
	while (s[i]) ++i;
	return s[i - 1];
}

static int find_char(const wchar_t* s, wchar_t ch1, wchar_t ch2)
{
	for (int i = 0; s[i]; ++i)
	{
		if (s[i] == ch1 || s[i] == ch2) {
			return i;

		}
	}
	return -1;
}

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

static int extract_filename_pos(wchar_t* fullpath)
{
	int p = find_char_reverse(fullpath, '\\', '/');
	if (p == -1 || fullpath[p+1] == '\0') {
		return -1;
	}
	return p + 1;
}

static bool get_module_filename(wchar_t* s, size_t len, bool trim_ext)
{
	wchar_t m[MAX_PATH] = { 0 };
	DWORD r = GetModuleFileNameW(NULL, m, MAX_PATH);
	if (r == 0 || r == MAX_PATH) {
		return false;
	}
	int fnpos = extract_filename_pos(m);
	if (fnpos == -1) {
		return false;
	}
	if (trim_ext) {
		int p = find_char_reverse(&m[fnpos], '.', '.');
		if (p != -1) {
			m[fnpos+p] = '\0';
		}
	}
	s[0] = '\0';
	if (!SUCCEEDED(StringCchCatW(s, len, &m[fnpos]))) {
		return false;
	}
	return true;
}

static bool get_shared_setting(struct asas_setting* setting) {
	if (!fmo || !mutex) {
		Dbg(DEBUG_WARN, L"%s", L"fmo is not ready");
		return false;
	}
	DWORD r = WaitForSingleObject(mutex, INFINITE);
	if (r != WAIT_OBJECT_0) {
		Dbg(DEBUG_ERROR, L"%s", L"WaitForSingleObject failed");
		return false;
	}
	struct asas_setting* p = MapViewOfFile(fmo, FILE_MAP_READ, 0, 0, 0);
	if (p == NULL) {
		Dbg(DEBUG_ERROR, L"%s", L"MapViewOfFile failed");
		ReleaseMutex(mutex);
		return false;
	}
	*setting = *p;
	UnmapViewOfFile(p);
	ReleaseMutex(mutex);
	return true;
}

static bool build_filename(wchar_t* str, size_t len, wchar_t* folder, wchar_t* fmt, wchar_t* given_filename)
 {
	str[0] = '\0';
	if (!SUCCEEDED(StringCchCatW(str, len, folder))) {
		Dbg(DEBUG_ERROR, L"%s", L"cannot copy folder path to string");
		return false;
	}
	wchar_t lc = last_char(str);
	if (lc != '\\' && lc != '/') {
		if (!SUCCEEDED(StringCchCatW(str, len, L"\\"))) {
			Dbg(DEBUG_ERROR, L"%s", L"cannot append path delimiter");
			return false;
		}
	}
	if (is_valid_filename(given_filename)) {
		if (!SUCCEEDED(StringCchCatW(str, len, given_filename))) {
			Dbg(DEBUG_ERROR, L"%s", L"cannot copy to string");
			return false;
		}
		return true;
	}
	wchar_t s[MAX_PATH] = { 0 };
	size_t i = 0;
	while (*fmt != '\0' && i < MAX_PATH) {
		if (*fmt == '*') {
			SYSTEMTIME st = { 0 };
			GetLocalTime(&st);
			if (!SUCCEEDED(StringCchPrintfW(
				s + i, MAX_PATH - i,
				L"%04d%02d%02d%02d%02d%02d",
				st.wYear, st.wMonth, st.wDay,
				st.wHour, st.wMinute, st.wSecond
			))) {
				Dbg(DEBUG_ERROR, L"%s", L"cannot append datetime");
				return false;
			}
			i += 14;
			++fmt;
			continue;
		}
		s[i++] = *fmt++;
	}
	if (*fmt != '\0' || !is_valid_filename(s)) {
		Dbg(DEBUG_ERROR, L"%s is not valid filename", s);
		return false;
	}
	if (!SUCCEEDED(StringCchCatW(str, len, s))) {
		Dbg(DEBUG_ERROR, L"%s", L"cannot copy to string");
		return false;
	}
	return true;
}

struct my_file_system_bind_data {
	const struct IFileSystemBindDataVtbl* lpVtbl;
	LONG ref;
	WIN32_FIND_DATAW fd;
};

static HRESULT WINAPI my_file_system_bind_data_QueryInterface(IFileSystemBindData* This, REFIID riid, void** ppv)
{
	if (is_same(riid, &IID_IFileSystemBindData, sizeof(IID)) || is_same(riid, &IID_IUnknown, sizeof(IID))) {
		This->lpVtbl->AddRef(This);
		*ppv = This;
		return S_OK;
	}
	*ppv = NULL;
	return E_NOINTERFACE;
}

static ULONG WINAPI my_file_system_bind_data_AddRef(IFileSystemBindData* This)
{
	struct my_file_system_bind_data* t = (void*)This;
	return InterlockedIncrement(&t->ref);
}

static ULONG WINAPI my_file_system_bind_data_Release(IFileSystemBindData* This)
{
	struct my_file_system_bind_data* t = (void*)This;
	LONG r = InterlockedDecrement(&t->ref);
	if (r == 0) {
		CoTaskMemFree(This);
	}
	return r;
}

static HRESULT WINAPI my_file_system_bind_data_SetFindData(IFileSystemBindData* This, const WIN32_FIND_DATAW* pfd)
{
	struct my_file_system_bind_data* t = (void*)This;
	t->fd = *pfd;
	return S_OK;
}

static HRESULT WINAPI my_file_system_bind_data_GetFindData(IFileSystemBindData* This, WIN32_FIND_DATAW* pfd)
{
	struct my_file_system_bind_data* t = (void*)This;
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

enum { num_state = 8, num_events = 4 };
static struct save_dialog_state {
	IFileDialog* This;
	bool is_save;
	bool skip_dialog;
	wchar_t filename[MAX_PATH];
	struct {
		IFileDialogEvents* pfde;
		DWORD cookie;
	} events[num_events];
} states[num_state] = { 0 };
static DWORD no_interrupt = 0;

static bool is_save_dialog(IFileDialog* This)
{
	IFileSaveDialog* fsd = NULL;
	if (!SUCCEEDED(This->lpVtbl->QueryInterface(This, &IID_IFileSaveDialog, &fsd))) {
		return false;
	}
	fsd->lpVtbl->Release(fsd);
	return true;
}

static struct save_dialog_state* set_state(IFileDialog* This)
{
	for (int i = 0; i < num_state; ++i) {
		if (states[i].This == NULL) {
			states[i].This = This;
			states[i].is_save = is_save_dialog(This);
			states[i].skip_dialog = false;
			for (int j = 0; j < num_events; ++j) {
				states[i].events[j].pfde = NULL;
				states[i].events[j].cookie = 0;
			}
			return &states[i];
		}
	}
	return NULL;
}

static struct save_dialog_state* get_state(IFileDialog* This)
{
	for (int i = 0; i < num_state; ++i) {
		if (states[i].This == This) {
			return &states[i];
		}
	}
	return set_state(This);
}

static ULONG WINAPI MyIFileDialog_Release(IFileDialog* This)
{
	ULONG r = TrueIFileDialog_Release(This);
	if (r == 0) {
		for (int i = 0; i < num_state; ++i) {
			if (states[i].This == This) {
				ZeroMemory(&states[i], sizeof(struct save_dialog_state));
				break;
			}
		}
	}
	return r;
}

static HRESULT WINAPI MyIFileDialog_SetFileTypes(IFileDialog* This, UINT cFileTypes, const COMDLG_FILTERSPEC* rgFilterSpec)
{
	Dbg(DEBUG_INFO, L"%s", L"begin");
	if (no_interrupt > 0) {
		Dbg(DEBUG_INFO, L"%s", L"currently no active by internal reason");
		goto call;
	}
	struct save_dialog_state* const s = get_state(This);
	if (s == NULL) {
		Dbg(DEBUG_ERROR, L"%s", L"cannot get state");
		goto call;
	}
	if (!s->is_save) {
		Dbg(DEBUG_INFO, L"%s", L"is not save dialog");
		goto call;
	}
	struct asas_setting setting = { 0 };
	if (!get_shared_setting(&setting)) {
		Dbg(DEBUG_ERROR, L"%s", L"cannot get current setting");
		goto call;
	}
	s->skip_dialog = false;
	for (UINT i = 0; i < cFileTypes; ++i) {
		Dbg(DEBUG_INFO, L"filter #%d %s", i+1, rgFilterSpec[i].pszSpec);
		if (is_same_stringi(rgFilterSpec[i].pszSpec, setting.Filter)) {
			Dbg(DEBUG_INFO, L"%s", L"found matched filter");
			s->skip_dialog = true;
			goto call;
		}
	}
	Dbg(DEBUG_INFO, L"%s", L"matched filter not found");
call:
	return TrueIFileDialog_SetFileTypes(This, cFileTypes, rgFilterSpec);
}

static HRESULT WINAPI MyIFileDialog_Show(IFileDialog* This, HWND hwndOwner)
{
	Dbg(DEBUG_INFO, L"%s", L"begin");
	if (no_interrupt > 0) {
		Dbg(DEBUG_INFO, L"%s", L"currently no active by internal reason");
		goto call;
	}
	struct save_dialog_state* const s = get_state(This);
	if (s == NULL || !s->is_save || !s->skip_dialog) {
		goto call;
	}

	struct asas_setting setting = { 0 };
	if (!get_shared_setting(&setting)) {
		Dbg(DEBUG_ERROR, L"%s", L"cannot get current setting");
		goto call;
	}
	if (!(setting.Flags & FLAGS_ACTIVE)) {
		Dbg(DEBUG_INFO, L"%s", L"asas is not active");
		goto call;
	}

	bool show_msgbox = false;
	wchar_t given_filename[MAX_PATH] = { 0 };
	if (setting.Flags & FLAGS_USE_GIVEN_FILENAME) {
		LPWSTR s = NULL;
		if (SUCCEEDED(This->lpVtbl->GetFileName(This, &s))) {
			HRESULT hr = StringCchCatW(given_filename, MAX_PATH, s);
			CoTaskMemFree(s);
			if (!SUCCEEDED(hr)) {
				Dbg(DEBUG_ERROR, L"%s", L"cannot copy given filename");
				goto call;
			}
		}
	}
	if (!build_filename(s->filename, sizeof(s->filename) / sizeof(s->filename[0]), setting.Folder, setting.Format, given_filename)) {
		MessageBoxW(hwndOwner, L"Failed to compose filename.", L"asas", MB_ICONERROR);
		return HRESULT_FROM_WIN32(ERROR_CANCELLED);
	}
	if (setting.Flags & FLAGS_CONFIRM) {
		wchar_t str[1024];
		if (!SUCCEEDED(StringCchPrintfW(str, 1024, L"Are you sure you want to save with the following filename?\n\n%s", s->filename))) {
			MessageBoxW(hwndOwner, L"Failed to compose confirm message.", L"asas", MB_ICONERROR);
			return HRESULT_FROM_WIN32(ERROR_CANCELLED);
		}
		switch (MessageBoxW(hwndOwner, str, L"asas", MB_ICONQUESTION | MB_YESNOCANCEL)) {
		case IDYES:
			break;
		case IDNO:
			s->skip_dialog = false;
			goto call;
		case IDCANCEL:
			Dbg(DEBUG_INFO, L"%s", L"aborted by user");
			return HRESULT_FROM_WIN32(ERROR_CANCELLED);
		}
	}
	for (int i = 0; i < num_state; ++i) {
		if (s->events[i].pfde != NULL) {
			if (!SUCCEEDED(s->events[i].pfde->lpVtbl->OnFileOk(s->events[i].pfde, This))) {
				Dbg(DEBUG_INFO, L"%s", L"aborted by IFileDialogEvent");
				return HRESULT_FROM_WIN32(ERROR_CANCELLED);
			}
		}
	}
	return S_OK;
call:
	return TrueIFileDialog_Show(This, hwndOwner);
}

static HRESULT WINAPI MyIFileDialog_Advise(IFileDialog* This, IFileDialogEvents* pfde, DWORD* pdwCookie)
{
	Dbg(DEBUG_INFO, L"%s", L"begin");
	HRESULT hr = TrueIFileDialog_Advise(This, pfde, pdwCookie);
	if (!SUCCEEDED(hr)) {
		return hr;
	}
	if (no_interrupt > 0) {
		Dbg(DEBUG_INFO, L"%s", L"currently no active by internal reason");
		return hr;
	}
	struct save_dialog_state* const s = get_state(This);
	if (s == NULL || !s->is_save) {
		return hr;
	}
	for (int i = 0; i < num_events; ++i) {
		if (s->events[i].pfde == NULL) {
			s->events[i].pfde = pfde;
			s->events[i].cookie = *pdwCookie;
			return hr;
		}
	}
	Dbg(DEBUG_WARN, L"%s", L"failed to register IFileDialogEvents");
	return hr;
}

static HRESULT WINAPI MyIFileDialog_Unadvise(IFileDialog* This, DWORD dwCookie)
{
	Dbg(DEBUG_INFO, L"%s", L"begin");
	HRESULT hr = TrueIFileDialog_Unadvise(This, dwCookie);
	if (!SUCCEEDED(hr)) {
		return hr;
	}
	if (no_interrupt > 0) {
		Dbg(DEBUG_INFO, L"%s", L"currently no active by internal reason");
		return hr;
	}
	struct save_dialog_state* const s = get_state(This);
	if (s == NULL || !s->is_save) {
		return hr;
	}
	for (int i = 0; i < num_events; ++i) {
		if (s->events[i].cookie == dwCookie) {
			s->events[i].pfde = NULL;
			s->events[i].cookie = 0;
			return hr;
		}
	}
	return hr;
}

static HRESULT WINAPI MyIFileDialog_GetResult(IFileDialog* This, IShellItem** ppsi)
{
	Dbg(DEBUG_INFO, L"%s", L"begin");
	if (no_interrupt > 0) {
		Dbg(DEBUG_INFO, L"%s", L"currently no active by internal reason");
		goto call;
	}
	struct save_dialog_state* const s = get_state(This);
	if (s == NULL || !s->is_save || !s->skip_dialog) {
		goto call;
	}
	if (s->filename[0] == '\0') {
		return S_FALSE;
	}
	IShellFolder* shell_folder = NULL;
	HRESULT hr = SHGetDesktopFolder(&shell_folder);
	if (!SUCCEEDED(hr)) {
		Dbg(DEBUG_ERROR, L"SHGetDesktopFolder failed %08x", hr);
		return S_FALSE;
	}
	IBindCtx* bctx = NULL;
	hr = CreateBindCtx(0, &bctx);
	if (!SUCCEEDED(hr)) {
		Dbg(DEBUG_ERROR, L"CreateBindCtx failed %08x", hr);
		return S_FALSE;
	}
	{
		struct my_file_system_bind_data* fsbd = CoTaskMemAlloc(sizeof(struct my_file_system_bind_data));
		if (fsbd == NULL) {
			Dbg(DEBUG_ERROR, L"CoTaskMemAlloc failed %08x", hr);
			return S_FALSE;
		}
		fsbd->lpVtbl = &my_file_system_bind_data_vtbl;
		fsbd->ref = 1;
		ZeroMemory(&fsbd->fd, sizeof(WIN32_FIND_DATAW));
		fsbd->fd.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		if (!SUCCEEDED(StringCchCatW(fsbd->fd.cFileName, sizeof(fsbd->fd.cFileName) / sizeof(fsbd->fd.cFileName[0]), s->filename))) {
			Dbg(DEBUG_ERROR, L"%s", L"cannot copy filename to WIN32_FIND_DATAW");
			return S_FALSE;
		}
		bctx->lpVtbl->RegisterObjectParam(bctx, L"File System Bind Data", (IUnknown*)fsbd);
		fsbd->lpVtbl->Release((void*)fsbd);
		fsbd = NULL;
	}
	LPITEMIDLIST pidl = NULL;
	hr = shell_folder->lpVtbl->ParseDisplayName(shell_folder, NULL, bctx, s->filename, NULL, &pidl, NULL);
	if (!SUCCEEDED(hr)) {
		Dbg(DEBUG_ERROR, L"ParseDisplayName failed %08x", hr);
		return S_FALSE;
	}
	hr = SHCreateShellItem(NULL, NULL, pidl, ppsi);
	if (!SUCCEEDED(hr)) {
		Dbg(DEBUG_ERROR, L"SHCreateShellItem failed %08x", hr);
		return S_FALSE;
	}
	return S_OK;
call:
	return TrueIFileDialog_GetResult(This, ppsi);
}

static bool attach_interface(IFileDialog* fd)
{
	TrueIFileDialog_Release = fd->lpVtbl->Release;
	TrueIFileDialog_Show = fd->lpVtbl->Show;
	TrueIFileDialog_SetFileTypes = fd->lpVtbl->SetFileTypes;
	TrueIFileDialog_Advise = fd->lpVtbl->Advise;
	TrueIFileDialog_Unadvise = fd->lpVtbl->Unadvise;
	TrueIFileDialog_GetResult = fd->lpVtbl->GetResult;

	if (DetourTransactionBegin() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to begin transaction");
		return false;
	}
	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to update thread");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueIFileDialog_Release, MyIFileDialog_Release) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach Release ");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueIFileDialog_Show, MyIFileDialog_Show) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach Show");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueIFileDialog_SetFileTypes, MyIFileDialog_SetFileTypes) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach SetFileTypes");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueIFileDialog_Advise, MyIFileDialog_Advise) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach Advise");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueIFileDialog_Unadvise, MyIFileDialog_Unadvise) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach Undvise");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueIFileDialog_GetResult, MyIFileDialog_GetResult) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach GetResult");
		goto abort;
	}
	if (DetourTransactionCommit() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to commit");
		goto abort;
	}
	return true;
abort:
	if (DetourTransactionAbort() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to abort");
	}
	return false;
}

static char* find_next_filter_a(const LPOPENFILENAMEA lpofn, char* last)
{
	char* p = NULL;
	if (last == NULL) {
		p = (char*)lpofn->lpstrFilter;
	}
	else {
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
	if (p == '\0') {
		return NULL;
	}
	return p;
}

static wchar_t* find_next_filter_w(const LPOPENFILENAMEW lpofn, wchar_t* last)
{
	wchar_t* p = NULL;
	if (last == NULL) {
		p = (wchar_t*)lpofn->lpstrFilter;
	}
	else {
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
	if (p == '\0') {
		return NULL;
	}
	return p;
}

static bool to_wide(const char* s, wchar_t* const d, const int dlen) {
	return MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, s, -1, d, dlen) != 0;
}

static bool to_mbcs(const wchar_t* s, char* const d, const int dlen) {
	return WideCharToMultiByte(CP_ACP, 0, s, -1, d, dlen, NULL, NULL) != 0;
}

static BOOL WINAPI MyGetSaveFileNameA(LPOPENFILENAMEA lpofn)
{
	Dbg(DEBUG_INFO, L"%s", L"begin");
	if (lpofn == NULL) {
		goto call;
	}
	struct asas_setting setting = { 0 };
	if (!get_shared_setting(&setting)) {
		Dbg(DEBUG_ERROR, L"%s", L"cannot get current setting");
		goto call;
	}
	if (!(setting.Flags & FLAGS_ACTIVE)) {
		Dbg(DEBUG_INFO, L"%s", L"asas is not active");
		goto call;
	}
	wchar_t w[MAX_PATH] = { 0 };
	int filter_index = 0;
	char* cur = find_next_filter_a(lpofn, NULL);
	while (cur != NULL) {
		++filter_index;
		if (!to_wide(cur, w, MAX_PATH)) {
			Dbg(DEBUG_ERROR, L"%s", L"failed to convert to widestring");
			goto call;
		}
		Dbg(DEBUG_INFO, L"filter #%d %s", filter_index, w);
		if (is_same_stringi(w, setting.Filter)) {
			goto autosave;
		}
		cur = find_next_filter_a(lpofn, cur);
	}
	Dbg(DEBUG_INFO, L"%s", L"matched filter not found");
	goto call;
autosave:
	{
		wchar_t filename[MAX_PATH] = { 0 };
		{
			wchar_t buf[MAX_PATH] = { 0 };
			wchar_t* given_filename = NULL;
			if (setting.Flags & FLAGS_USE_GIVEN_FILENAME) {
				if (!to_wide(lpofn->lpstrFile, buf, MAX_PATH)) {
					Dbg(DEBUG_ERROR, L"%s", L"failed to convert to widestring");
					goto call;
				}
				int p = extract_filename_pos(buf);
				if (p != -1) {
					given_filename = &buf[p];
				}
			}
			if (!build_filename(filename, MAX_PATH, setting.Folder, setting.Format, given_filename)) {
				MessageBoxW(lpofn->hwndOwner, L"Failed to compose filename.", L"asas", MB_ICONERROR);
				return FALSE;
			}
		}
		if (setting.Flags & FLAGS_CONFIRM) {
			wchar_t str[1024];
			if (!SUCCEEDED(StringCchPrintfW(str, 1024, L"Are you sure you want to save with the following filename?\n\n%s", filename))) {
				MessageBoxW(lpofn->hwndOwner, L"Failed to compose confirm message.", L"asas", MB_ICONERROR);
				return FALSE;
			}
			switch (MessageBoxW(lpofn->hwndOwner, str, L"asas", MB_ICONQUESTION | MB_YESNOCANCEL)) {
			case IDYES:
				break;
			case IDNO:
			{
				++no_interrupt;
				BOOL r = TrueGetSaveFileNameA(lpofn);
				--no_interrupt;
				return r;
			}
			case IDCANCEL:
				Dbg(DEBUG_INFO, L"%s", L"aborted by user");
				return FALSE;
			}
		}
		if (!to_mbcs(filename, lpofn->lpstrFile, lpofn->nMaxFile)) {
			MessageBoxW(lpofn->hwndOwner, L"lpstrFile buffer is too small.", L"asas", MB_ICONERROR);
			return FALSE;
		}
		size_t fulllen = 0;
		if (!SUCCEEDED(StringCchLengthA(lpofn->lpstrFile, lpofn->nMaxFile, &fulllen))) {
			MessageBoxW(lpofn->hwndOwner, L"Failed to get string length.", L"asas", MB_ICONERROR);
			return FALSE;
		}
		char fn[MAX_PATH] = { 0 };
		int pos = extract_filename_pos(filename);
		if (pos == -1) {
			MessageBoxW(lpofn->hwndOwner, L"Failed to extract filename from fullpath.", L"asas", MB_ICONERROR);
			return FALSE;
		}
		if (!to_mbcs(&filename[pos], fn, MAX_PATH)) {
			MessageBoxW(lpofn->hwndOwner, L"Failed to convert string to mbcs.", L"asas", MB_ICONERROR);
			return FALSE;
		}
		size_t len = 0;
		if (!SUCCEEDED(StringCchLengthA(fn, MAX_PATH, &len))) {
			MessageBoxW(lpofn->hwndOwner, L"Failed to get string length.", L"asas", MB_ICONERROR);
			return FALSE;
		}
		lpofn->nFileOffset = (WORD)(fulllen - len);
		if (lpofn->lpstrFileTitle != NULL) {
			lpofn->lpstrFileTitle[0] = '\0';
			if (!SUCCEEDED(StringCchCatA(lpofn->lpstrFileTitle, lpofn->nMaxFileTitle, fn))) {
				MessageBoxW(lpofn->hwndOwner, L"lpstrFileTitle buffer is too small", L"asas", MB_ICONERROR);
				return FALSE;
			}
		}
		int extpos = find_char_reverse(&filename[pos], '.', '.');
		if (extpos == -1) {
			lpofn->nFileExtension = 0;
		}
		else {
			if (!to_mbcs(&filename[pos+extpos+1], fn, MAX_PATH)) {
				MessageBoxW(lpofn->hwndOwner, L"Failed to convert string to mbcs.", L"asas", MB_ICONERROR);
				return FALSE;
			}
			if (!SUCCEEDED(StringCchLengthA(fn, MAX_PATH, &len))) {
				MessageBoxW(lpofn->hwndOwner, L"Failed to get string length.", L"asas", MB_ICONERROR);
				return FALSE;
			}
			lpofn->nFileExtension = (WORD)(fulllen - len);
		}
		lpofn->nFilterIndex = filter_index;
		return TRUE;
	}
call:
	return TrueGetSaveFileNameA(lpofn);
}

static BOOL WINAPI MyGetSaveFileNameW(LPOPENFILENAMEW lpofn)
{
	Dbg(DEBUG_INFO, L"%s", L"begin");
	if (lpofn == NULL) {
		goto call;
	}
	struct asas_setting setting = { 0 };
	if (!get_shared_setting(&setting)) {
		Dbg(DEBUG_ERROR, L"%s", L"cannot get current setting");
		goto call;
	}
	if (!(setting.Flags & FLAGS_ACTIVE)) {
		Dbg(DEBUG_INFO, L"%s", L"asas is not active");
		goto call;
	}
	int filter_index = 0;
	wchar_t* cur = find_next_filter_w(lpofn, NULL);
	while (cur != NULL) {
		++filter_index;
		Dbg(DEBUG_INFO, L"filter #%d %s", filter_index, cur);
		if (is_same_stringi(cur, setting.Filter)) {
			goto autosave;
		}
		cur = find_next_filter_w(lpofn, cur);
	}
	Dbg(DEBUG_INFO, L"%s", L"matched filter not found");
	goto call;
autosave:
	{
		wchar_t filename[MAX_PATH] = { 0 };
		{
			wchar_t* given_filename = NULL;
			if (setting.Flags & FLAGS_USE_GIVEN_FILENAME) {
				int p = extract_filename_pos(lpofn->lpstrFile);
				if (p != -1) {
					given_filename = &lpofn->lpstrFile[p];
				}
			}
			if (!build_filename(filename, MAX_PATH, setting.Folder, setting.Format, given_filename)) {
				MessageBoxW(lpofn->hwndOwner, L"Failed to compose filename.", L"asas", MB_ICONERROR);
				return FALSE;
			}
		}
		if (setting.Flags & FLAGS_CONFIRM) {
			wchar_t str[1024];
			if (!SUCCEEDED(StringCchPrintfW(str, 1024, L"Are you sure you want to save with the following filename?\n\n%s", filename))) {
				MessageBoxW(lpofn->hwndOwner, L"Failed to compose confirm message.", L"asas", MB_ICONERROR);
				return FALSE;
			}
			switch (MessageBoxW(lpofn->hwndOwner, str, L"asas", MB_ICONQUESTION | MB_YESNOCANCEL)) {
			case IDYES:
				break;
			case IDNO:
			{
				++no_interrupt;
				BOOL r = TrueGetSaveFileNameW(lpofn);
				--no_interrupt;
				return r;
			}
			case IDCANCEL:
				Dbg(DEBUG_INFO, L"%s", L"aborted by user");
				return FALSE;
			}
		}
		lpofn->lpstrFile[0] = '\0';
		if (!SUCCEEDED(StringCchCatW(lpofn->lpstrFile, lpofn->nMaxFile, filename))) {
			MessageBoxW(lpofn->hwndOwner, L"lpstrFile buffer is too small", L"asas", MB_ICONERROR);
			return FALSE;
		}
		int fnpos = extract_filename_pos(filename);
		if (fnpos == -1) {
			MessageBoxW(lpofn->hwndOwner, L"Failed to extract filename.", L"asas", MB_ICONERROR);
			return FALSE;
		}
		if (lpofn->lpstrFileTitle != NULL) {
			lpofn->lpstrFileTitle[0] = '\0';
			if (!SUCCEEDED(StringCchCatW(lpofn->lpstrFileTitle, lpofn->nMaxFileTitle, &filename[fnpos]))) {
				MessageBoxW(lpofn->hwndOwner, L"lpstrFileTitle buffer is too small", L"asas", MB_ICONERROR);
				return FALSE;
			}
		}
		lpofn->nFileOffset = fnpos;
		int extpos = find_char_reverse(&filename[fnpos], '.', '.');
		lpofn->nFileExtension = extpos == -1 ? 0 : fnpos+extpos+1;
		lpofn->nFilterIndex = filter_index;
		return TRUE;
	}
call:
	return TrueGetSaveFileNameW(lpofn);
}

static HRESULT WINAPI MyCoInitializeEx(LPVOID pvReserved, DWORD dwCoInit)
{
	const HRESULT hr = TrueCoInitializeEx(pvReserved, dwCoInit);
	if (TrueIFileDialog_Show != NULL) {
		return hr;
	}
	IFileDialog* fd = NULL;
	if (!SUCCEEDED(CoCreateInstance(&CLSID_FileSaveDialog, NULL, CLSCTX_ALL, &IID_IFileDialog, &fd))) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to get IFileDialog");
		return hr;
	}
	attach_interface(fd);
	fd->lpVtbl->Release(fd);
	fd = NULL;
	return hr;
}

static bool attach_process(void)
{
	if (DetourTransactionBegin() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to begin transaction");
		return false;
	}
	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to update thread");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueCoInitializeEx, MyCoInitializeEx) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach CoInitializeEx");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueGetSaveFileNameW, MyGetSaveFileNameW) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach GetSaveFileNameW");
		goto abort;
	}
	if (DetourAttach((PVOID*)&TrueGetSaveFileNameA, MyGetSaveFileNameA) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to attach GetSaveFileNameA");
		goto abort;
	}
	if (DetourTransactionCommit() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to commit");
		goto abort;
	}
	return true;
abort:
	if (DetourTransactionAbort() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to abort");
	}
	return false;
}

static bool detach_process(void)
{
	if (DetourTransactionBegin() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to begin transaction");
		return false;
	}
	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to update thread");
		goto abort;
	}
	DetourDetach((PVOID*)&TrueCoInitializeEx, MyCoInitializeEx);
	if (TrueIFileDialog_Show != NULL) {
		DetourDetach((PVOID*)&TrueIFileDialog_Release, MyIFileDialog_Release);
		DetourDetach((PVOID*)&TrueIFileDialog_Show, MyIFileDialog_Show);
		DetourDetach((PVOID*)&TrueIFileDialog_SetFileTypes, MyIFileDialog_SetFileTypes);
		DetourDetach((PVOID*)&TrueIFileDialog_Advise, MyIFileDialog_Advise);
		DetourDetach((PVOID*)&TrueIFileDialog_Unadvise, MyIFileDialog_Unadvise);
		DetourDetach((PVOID*)&TrueIFileDialog_GetResult, MyIFileDialog_GetResult);
	}
	DetourDetach((PVOID*)&TrueGetSaveFileNameW, MyGetSaveFileNameW);
	DetourDetach((PVOID*)&TrueGetSaveFileNameA, MyGetSaveFileNameA);
	if (DetourTransactionCommit() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to commit");
		goto abort;
	}
	return true;
abort:
	if (DetourTransactionAbort() != NO_ERROR) {
		Dbg(DEBUG_ERROR, L"%s", L"failed to abort");
	}
	return false;
}

static bool init_shared_memory(void) {
	struct asas_setting* p = NULL;
	enum { slen = 128 };
	wchar_t s[slen] = { 0 };
	{
		wchar_t s2[slen] = { 0 };
		DWORD r = GetEnvironmentVariableW(L"ASAS", s2, 64);
		if (r == 0 || r >= 64) {
			// generate fmo name because valid fmo name is not present
			StringCchPrintfW(s, slen, L"ASAS%d", GetCurrentProcessId());
		}
		else {
			StringCchPrintfW(s, slen, L"ASAS-%s", s2);
		}
	}
	Dbg(DEBUG_INFO, L"fmo name: %s", s);
	fmo = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(struct asas_setting), s);
	if (fmo != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
		Dbg(DEBUG_ERROR, L"%s", L"CreateFileMapping failed");
		goto fail;
	}
	StringCchCatW(s, slen, L"-Mutex");
	Dbg(DEBUG_INFO, L"mutex name: %s", s);
	mutex = CreateMutexW(NULL, TRUE, s);
	if (mutex == NULL) {
		Dbg(DEBUG_ERROR, L"%s", L"CreateMutex failed");
		goto fail;
	}

	p = MapViewOfFile(fmo, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (p == NULL) {
		Dbg(DEBUG_ERROR, L"%s", L"MapViewOfFile failed");
		goto fail;
	}
	p->APIVer = 0;

	DWORD n, r;
	n = sizeof(p->Folder) / sizeof(p->Folder[0]);
	r = GetEnvironmentVariableW(L"ASAS_FOLDER", p->Folder, n);
	if (r == 0 || r >= n) {
		if (!SHGetSpecialFolderPathW(NULL, p->Folder, CSIDL_PERSONAL, FALSE)) {
			goto fail;
		}
	}
	Dbg(DEBUG_INFO, L"folder: %s", p->Folder);

	n = sizeof(p->Filter) / sizeof(p->Filter[0]);
	r = GetEnvironmentVariableW(L"ASAS_FILTER", p->Filter, n);
	if (r == 0 || r >= n) {
		p->Filter[0] = '\0';
		if (!SUCCEEDED(StringCchCatW(p->Filter, n, L"*.txt"))) {
			Dbg(DEBUG_ERROR, L"%s", L"cannot copy filter to string");
			goto fail;
		}
	}
	Dbg(DEBUG_INFO, L"filter: %s", p->Filter);

	n = sizeof(p->Format) / sizeof(p->Format[0]);
	r = GetEnvironmentVariableW(L"ASAS_FORMAT", p->Format, n);
	if (r == 0 || r >= n) {
		p->Format[0] = '\0';
		if (!get_module_filename(p->Format, n, true)) {
			p->Format[0] = '\0';
			if (!SUCCEEDED(StringCchCatW(p->Format, n, L"asas"))) {
				Dbg(DEBUG_ERROR, L"%s", L"cannot copy string");
				goto fail;
			}
		}
		if (!SUCCEEDED(StringCchCatW(p->Format, n, L"_*"))) {
			Dbg(DEBUG_ERROR, L"%s", L"cannot append string");
			goto fail;
		}
		const int dotpos = find_char_reverse(p->Filter, '.', '.');
		wchar_t* ext = dotpos == -1 ? L".asas" : &p->Filter[dotpos];
		if (!SUCCEEDED(StringCchCatW(p->Format, n, ext))) {
			Dbg(DEBUG_ERROR, L"%s", L"cannot append string");
			goto fail;
		}
	}
	Dbg(DEBUG_INFO, L"format: %s", p->Format);

	p->Flags = FLAGS_ACTIVE | FLAGS_CONFIRM;
	r = GetEnvironmentVariableW(L"ASAS_FLAGS", s, slen);
	uint32_t flags = 0;
	if (0 < r && r < slen && atou32(s, &flags)) {
		p->Flags = flags;
	}
	Dbg(DEBUG_INFO, L"flags: %d", p->Flags);
	Dbg(DEBUG_INFO, L"  1 FLAGS_ACTIVE: %s", (p->Flags & FLAGS_ACTIVE) ? L"Yes" : L"No");
	Dbg(DEBUG_INFO, L"  2 FLAGS_USE_GIVEN_FILENAME: %s", (p->Flags & FLAGS_USE_GIVEN_FILENAME) ? L"Yes" : L"No");
	Dbg(DEBUG_INFO, L"  4 FLAGS_CONFIRM: %s", (p->Flags & FLAGS_CONFIRM) ? L"Yes" : L"No");

	UnmapViewOfFile(p);
	p = NULL;
	ReleaseMutex(mutex);
	return true;

fail:
	if (p != NULL) {
		UnmapViewOfFile(p);
		p = NULL;
	}
	if (fmo != NULL) {
		CloseHandle(fmo);
		fmo = NULL;
	}
	if (mutex != NULL) {
		CloseHandle(mutex);
		mutex = NULL;
	}
	return false;
}

static void free_shared_memory(void) {
	if (fmo != NULL) {
		CloseHandle(fmo);
		fmo = NULL;
	}
	if (mutex != NULL) {
		CloseHandle(mutex);
		mutex = NULL;
	}
}

static void init_logger(void) {
	wchar_t buf[MAX_PATH] = { 0 };
	uint32_t u;
	DWORD r = GetEnvironmentVariableW(L"ASAS_LOG", buf, MAX_PATH);
	if (0 < r && r < MAX_PATH) {
		log_filename[0] = '\0';
		StringCchCatW(log_filename, sizeof(log_filename) / sizeof(log_filename[0]), buf);
	}
	r = GetEnvironmentVariableW(L"ASAS_LOGLEVEL", buf, MAX_PATH);
	if (0 < r && r < MAX_PATH && atou32(buf, &u)) {
		log_level = (int)u;
	}
}
static HMODULE instance = NULL;

BOOL APIENTRY MyCreateProcess(
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
)
{
	char dllpath[MAX_PATH] = { 0 };
	DWORD r = GetModuleFileNameA(instance, dllpath, MAX_PATH);
	if (r == 0 || r >= MAX_PATH) {
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return false;
	}
	return DetourCreateProcessWithDllExW(
		lpApplicationName,
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

static bool attached = false;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (instance == NULL) {
		instance = hModule;
	}
	if (DetourIsHelperProcess()) {
		return TRUE;
	}
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);
		if (DetourRestoreAfterWith()) {
			init_logger();
			Dbg(DEBUG_INFO, L"boot");
			if (!init_shared_memory()) {
				Dbg(DEBUG_ERROR, L"%s", L"failed to initialize shared memory");
			}
			if (attach_process()) {
				attached = true;
				Dbg(DEBUG_INFO, L"%s", L"ready");
			}
			else {
				Dbg(DEBUG_WARN, L"%s", L"initialization failed");
			}
		}
	} else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		if (attached) {
			detach_process();
		}
		free_shared_memory();
		Dbg(DEBUG_INFO, L"shutdown");
	}
	return TRUE;
}
