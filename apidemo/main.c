#include <stdint.h>
#include <stdio.h>

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

enum {
	FLAGS_ACTIVE = 1,
	FLAGS_USE_GIVEN_FILENAME = 2,
	FLAGS_CONFIRM = 4,
};
struct asas {
	uint32_t APIVer; // Œ»Ý‚Í 0 ‚Ì‚Ý
	uint32_t Flags;
	wchar_t Filter[MAX_PATH];
	wchar_t Folder[MAX_PATH];
	wchar_t Format[MAX_PATH];
};

int main(void){
    HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, TEXT("ASAS-Hello-Mutex"));
    if (hMutex == NULL) {
        printf("OpenMutex ‚ÉŽ¸”s‚µ‚Ü‚µ‚½B\n");
        return 0;
    }
    HANDLE hFMO = OpenFileMapping(FILE_MAP_READ, FALSE, TEXT("ASAS-Hello"));
    if (hFMO == NULL) {
        printf("OpenFileMapping ‚ÉŽ¸”s‚µ‚Ü‚µ‚½B\n");
        goto CloseMutex;
    }
    struct asas* p = MapViewOfFile(hFMO, FILE_MAP_READ, 0, 0, 0);
    if (p == NULL) {
        printf("MapViewOfFile ‚ÉŽ¸”s‚µ‚Ü‚µ‚½B\n");
        goto CloseFMO;
    }

    WaitForSingleObject(hMutex, INFINITE);
    printf("APIVer: %d\n", p->APIVer);
    printf("Flags: %d\n", p->Flags);
    printf("Filter: %ls\n", p->Filter);
    printf("Folder: %ls\n", p->Folder);
    printf("Format: %ls\n", p->Format);
    ReleaseMutex(hMutex);

    UnmapViewOfFile(p);
CloseFMO:
    CloseHandle(hFMO);
CloseMutex:
    CloseHandle(hMutex);
    return 0;
}