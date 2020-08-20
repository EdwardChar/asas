# memo

## Detours で日本語フォルダーが上手く動かない問題

`creatwth.cpp` にある `DetourProcessViaHelperDllsW` が原因。

`StringCchPrintfW` が `&helper->rDlls[0]` を正しく Unicode に変換できていないのが原因。
`%hs` での動作を期待せずに以下のコードに差し替えることで修正。

```c
    WCHAR dll[MAX_PATH];
    if (!MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, &helper->rDlls[0], -1, dll, MAX_PATH)) {
        goto Cleanup;
    }
    hr = StringCchPrintfW(szCommand, ARRAYSIZE(szCommand),
                          L"rundll32.exe \"%ws\",#1", &dll[0]);
    if (!SUCCEEDED(hr)) {
        goto Cleanup;
    }
```