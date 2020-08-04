@echo off
copy README.md bin\asas.txt
copy CHANGELOG.md bin\changelog.txt
cd bin
..\7za.exe a -tzip ..\asas.zip asas.exe asas32.dll asas64.dll asas.txt changelog.txt
cd ..