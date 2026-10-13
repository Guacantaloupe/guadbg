@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /utf-8 /EHsc /O2 /MT /W3 /Foengine\ engine\test_client.cpp /Fetest_client.exe
