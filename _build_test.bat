@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "C:\Users\scree\kimi\tasks\2026-10-13\08-46-14-4e459719\guadbg"
cl /nologo /utf-8 /EHsc /O2 /MT test_target.c
