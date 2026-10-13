@echo off
rem guadbg 构建脚本 —— 需要 "x64 Native Tools Command Prompt for VS"
setlocal
cd /d %~dp0

if not defined DevEnvDir (
    echo [x] 请在 "x64 Native Tools Command Prompt" 中运行本脚本
    exit /b 1
)

echo === 构建引擎 guadbg.exe ===
cl /nologo /EHsc /O2 /MT /W3 engine\guadbg_core.cpp /Feguadbg.exe || exit /b 1

if exist third_party\imgui\imgui.h (
    echo === 构建 UI guadbg_ui.exe ===
    set IMGUI=third_party\imgui
    cl /nologo /EHsc /O2 /MT /I%IMGUI% ui\guadbg_ui.cpp ^
        %IMGUI%\imgui.cpp %IMGUI%\imgui_draw.cpp %IMGUI%\imgui_tables.cpp %IMGUI%\imgui_widgets.cpp ^
        %IMGUI%\backends\imgui_impl_win32.cpp %IMGUI%\backends\imgui_impl_dx11.cpp ^
        /Feui\guadbg_ui.exe /link d3d11.lib dxgi.lib shell32.lib || exit /b 1
) else (
    echo [i] 未找到 third_party\imgui，跳过 UI 构建
    echo     获取：git clone --depth 1 https://github.com/ocornut/imgui third_party\imgui
)

echo === 完成 ===
echo 用法：guadbg.exe ^<target.exe^>    然后启动 MCP 桥或 UI
