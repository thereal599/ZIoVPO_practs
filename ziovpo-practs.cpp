#include "ziovpo-practs.h"
#include "ziovpo-common.h"
#include "service-control.h"

#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

constexpr wchar_t WINDOW_CLASS_NAME[] = L"ZiovpoWindowClass";
constexpr wchar_t WINDOW_TITLE[] = L"ziovpo app";
constexpr wchar_t MUTEX_NAME[] = L"Local\\ziovpo-single-instance";

constexpr UINT WM_TRAYICON = WM_APP + 1;

constexpr UINT ID_TRAY_OPEN = 1001;
constexpr UINT ID_TRAY_EXIT = 1002;
constexpr UINT ID_MENU_FILE_EXIT = 2001;

HINSTANCE g_hInstance = nullptr;
HWND g_hWnd = nullptr;
HMENU g_hTrayMenu = nullptr;
HANDLE g_hMutex = nullptr;
UINT g_taskbarCreatedMessage = 0;
NOTIFYICONDATAW g_nid{};

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* p)
{
    free(p);
}

bool CheckSingleInstance()
{
    g_hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
    if (!g_hMutex)
    {
        return false;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(g_hMutex);
        g_hMutex = nullptr;
        return false;
    }

    return true;
}

void ReleaseSingleInstance()
{
    if (g_hMutex)
    {
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
        g_hMutex = nullptr;
    }
}

void ShowMainWindow(HWND hwnd)
{
    ShowWindow(hwnd, SW_SHOW);
    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
}

void HideMainWindow(HWND hwnd)
{
    ShowWindow(hwnd, SW_HIDE);
}

bool LaunchHidden()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) { return false; }
    bool hidden = false;
    for (int i = 1; i < argc; ++i) {
        if (lstrcmpiW(argv[i], L"--hidden") == 0) {
            hidden = true;
            break;
        }
    }
    LocalFree(argv);
    return hidden;
}

bool AddTrayIcon(HWND hwnd)
{
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);

    StringCchCopyW(g_nid.szTip, ARRAYSIZE(g_nid.szTip), L"ziovpo-practs");

    return Shell_NotifyIconW(NIM_ADD, &g_nid) == TRUE;
}

void RemoveTrayIcon()
{
    if (g_nid.hWnd)
    {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
    }
}

void CreateTrayMenu()
{
    g_hTrayMenu = CreatePopupMenu();
    AppendMenuW(g_hTrayMenu, MF_STRING, ID_TRAY_OPEN, L"Открыть");
    AppendMenuW(g_hTrayMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(g_hTrayMenu, MF_STRING, ID_TRAY_EXIT, L"Выход");
}

void ShowTrayMenu(HWND hwnd)
{
    POINT pt{};
    GetCursorPos(&pt);

    SetForegroundWindow(hwnd);
    TrackPopupMenu(
        g_hTrayMenu,
        TPM_BOTTOMALIGN | TPM_LEFTALIGN,
        pt.x,
        pt.y,
        0,
        hwnd,
        nullptr
    );

    PostMessageW(hwnd, WM_NULL, 0, 0);
}

void CreateMainMenu(HWND hwnd)
{
    HMENU hMenuBar = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();

    AppendMenuW(hFileMenu, MF_STRING, ID_MENU_FILE_EXIT, L"Выход");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), L"Файл");

    SetMenu(hwnd, hMenuBar);
}

bool CreateMainWindow(HINSTANCE hInstance)
{
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = WINDOW_CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    if (!RegisterClassExW(&wc))
    {
        return false;
    }

    g_hWnd = CreateWindowExW(
        0,
        WINDOW_CLASS_NAME,
        WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        700,
        500,
        nullptr,
        nullptr,
        hInstance,
        nullptr
    );

    if (!g_hWnd)
    {
        return false;
    }

    CreateMainMenu(g_hWnd);
    CreateTrayMenu();

    return true;
}

bool StopServiceViaRpc()
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;

    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtseq)),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr,
        &stringBinding
    );

    if (status != RPC_S_OK)
    {
        return false;
    }

    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);

    if (status != RPC_S_OK)
    {
        return false;
    }

    bool ok = true;

    __try
    {
        // Это функция из service_control.idl / service_control_c.c
        StopService(binding);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
    }

    RpcBindingFree(&binding);
    return ok;
}

bool EnsureServiceIsRunningOrExit()
{
    DWORD servicePid = 0;

    if (IsServiceRunning(&servicePid))
    {
        return true;
    }

    if (StartServiceAndWait())
    {
        return false;
    }

    MessageBoxW(
        nullptr,
        L"Не удалось запустить Windows-службу. Запустите приложение от имени администратора.",
        L"Ошибка",
        MB_OK | MB_ICONERROR
    );

    return false;
}

bool IsParentServiceProcess()
{
    DWORD servicePid = 0;
    if (!IsServiceRunning(&servicePid))
    {
        return false;
    }

    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = GetParentProcessId(currentPid);

    return parentPid != 0 && parentPid == servicePid;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int)
{
    g_hInstance = hInstance;
    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!EnsureServiceIsRunningOrExit()) { return 0; }

    if (!IsParentServiceProcess()) { return 0; }

    if (!CheckSingleInstance()) { return 0; }

    if (!CreateMainWindow(hInstance))
    {
        ReleaseSingleInstance();
        return 1;
    }

    if (!AddTrayIcon(g_hWnd))
    {
        ReleaseSingleInstance();
        DestroyWindow(g_hWnd);
        return 1;
    }

    (LaunchHidden()) ? HideMainWindow(g_hWnd) : ShowMainWindow(g_hWnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == g_taskbarCreatedMessage)
    {
        AddTrayIcon(hwnd);
        return 0;
    }

    switch (msg)
    {
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_TRAY_OPEN:
            ShowMainWindow(hwnd);
            return 0;

        case ID_TRAY_EXIT:
        case ID_MENU_FILE_EXIT:
            StopServiceViaRpc();
            return 0;
        }
        break;

    case WM_TRAYICON:
        switch (lParam)
        {
        case WM_LBUTTONUP:
            ShowMainWindow(hwnd);
            return 0;

        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayMenu(hwnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        HideMainWindow(hwnd);
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        if (g_hTrayMenu)
        {
            DestroyMenu(g_hTrayMenu);
            g_hTrayMenu = nullptr;
        }
        ReleaseSingleInstance();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}