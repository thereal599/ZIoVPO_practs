#include "ziovpo-practs.h"
#include "ziovpo-common.h"
#include "service-control.h"

#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <rpc.h>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "advapi32.lib")

constexpr wchar_t WINDOW_CLASS_NAME[] = L"ZiovpoWindowClass";
constexpr wchar_t WINDOW_TITLE[] = L"ziovpo app";
constexpr wchar_t MUTEX_NAME[] = L"Local\\ziovpo-single-instance";

constexpr UINT WM_TRAYICON = WM_APP + 1;

constexpr UINT ID_TRAY_OPEN = 1001;
constexpr UINT ID_TRAY_EXIT = 1002;
constexpr UINT ID_MENU_FILE_EXIT = 2001;
constexpr UINT ID_MENU_LOGOUT = 2002;

constexpr UINT ID_LOGIN_BUTTON = 3001;
constexpr UINT ID_ACTIVATE_BUTTON = 3002;
constexpr UINT ID_AV_BUTTON = 3004;
constexpr UINT ID_TIMER_REFRESH = 4001;

HINSTANCE g_hInstance = nullptr;
HWND g_hWnd = nullptr;
HMENU g_hTrayMenu = nullptr;
HANDLE g_hMutex = nullptr;
UINT g_taskbarCreatedMessage = 0;
NOTIFYICONDATAW g_nid{};

HWND g_statusLabel = nullptr;
HWND g_userLabel = nullptr;
HWND g_licenseLabel = nullptr;
HWND g_loginTitle = nullptr;
HWND g_loginUserLabel = nullptr;
HWND g_loginPassLabel = nullptr;
HWND g_userEdit = nullptr;
HWND g_passEdit = nullptr;
HWND g_loginButton = nullptr;
HWND g_activationTitle = nullptr;
HWND g_activationCodeLabel = nullptr;
HWND g_activationEdit = nullptr;
HWND g_activationButton = nullptr;
HWND g_avButton = nullptr;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void RefreshGuiState();

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* p)
{
    free(p);
}

std::wstring RpcStringToWString(wchar_t* s)
{
    if (!s) return L"";
    std::wstring out = s;
    midl_user_free(s);
    return out;
}

bool CreateRpcBinding(RPC_BINDING_HANDLE* binding)
{
    if (!binding) return false;
    *binding = nullptr;

    RPC_WSTR stringBinding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtseq)),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr,
        &stringBinding
    );
    if (status != RPC_S_OK) return false;

    status = RpcBindingFromStringBindingW(stringBinding, binding);
    RpcStringFreeW(&stringBinding);
    return status == RPC_S_OK;
}

void FreeRpcBinding(RPC_BINDING_HANDLE binding)
{
    if (binding) RpcBindingFree(&binding);
}

bool CheckSingleInstance()
{
    g_hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
    if (!g_hMutex) return false;

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
    if (!argv) return false;

    bool hidden = false;
    for (int i = 1; i < argc; ++i)
    {
        if (lstrcmpiW(argv[i], L"--hidden") == 0)
        {
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
    if (g_nid.hWnd) Shell_NotifyIconW(NIM_DELETE, &g_nid);
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
    TrackPopupMenu(g_hTrayMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
    PostMessageW(hwnd, WM_NULL, 0, 0);
}

void CreateMainMenu(HWND hwnd)
{
    HMENU hMenuBar = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();

    AppendMenuW(hFileMenu, MF_STRING, ID_MENU_LOGOUT, L"Выйти из аккаунта");
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFileMenu, MF_STRING, ID_MENU_FILE_EXIT, L"Выход");
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), L"Файл");

    SetMenu(hwnd, hMenuBar);
}

HWND CreateLabel(HWND parent, const wchar_t* text, int x, int y, int w, int h)
{
    return CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, x, y, w, h, parent, nullptr, g_hInstance, nullptr);
}

HWND CreateEdit(HWND parent, int x, int y, int w, int h, bool password = false)
{
    DWORD style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;
    if (password) style |= ES_PASSWORD;
    return CreateWindowW(L"EDIT", L"", style, x, y, w, h, parent, nullptr, g_hInstance, nullptr);
}

HWND CreateButton(HWND parent, const wchar_t* text, UINT id, int x, int y, int w, int h)
{
    return CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, y, w, h, parent, reinterpret_cast<HMENU>(id), g_hInstance, nullptr);
}

void CreateAppControls(HWND hwnd)
{
    g_statusLabel = CreateLabel(hwnd, L"Статус: загрузка...", 20, 20, 640, 24);
    g_userLabel = CreateLabel(hwnd, L"Пользователь: -", 20, 50, 640, 24);
    g_licenseLabel = CreateLabel(hwnd, L"Лицензия: -", 20, 80, 640, 24);

    g_loginTitle = CreateLabel(hwnd, L"Вход в учетную запись", 20, 125, 300, 24);
    g_loginUserLabel = CreateLabel(hwnd, L"Логин:", 20, 155, 90, 22);
    g_userEdit = CreateEdit(hwnd, 120, 152, 220, 24);
    g_loginPassLabel = CreateLabel(hwnd, L"Пароль:", 20, 185, 90, 22);
    g_passEdit = CreateEdit(hwnd, 120, 182, 220, 24, true);
    g_loginButton = CreateButton(hwnd, L"Войти", ID_LOGIN_BUTTON, 120, 218, 110, 30);

    g_activationTitle = CreateLabel(hwnd, L"Активация продукта", 20, 270, 300, 24);
    g_activationCodeLabel = CreateLabel(hwnd, L"Код:", 20, 300, 90, 22);
    g_activationEdit = CreateEdit(hwnd, 120, 297, 330, 24);
    g_activationButton = CreateButton(hwnd, L"Активировать", ID_ACTIVATE_BUTTON, 120, 333, 140, 30);

    g_avButton = CreateButton(hwnd, L"Запустить проверку", ID_AV_BUTTON, 20, 400, 180, 34);
}

void ShowControl(HWND h, bool show)
{
    if (h) ShowWindow(h, show ? SW_SHOW : SW_HIDE);
}

void SetLabel(HWND h, const std::wstring& text)
{
    if (h) SetWindowTextW(h, text.c_str());
}

std::wstring GetControlText(HWND h)
{
    int len = GetWindowTextLengthW(h);
    std::wstring s(len + 1, L'\0');
    if (len > 0) GetWindowTextW(h, s.data(), len + 1);
    s.resize(len);
    return s;
}

void SetAntivirusLocked(bool locked)
{
    EnableWindow(g_avButton, locked ? FALSE : TRUE);
}

void ShowLoginForm(bool show)
{
    ShowControl(g_loginTitle, show);
    ShowControl(g_loginUserLabel, show);
    ShowControl(g_loginPassLabel, show);
    ShowControl(g_userEdit, show);
    ShowControl(g_passEdit, show);
    ShowControl(g_loginButton, show);
}

void ShowActivationForm(bool show)
{
    ShowControl(g_activationTitle, show);
    ShowControl(g_activationCodeLabel, show);
    ShowControl(g_activationEdit, show);
    ShowControl(g_activationButton, show);
}


bool RpcCallStopService(RPC_BINDING_HANDLE binding)
{
    bool ok = true;
    __try
    {
        StopService(binding);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
    }
    return ok;
}

bool RpcCallGetCurrentUser(RPC_BINDING_HANDLE binding, RpcUserInfo* info)
{
    bool ok = true;
    __try
    {
        GetCurrentUser(binding, info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
    }
    return ok;
}

bool RpcCallGetLicenseInfo(RPC_BINDING_HANDLE binding, RpcLicenseInfo* info)
{
    bool ok = true;
    __try
    {
        GetLicenseInfo(binding, info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
    }
    return ok;
}

int RpcCallLogin(RPC_BINDING_HANDLE binding, wchar_t* username, wchar_t* password, wchar_t** errorMessage)
{
    int status = RPC_APP_SERVER_ERROR;
    __try
    {
        status = Login(binding, username, password, errorMessage);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = RPC_APP_NETWORK_ERROR;
    }
    return status;
}

void RpcCallLogout(RPC_BINDING_HANDLE binding)
{
    __try
    {
        Logout(binding);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

int RpcCallActivateLicense(RPC_BINDING_HANDLE binding, wchar_t* activationKey, wchar_t** errorMessage)
{
    int status = RPC_APP_SERVER_ERROR;
    __try
    {
        status = ActivateLicense(binding, activationKey, errorMessage);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = RPC_APP_NETWORK_ERROR;
    }
    return status;
}

bool StopServiceViaRpc()
{
    RPC_BINDING_HANDLE binding = nullptr;
    if (!CreateRpcBinding(&binding)) return false;

    bool ok = RpcCallStopService(binding);

    FreeRpcBinding(binding);
    return ok;
}

bool GetCurrentUserViaRpc(RpcUserInfo& info)
{
    ZeroMemory(&info, sizeof(info));
    RPC_BINDING_HANDLE binding = nullptr;
    if (!CreateRpcBinding(&binding)) return false;

    bool ok = RpcCallGetCurrentUser(binding, &info);

    FreeRpcBinding(binding);
    return ok;
}

bool GetLicenseInfoViaRpc(RpcLicenseInfo& info)
{
    ZeroMemory(&info, sizeof(info));
    RPC_BINDING_HANDLE binding = nullptr;
    if (!CreateRpcBinding(&binding)) return false;

    bool ok = RpcCallGetLicenseInfo(binding, &info);

    FreeRpcBinding(binding);
    return ok;
}

int LoginViaRpc(const std::wstring& username, const std::wstring& password, std::wstring& error)
{
    RPC_BINDING_HANDLE binding = nullptr;
    if (!CreateRpcBinding(&binding))
    {
        error = L"Не удалось подключиться к службе";
        return RPC_APP_NETWORK_ERROR;
    }

    wchar_t* rpcError = nullptr;
    int status = RpcCallLogin(
        binding,
        const_cast<wchar_t*>(username.c_str()),
        const_cast<wchar_t*>(password.c_str()),
        &rpcError
    );

    error = RpcStringToWString(rpcError);
    FreeRpcBinding(binding);
    return status;
}

void LogoutViaRpc()
{
    RPC_BINDING_HANDLE binding = nullptr;
    if (!CreateRpcBinding(&binding)) return;

    RpcCallLogout(binding);

    FreeRpcBinding(binding);
}

int ActivateLicenseViaRpc(const std::wstring& key, std::wstring& error)
{
    RPC_BINDING_HANDLE binding = nullptr;
    if (!CreateRpcBinding(&binding))
    {
        error = L"Не удалось подключиться к службе";
        return RPC_APP_NETWORK_ERROR;
    }

    wchar_t* rpcError = nullptr;
    int status = RpcCallActivateLicense(
        binding,
        const_cast<wchar_t*>(key.c_str()),
        &rpcError
    );

    error = RpcStringToWString(rpcError);
    FreeRpcBinding(binding);
    return status;
}

void FreeUserInfo(RpcUserInfo& info)
{
    if (info.username) midl_user_free(info.username);
    if (info.message) midl_user_free(info.message);
    ZeroMemory(&info, sizeof(info));
}

void FreeLicenseInfo(RpcLicenseInfo& info)
{
    if (info.expirationDate) midl_user_free(info.expirationDate);
    if (info.message) midl_user_free(info.message);
    ZeroMemory(&info, sizeof(info));
}

void RefreshGuiState()
{
    RpcUserInfo user{};
    if (!GetCurrentUserViaRpc(user))
    {
        SetLabel(g_statusLabel, L"Статус: нет связи со службой");
        SetLabel(g_userLabel, L"Пользователь: -");
        SetLabel(g_licenseLabel, L"Лицензия: -");
        ShowLoginForm(true);
        ShowActivationForm(false);
        SetAntivirusLocked(true);
        return;
    }

    std::wstring username = user.username ? user.username : L"";
    bool authenticated = user.authenticated != 0;
    FreeUserInfo(user);

    if (!authenticated)
    {
        SetLabel(g_statusLabel, L"Статус: требуется вход");
        SetLabel(g_userLabel, L"Пользователь: -");
        SetLabel(g_licenseLabel, L"Лицензия: отсутствует");
        ShowLoginForm(true);
        ShowActivationForm(false);
        SetAntivirusLocked(true);
        return;
    }

    SetLabel(g_userLabel, L"Пользователь: " + username);
    ShowLoginForm(false);

    RpcLicenseInfo lic{};
    if (!GetLicenseInfoViaRpc(lic))
    {
        SetLabel(g_statusLabel, L"Статус: ошибка запроса лицензии");
        SetLabel(g_licenseLabel, L"Лицензия: неизвестно");
        ShowActivationForm(true);
        SetAntivirusLocked(true);
        return;
    }

    std::wstring exp = lic.expirationDate ? lic.expirationDate : L"";
    std::wstring msg = lic.message ? lic.message : L"";
    bool active = lic.active != 0;
    bool hasLicense = lic.hasLicense != 0;
    int status = lic.statusCode;
    FreeLicenseInfo(lic);

    if (active)
    {
        SetLabel(g_statusLabel, L"Статус: антивирус разблокирован");
        SetLabel(g_licenseLabel, L"Лицензия активна до: " + exp);
        ShowActivationForm(false);
        SetAntivirusLocked(false);
    }
    else
    {
        switch (status)
        {
        case RPC_APP_LICENSE_BLOCKED:
            SetLabel(g_licenseLabel, L"Лицензия: заблокирована");
            SetLabel(g_statusLabel, L"Статус: антивирус заблокирован. Лицензия заблокирована");
            break;

        case RPC_APP_LICENSE_EXPIRED:
            SetLabel(g_licenseLabel, L"Лицензия: истекла");
            SetLabel(g_statusLabel, L"Статус: антивирус заблокирован. Лицензия истекла");
            break;

        case RPC_APP_NO_LICENSE:
            SetLabel(g_licenseLabel, L"Лицензия: отсутствует или недействительна");
            SetLabel(g_statusLabel, L"Статус: антивирус заблокирован. Лицензия отсутствует или недействительна");
            break;

        default:
            if (!msg.empty())
            {
                SetLabel(g_licenseLabel, L"Лицензия: " + msg);
                SetLabel(g_statusLabel, L"Статус: антивирус заблокирован. " + msg);
            }
            else
            {
                SetLabel(g_licenseLabel, L"Лицензия: недействительна");
                SetLabel(g_statusLabel, L"Статус: антивирус заблокирован");
            }
            break;
        }

        ShowActivationForm(true);
        SetAntivirusLocked(true);
    }
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

    if (!RegisterClassExW(&wc)) return false;

    g_hWnd = CreateWindowExW(
        0,
        WINDOW_CLASS_NAME,
        WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        720,
        520,
        nullptr,
        nullptr,
        hInstance,
        nullptr
    );

    if (!g_hWnd) return false;

    CreateMainMenu(g_hWnd);
    CreateTrayMenu();
    CreateAppControls(g_hWnd);
    return true;
}

bool EnsureServiceIsRunningOrExit()
{
    DWORD servicePid = 0;

    if (IsServiceRunning(&servicePid)) return true;

    if (StartServiceAndWait()) return false;

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
    if (!IsServiceRunning(&servicePid)) return false;

    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = GetParentProcessId(currentPid);

    return parentPid != 0 && parentPid == servicePid;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int)
{
    g_hInstance = hInstance;
    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!EnsureServiceIsRunningOrExit()) return 0;
    if (!IsParentServiceProcess()) return 0;
    if (!CheckSingleInstance()) return 0;

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

    RefreshGuiState();
    SetTimer(g_hWnd, ID_TIMER_REFRESH, 5000, nullptr);

    LaunchHidden() ? HideMainWindow(g_hWnd) : ShowMainWindow(g_hWnd);

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
            RefreshGuiState();
            ShowMainWindow(hwnd);
            return 0;

        case ID_LOGIN_BUTTON:
        {
            std::wstring username = GetControlText(g_userEdit);
            std::wstring password = GetControlText(g_passEdit);
            std::wstring error;
            int status = LoginViaRpc(username, password, error);
            if (status != RPC_APP_OK)
            {
                SetAntivirusLocked(true);
                ShowLoginForm(true);
                MessageBoxW(hwnd, error.empty() ? L"Ошибка входа" : error.c_str(), L"Вход", MB_OK | MB_ICONERROR);
            }
            RefreshGuiState();
            return 0;
        }

        case ID_ACTIVATE_BUTTON:
        {
            std::wstring key = GetControlText(g_activationEdit);
            std::wstring error;
            int status = ActivateLicenseViaRpc(key, error);
            if (status != RPC_APP_OK)
            {
                SetAntivirusLocked(true);
                ShowActivationForm(true);
                MessageBoxW(hwnd, error.empty() ? L"Ошибка активации" : error.c_str(), L"Активация", MB_OK | MB_ICONERROR);
            }
            RefreshGuiState();
            return 0;
        }

        case ID_MENU_LOGOUT:
            LogoutViaRpc();
            RefreshGuiState();
            return 0;

        case ID_AV_BUTTON:
            MessageBoxW(hwnd, L"Проверка запущена. Это демонстрационная функция антивируса.", L"Антивирус", MB_OK | MB_ICONINFORMATION);
            return 0;

        case ID_TRAY_EXIT:
        case ID_MENU_FILE_EXIT:
            StopServiceViaRpc();
            return 0;
        }
        break;

    case WM_TIMER:
        if (wParam == ID_TIMER_REFRESH)
        {
            RefreshGuiState();
            return 0;
        }
        break;

    case WM_TRAYICON:
        switch (lParam)
        {
        case WM_LBUTTONUP:
            RefreshGuiState();
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
        KillTimer(hwnd, ID_TIMER_REFRESH);
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
