#include "ziovpo-common.h"
#include "service-control.h"

#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <vector>
#include <string>
#include <mutex>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void __RPC_USER midl_user_free(void* p) { free(p); }

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
std::mutex g_procMutex;
std::vector<HANDLE> g_startedProcesses;

void SetSvcStatus(DWORD state, DWORD controlsAccepted = 0, DWORD win32ExitCode = NO_ERROR)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = controlsAccepted;
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint = 0;
    g_status.dwWaitHint = 0;
    SetServiceStatus(g_statusHandle, &g_status);
}

std::wstring GetGuiPath()
{
    std::wstring self = GetModuleFileNameW ? L"" : L"";
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring p = path;
    auto pos = p.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
    return dir + L"\\ziovpo-practs.exe";
}

bool LaunchGuiInSession(DWORD sessionId)
{
    if (sessionId == 0) return false;

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken))
        return false;

    LPVOID env = nullptr;
    CreateEnvironmentBlock(&env, userToken, FALSE);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION pi{};

    std::wstring cmd = Quote(GetGuiPath()) + L" --hidden";
    std::vector<wchar_t> cmdLine(cmd.begin(), cmd.end());
    cmdLine.push_back(L'\0');
    BOOL ok = CreateProcessAsUserW(
        userToken,
        nullptr,
        cmdLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        env,
        nullptr,
        &si,
        &pi
    );

    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(userToken);

    if (!ok) return false;

    CloseHandle(pi.hThread);

    {
        std::lock_guard<std::mutex> lock(g_procMutex);
        g_startedProcesses.push_back(pi.hProcess);
    }

    return true;
}

void LaunchForExistingSessions()
{
    PWTS_SESSION_INFO pSessions = nullptr;
    DWORD count = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count))
        return;

    for (DWORD i = 0; i < count; ++i)
    {
        DWORD sid = pSessions[i].SessionId;
        if (sid == 0)
            continue;

        if (pSessions[i].State == WTSActive ||
            pSessions[i].State == WTSConnected ||
            pSessions[i].State == WTSDisconnected)
        {
            LaunchGuiInSession(sid);
        }
    }

    WTSFreeMemory(pSessions);
}

void KillAllStartedGui()
{
    std::lock_guard<std::mutex> lock(g_procMutex);
    for (HANDLE h : g_startedProcesses)
    {
        if (h)
        {
            TerminateProcess(h, 0);
            CloseHandle(h);
        }
    }
    g_startedProcesses.clear();
}

DWORD WINAPI HandlerEx(DWORD control, DWORD eventType, LPVOID eventData, LPVOID)
{
    switch (control)
    {
    case SERVICE_CONTROL_SESSIONCHANGE:
    {
        auto* notif = reinterpret_cast<WTSSESSION_NOTIFICATION*>(eventData);

        if (!notif || notif->dwSessionId == 0)
            return NO_ERROR;

        switch (eventType)
        {
        case WTS_SESSION_LOGON:
        case WTS_SESSION_UNLOCK:
        case WTS_CONSOLE_CONNECT:
        case WTS_REMOTE_CONNECT:
            LaunchGuiInSession(notif->dwSessionId);
            break;

        default:
            break;
        }

        return NO_ERROR;
    }

    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        return NO_ERROR;

    default:
        return NO_ERROR;
    }
}

void StopService(handle_t)
{
    RpcMgmtStopServerListening(nullptr);
}

bool StartRpcServer()
{
    RPC_STATUS st = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtseq)),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr
    );
    if (st != RPC_S_OK) return false;

    st = RpcServerRegisterIf(
        ZiovpoServiceControl_v1_0_s_ifspec,
        nullptr,
        nullptr
    );
    if (st != RPC_S_OK) return false;

    st = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    return st == RPC_S_OK || st == RPC_S_ALREADY_LISTENING;
}

void StopRpcServer()
{
    RpcMgmtStopServerListening(nullptr);
    RpcServerUnregisterIf(nullptr, nullptr, FALSE);
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, HandlerEx, nullptr);
    if (!g_statusHandle) return;

    SetSvcStatus(SERVICE_START_PENDING);

    if (!StartRpcServer())
    {
        SetSvcStatus(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    SetSvcStatus(SERVICE_RUNNING, SERVICE_ACCEPT_SESSIONCHANGE);

    LaunchForExistingSessions();

    RpcMgmtWaitServerListen();

    SetSvcStatus(SERVICE_STOP_PENDING);
    KillAllStartedGui();
    StopRpcServer();
    SetSvcStatus(SERVICE_STOPPED);
}

int wmain()
{
    SERVICE_TABLE_ENTRYW table[] =
    {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    StartServiceCtrlDispatcherW(table);
    return 0;
}