#include "ziovpo-common.h"
#include <tlhelp32.h>

std::wstring GetModulePath()
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return path;
}

std::wstring Quote(const std::wstring& s)
{
    return L"\"" + s + L"\"";
}

bool QueryServiceState(DWORD& state, DWORD* processId)
{
    state = SERVICE_STOPPED;
    if (processId) *processId = 0;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!svc)
    {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;
    BOOL ok = QueryServiceStatusEx(
        svc,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp),
        sizeof(ssp),
        &bytesNeeded
    );

    if (ok)
    {
        state = ssp.dwCurrentState;
        if (processId) *processId = ssp.dwProcessId;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

bool IsServiceRunning(DWORD* processId)
{
    DWORD state = 0;
    if (!QueryServiceState(state, processId)) return false;
    return state == SERVICE_RUNNING;
}

bool StartServiceAndWait(DWORD timeoutMs)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(
        scm,
        kServiceName,
        SERVICE_QUERY_STATUS | SERVICE_START
    );
    if (!svc)
    {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;

    if (!QueryServiceStatusEx(
        svc, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
    {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING)
    {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return true;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED)
    {
        if (!StartServiceW(svc, 0, nullptr))
        {
            DWORD err = GetLastError();
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);

            if (err == ERROR_SERVICE_ALREADY_RUNNING)
                return true;

            return false;
        }
    }

    DWORD startTick = GetTickCount();
    while (GetTickCount() - startTick < timeoutMs)
    {
        if (!QueryServiceStatusEx(
            svc, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
        {
            break;
        }

        if (ssp.dwCurrentState == SERVICE_RUNNING)
        {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return true;
        }

        Sleep(300);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return false;
}

DWORD GetParentProcessId(DWORD pid)
{
    DWORD parentPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return parentPid;
}