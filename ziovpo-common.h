#pragma once

#include <windows.h>
#include <string>

constexpr wchar_t kServiceName[] = L"ZiovpoPractsService";
constexpr wchar_t kServiceDisplayName[] = L"Ziovpo Service";
constexpr wchar_t kRpcProtseq[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"ZiovpoServiceEndpoint";

bool QueryServiceState(DWORD& state, DWORD* processId = nullptr);
bool StartServiceAndWait(DWORD timeoutMs = 30000);
bool IsServiceRunning(DWORD* processId = nullptr);
DWORD GetParentProcessId(DWORD pid);
std::wstring GetModulePath();
std::wstring Quote(const std::wstring& s);