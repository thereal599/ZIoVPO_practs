#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "ziovpo-common.h"
#include "service-control.h"

#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <winhttp.h>
#include <iphlpapi.h>

#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdio>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void __RPC_USER midl_user_free(void* p) { free(p); }

constexpr wchar_t kApiHost[] = L"192.168.43.110";
constexpr INTERNET_PORT kApiPort = 8443;
constexpr char kProductId[] = "11111111-2222-3333-4444-555555555555";

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
std::mutex g_procMutex;
std::vector<HANDLE> g_startedProcesses;
std::atomic_bool g_serviceStopping = false;

struct AppState
{
    std::mutex mutex;

    bool authenticated = false;
    std::wstring username;
    std::string accessToken;
    std::string refreshToken;
    std::string loginDeviceId;
    std::string deviceMac;
    std::string deviceName;
    time_t accessExpiresAt = 0;
    time_t refreshExpiresAt = 0;

    bool hasLicense = false;
    bool licenseActive = false;
    bool licenseBlocked = false;
    std::wstring licenseExpirationDate;
    int ticketLifetimeDays = 0;
    std::string ticketJson;
    std::string signature;
    int licenseStatusCode = RPC_APP_NO_LICENSE;
    std::wstring licenseMessage = L"Лицензия отсутствует";

    unsigned long long authGeneration = 0;
    unsigned long long licenseGeneration = 0;
};

AppState g_app;

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

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
    return out;
}

std::string WideToUtf8(const std::wstring& s)
{
    if (s.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), len, nullptr, nullptr);
    return out;
}

std::string JsonEscape(const std::string& input)
{
    std::string out;
    out.reserve(input.size() + 8);
    for (char ch : input)
    {
        switch (ch)
        {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += ch; break;
        }
    }
    return out;
}

bool StartsAndEndsWithQuote(const std::string& s)
{
    return s.size() >= 2 && s.front() == '"' && s.back() == '"';
}

std::string UnquoteJsonString(const std::string& s)
{
    if (!StartsAndEndsWithQuote(s)) return s;
    std::string out;
    for (size_t i = 1; i + 1 < s.size(); ++i)
    {
        if (s[i] == '\\' && i + 1 < s.size())
        {
            char n = s[++i];
            switch (n)
            {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            default: out += n; break;
            }
        }
        else
        {
            out += s[i];
        }
    }
    return out;
}

std::string ExtractJsonString(const std::string& json, const std::string& key)
{
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";

    std::string out;
    bool esc = false;
    for (size_t i = pos + 1; i < json.size(); ++i)
    {
        char c = json[i];
        if (esc)
        {
            switch (c)
            {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            default: out += c; break;
            }
            esc = false;
        }
        else if (c == '\\')
        {
            esc = true;
        }
        else if (c == '"')
        {
            break;
        }
        else
        {
            out += c;
        }
    }
    return out;
}

long long ExtractJsonInt64(const std::string& json, const std::string& key)
{
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return 0;
    ++pos;
    while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    bool neg = false;
    if (pos < json.size() && json[pos] == '-') { neg = true; ++pos; }
    long long value = 0;
    while (pos < json.size() && isdigit(static_cast<unsigned char>(json[pos])))
    {
        value = value * 10 + (json[pos] - '0');
        ++pos;
    }
    return neg ? -value : value;
}

bool ExtractJsonBool(const std::string& json, const std::string& key)
{
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    return json.compare(pos, 4, "true") == 0;
}

std::string Base64UrlDecode(const std::string& in)
{
    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,0,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::string out;
    int val = 0;
    int valb = -8;
    for (unsigned char c : in)
    {
        if (c == '=') break;
        int d = table[c];
        if (d == -1) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

time_t ExtractJwtExpiration(const std::string& token)
{
    size_t p1 = token.find('.');
    if (p1 == std::string::npos) return 0;
    size_t p2 = token.find('.', p1 + 1);
    if (p2 == std::string::npos) return 0;
    std::string payload64 = token.substr(p1 + 1, p2 - p1 - 1);
    std::string payload = Base64UrlDecode(payload64);
    return static_cast<time_t>(ExtractJsonInt64(payload, "exp"));
}

std::wstring RpcStringOrEmpty(const wchar_t* s)
{
    return s ? std::wstring(s) : L"";
}

wchar_t* RpcAllocString(const std::wstring& s)
{
    size_t bytes = (s.size() + 1) * sizeof(wchar_t);
    wchar_t* p = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (!p) return nullptr;
    wcscpy_s(p, s.size() + 1, s.c_str());
    return p;
}

std::string GetComputerNameUtf8()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = ARRAYSIZE(name);
    if (!GetComputerNameW(name, &size)) return "UnknownDevice";
    return WideToUtf8(name);
}

std::string GetPrimaryMacAddress()
{
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 15000;
    std::vector<BYTE> buffer(size);
    IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    if (ret == ERROR_BUFFER_OVERFLOW)
    {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    }

    if (ret != NO_ERROR) return "00:00:00:00:00:00";

    for (auto* a = adapters; a; a = a->Next)
    {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->PhysicalAddressLength < 6) continue;

        char mac[32]{};
        sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
            a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
        return mac;
    }

    return "00:00:00:00:00:00";
}

std::wstring TodayYmd()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    wchar_t buf[16]{};
    swprintf_s(buf, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return buf;
}

struct HttpResponse
{
    bool transportOk = false;
    DWORD status = 0;
    DWORD winError = 0;
    std::string body;
};

HttpResponse HttpPostJson(const wchar_t* path, const std::string& body, const std::string& bearerToken = "")
{
    HttpResponse result;

    HINTERNET hSession = WinHttpOpen(
        L"ziovpo-service/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession)
    {
        result.winError = GetLastError();
        return result;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, kApiHost, kApiPort, 0);
    if (!hConnect)
    {
        result.winError = GetLastError();
        WinHttpCloseHandle(hSession);
        return result;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        path,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest)
    {
        result.winError = GetLastError();
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD securityFlags =
        SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    if (!WinHttpSetOption(
        hRequest,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &securityFlags,
        sizeof(securityFlags)))
    {
        DWORD err = GetLastError();
        wchar_t msg[256]{};
        wsprintfW(msg, L"WinHttpSetOption SECURITY_FLAGS failed: %lu", err);
        OutputDebugStringW(msg);
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!bearerToken.empty())
    {
        headers += L"Authorization: Bearer ";
        headers += Utf8ToWide(bearerToken);
        headers += L"\r\n";
    }

    BOOL ok = WinHttpSendRequest(
        hRequest,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);

    if (!ok || !WinHttpReceiveResponse(hRequest, nullptr))
    {
        result.winError = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX))
    {
        result.status = status;
    }

    DWORD available = 0;
    do
    {
        available = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &available)) break;
        if (available == 0) break;
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, chunk.data(), available, &read)) break;
        chunk.resize(read);
        result.body += chunk;
    } while (available > 0);

    result.transportOk = true;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

std::wstring ExtractServerMessage(const std::string& body)
{
    std::string msg = ExtractJsonString(body, "error");
    if (msg.empty()) msg = ExtractJsonString(body, "message");
    if (msg.empty()) msg = UnquoteJsonString(body);
    if (msg.empty()) msg = "Server error";
    return Utf8ToWide(msg);
}

void ClearLicenseLocked()
{
    g_app.hasLicense = false;
    g_app.licenseActive = false;
    g_app.licenseBlocked = false;
    g_app.licenseExpirationDate.clear();
    g_app.ticketLifetimeDays = 0;
    g_app.ticketJson.clear();
    g_app.signature.clear();
    g_app.licenseStatusCode = RPC_APP_NO_LICENSE;
    g_app.licenseMessage = L"Лицензия отсутствует";
    ++g_app.licenseGeneration;
}

void ClearAuthLocked()
{
    g_app.authenticated = false;
    g_app.username.clear();
    g_app.accessToken.clear();
    g_app.refreshToken.clear();
    g_app.accessExpiresAt = 0;
    g_app.refreshExpiresAt = 0;
    ++g_app.authGeneration;
    ClearLicenseLocked();
}

bool IsTicketActive(const std::wstring& expiration, bool blocked)
{
    if (blocked || expiration.empty()) return false;
    return expiration >= TodayYmd();
}

int StoreTicketFromResponseLocked(const std::string& body)
{
    std::string expiration = ExtractJsonString(body, "licenseExpirationDate");
    bool blocked = ExtractJsonBool(body, "blocked");
    int lifetime = static_cast<int>(ExtractJsonInt64(body, "ticketLifetimeDays"));
    std::string signature = ExtractJsonString(body, "signature");

    if (expiration.empty())
    {
        ClearLicenseLocked();
        g_app.licenseStatusCode = RPC_APP_SERVER_ERROR;
        g_app.licenseMessage = L"Некорректный ответ сервера лицензирования";
        return RPC_APP_SERVER_ERROR;
    }

    g_app.hasLicense = true;
    g_app.licenseBlocked = blocked;
    g_app.licenseExpirationDate = Utf8ToWide(expiration);
    g_app.ticketLifetimeDays = lifetime;
    g_app.ticketJson = body;
    g_app.signature = signature;
    g_app.licenseActive = IsTicketActive(g_app.licenseExpirationDate, blocked);

    if (blocked)
    {
        g_app.licenseStatusCode = RPC_APP_LICENSE_BLOCKED;
        g_app.licenseMessage = L"Лицензия заблокирована";
    }
    else if (!g_app.licenseActive)
    {
        g_app.licenseStatusCode = RPC_APP_LICENSE_EXPIRED;
        g_app.licenseMessage = L"Лицензия истекла";
    }
    else
    {
        g_app.licenseStatusCode = RPC_APP_OK;
        g_app.licenseMessage = L"Лицензия активна";
    }

    ++g_app.licenseGeneration;
    return g_app.licenseStatusCode;
}

int MapLicenseCheckError(DWORD httpStatus, const std::string& body, std::wstring& message)
{
    std::wstring serverMsg = ExtractServerMessage(body);

    if (httpStatus == 404)
    {
        message = L"Лицензия не активирована для этого устройства";
        return RPC_APP_NO_LICENSE;
    }

    if (httpStatus == 403)
    {
        if (body.find("Device owned by another user") != std::string::npos)
        {
            message = L"Устройство привязано к другому пользователю";
            return RPC_APP_DEVICE_OWNED_BY_ANOTHER_USER;
        }

        message = L"Сессия недействительна. Выполните вход снова";
        return RPC_APP_SESSION_EXPIRED;
    }

    message = serverMsg;
    return RPC_APP_SERVER_ERROR;
}

int MapActivationError(DWORD httpStatus, const std::string& body, std::wstring& message)
{
    if (httpStatus == 404)
    {
        message = L"Неверный код активации";
        return RPC_APP_INVALID_ACTIVATION_KEY;
    }

    if (httpStatus == 403)
    {
        if (body.find("License is blocked") != std::string::npos)
        {
            message = L"Лицензия заблокирована";
            return RPC_APP_LICENSE_BLOCKED;
        }
        if (body.find("License is owned by another user") != std::string::npos)
        {
            message = L"Лицензия принадлежит другому пользователю";
            return RPC_APP_LICENSE_OWNED_BY_ANOTHER_USER;
        }
        if (body.find("Device owned by another user") != std::string::npos)
        {
            message = L"Устройство привязано к другому пользователю";
            return RPC_APP_DEVICE_OWNED_BY_ANOTHER_USER;
        }

        message = L"Сессия недействительна. Выполните вход снова";
        return RPC_APP_SESSION_EXPIRED;
    }

    if (httpStatus == 409)
    {
        message = L"Превышено количество устройств для лицензии";
        return RPC_APP_DEVICE_LIMIT_REACHED;
    }

    message = ExtractServerMessage(body);
    return RPC_APP_SERVER_ERROR;
}

int FetchLicenseStatusAndStore()
{
    std::string token;
    std::string deviceMac;

    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        if (!g_app.authenticated)
            return RPC_APP_NOT_AUTHENTICATED;
        token = g_app.accessToken;
        deviceMac = g_app.deviceMac;
    }

    std::string body = "{\"deviceMac\":\"" + JsonEscape(deviceMac) + "\",\"productId\":\"" + std::string(kProductId) + "\"}";
    HttpResponse resp = HttpPostJson(L"/api/licenses/check", body, token);

    std::lock_guard<std::mutex> lock(g_app.mutex);

    if (!resp.transportOk)
    {
        ClearLicenseLocked();
        g_app.licenseStatusCode = RPC_APP_NETWORK_ERROR;
        g_app.licenseMessage = L"Нет соединения с сервером лицензирования";
        return RPC_APP_NETWORK_ERROR;
    }

    if (resp.status == 200)
    {
        return StoreTicketFromResponseLocked(resp.body);
    }

    std::wstring message;
    int code = MapLicenseCheckError(resp.status, resp.body, message);

    if (code == RPC_APP_SESSION_EXPIRED)
    {
        ClearAuthLocked();
        return code;
    }

    ClearLicenseLocked();
    g_app.licenseStatusCode = code;
    g_app.licenseMessage = message;
    return code;
}

void StartLicenseRefreshWorker(unsigned long long generation)
{
    std::thread([generation]() mutable
        {
            while (!g_serviceStopping.load())
            {
                int delaySeconds = 60;

                {
                    std::lock_guard<std::mutex> lock(g_app.mutex);

                    if (!g_app.authenticated || !g_app.hasLicense || generation != g_app.licenseGeneration)
                        return;

                    int ticketSeconds = g_app.ticketLifetimeDays > 0
                        ? g_app.ticketLifetimeDays * 24 * 60 * 60
                        : 60;

                    delaySeconds = max(10, min(ticketSeconds / 2, 60));
                }

                for (int i = 0; i < delaySeconds && !g_serviceStopping.load(); ++i)
                {
                    Sleep(1000);

                    std::lock_guard<std::mutex> lock(g_app.mutex);

                    if (!g_app.authenticated || !g_app.hasLicense || generation != g_app.licenseGeneration)
                        return;
                }

                FetchLicenseStatusAndStore();

                {
                    std::lock_guard<std::mutex> lock(g_app.mutex);

                    if (!g_app.authenticated || !g_app.hasLicense)
                        return;
                    generation = g_app.licenseGeneration;
                }
            }
        }).detach();
}

void StartTokenRefreshWorker(unsigned long long generation)
{
    std::thread([generation]()
        {
            while (!g_serviceStopping.load())
            {
                time_t accessExp = 0;
                std::string refresh;
                std::string deviceId;

                {
                    std::lock_guard<std::mutex> lock(g_app.mutex);
                    if (!g_app.authenticated || generation != g_app.authGeneration)
                        return;
                    accessExp = g_app.accessExpiresAt;
                    refresh = g_app.refreshToken;
                    deviceId = g_app.loginDeviceId;
                }

                time_t now = time(nullptr);
                int waitSeconds = 60;
                if (accessExp > 0)
                {
                    waitSeconds = static_cast<int>(accessExp - now - 60);
                    waitSeconds = max(5, min(waitSeconds, 300));
                }

                for (int i = 0; i < waitSeconds && !g_serviceStopping.load(); ++i)
                {
                    Sleep(1000);
                    std::lock_guard<std::mutex> lock(g_app.mutex);
                    if (generation != g_app.authGeneration || !g_app.authenticated)
                        return;
                }

                std::string req = "{\"refreshToken\":\"" + JsonEscape(refresh) + "\",\"deviceId\":\"" + JsonEscape(deviceId) + "\"}";
                HttpResponse resp = HttpPostJson(L"/api/auth/refresh", req);

                std::lock_guard<std::mutex> lock(g_app.mutex);
                if (generation != g_app.authGeneration || !g_app.authenticated)
                    return;

                if (!resp.transportOk || resp.status != 200)
                {
                    ClearAuthLocked();
                    return;
                }

                std::string newAccess = ExtractJsonString(resp.body, "accessToken");
                std::string newRefresh = ExtractJsonString(resp.body, "refreshToken");
                if (newAccess.empty() || newRefresh.empty())
                {
                    ClearAuthLocked();
                    return;
                }

                g_app.accessToken = newAccess;
                g_app.refreshToken = newRefresh;
                g_app.accessExpiresAt = ExtractJwtExpiration(newAccess);
                g_app.refreshExpiresAt = ExtractJwtExpiration(newRefresh);
            }
        }).detach();
}

std::wstring GetGuiPath()
{
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

DWORD WINAPI DelayedLaunchGuiThread(LPVOID param)
{
    DWORD sessionId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(param));
    Sleep(5000);
    LaunchGuiInSession(sessionId);
    return 0;
}

void LaunchGuiInSessionDelayed(DWORD sessionId)
{
    HANDLE hThread = CreateThread(
        nullptr,
        0,
        DelayedLaunchGuiThread,
        reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(sessionId)),
        0,
        nullptr
    );

    if (hThread) CloseHandle(hThread);
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
        if (sid == 0) continue;

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
        if (!notif || notif->dwSessionId == 0) return NO_ERROR;

        switch (eventType)
        {
        case WTS_SESSION_LOGON:
        case WTS_SESSION_UNLOCK:
        case WTS_CONSOLE_CONNECT:
        case WTS_REMOTE_CONNECT:
            LaunchGuiInSessionDelayed(notif->dwSessionId);
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
    g_serviceStopping = true;
    RpcMgmtStopServerListening(nullptr);
}

void GetCurrentUser(handle_t, RpcUserInfo* info)
{
    if (!info) return;
    std::lock_guard<std::mutex> lock(g_app.mutex);
    info->authenticated = g_app.authenticated ? 1 : 0;
    info->username = RpcAllocString(g_app.username);
    info->statusCode = g_app.authenticated ? RPC_APP_OK : RPC_APP_NOT_AUTHENTICATED;
    info->message = RpcAllocString(g_app.authenticated ? L"Пользователь авторизован" : L"Пользователь не авторизован");
}

int Login(handle_t, wchar_t* username, wchar_t* password, wchar_t** errorMessage)
{
    if (errorMessage) *errorMessage = nullptr;

    std::wstring wUser = RpcStringOrEmpty(username);
    std::wstring wPass = RpcStringOrEmpty(password);
    std::string user = WideToUtf8(wUser);
    std::string pass = WideToUtf8(wPass);
    std::string deviceMac = GetPrimaryMacAddress();
    std::string deviceName = GetComputerNameUtf8();

    std::string body = "{\"username\":\"" + JsonEscape(user) + "\",\"password\":\"" + JsonEscape(pass) + "\",\"deviceId\":\"" + JsonEscape(deviceMac) + "\"}";
    HttpResponse resp = HttpPostJson(L"/api/auth/login", body);

    if (!resp.transportOk)
    {
        if (errorMessage) *errorMessage = RpcAllocString(L"Нет соединения с сервером авторизации");
        return RPC_APP_NETWORK_ERROR;
    }

    if (resp.status == 401)
    {
        if (errorMessage) *errorMessage = RpcAllocString(L"Неверный логин или пароль");
        return RPC_APP_BAD_CREDENTIALS;
    }

    if (resp.status != 200)
    {
        if (errorMessage) *errorMessage = RpcAllocString(ExtractServerMessage(resp.body));
        return RPC_APP_SERVER_ERROR;
    }

    std::string access = ExtractJsonString(resp.body, "accessToken");
    std::string refresh = ExtractJsonString(resp.body, "refreshToken");
    if (access.empty() || refresh.empty())
    {
        if (errorMessage) *errorMessage = RpcAllocString(L"Сервер не вернул токены");
        return RPC_APP_SERVER_ERROR;
    }

    unsigned long long authGen = 0;
    unsigned long long licGen = 0;
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        ClearAuthLocked();
        g_app.authenticated = true;
        g_app.username = wUser;
        g_app.accessToken = access;
        g_app.refreshToken = refresh;
        g_app.loginDeviceId = deviceMac;
        g_app.deviceMac = deviceMac;
        g_app.deviceName = deviceName;
        g_app.accessExpiresAt = ExtractJwtExpiration(access);
        g_app.refreshExpiresAt = ExtractJwtExpiration(refresh);
        authGen = ++g_app.authGeneration;
        licGen = g_app.licenseGeneration;
    }

    StartTokenRefreshWorker(authGen);

    int licenseCode = FetchLicenseStatusAndStore();
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        licGen = g_app.licenseGeneration;
    }
    if (licenseCode == RPC_APP_OK)
        StartLicenseRefreshWorker(licGen);

    if (errorMessage) *errorMessage = RpcAllocString(L"");
    return RPC_APP_OK;
}

void Logout(handle_t)
{
    std::lock_guard<std::mutex> lock(g_app.mutex);
    ClearAuthLocked();
}

void GetLicenseInfo(handle_t, RpcLicenseInfo* info)
{
    if (!info) return;

    std::lock_guard<std::mutex> lock(g_app.mutex);

    if (!g_app.authenticated)
    {
        info->hasLicense = 0;
        info->active = 0;
        info->blocked = 0;
        info->expirationDate = RpcAllocString(L"");
        info->statusCode = RPC_APP_NOT_AUTHENTICATED;
        info->message = RpcAllocString(L"Пользователь не авторизован");
        return;
    }

    info->hasLicense = g_app.hasLicense ? 1 : 0;
    info->active = g_app.licenseActive ? 1 : 0;
    info->blocked = g_app.licenseBlocked ? 1 : 0;
    info->expirationDate = RpcAllocString(g_app.licenseExpirationDate);
    info->statusCode = g_app.licenseStatusCode;
    info->message = RpcAllocString(g_app.licenseMessage);
}

int ActivateLicense(handle_t, wchar_t* activationKey, wchar_t** errorMessage)
{
    if (errorMessage) *errorMessage = nullptr;

    std::string token;
    std::string deviceMac;
    std::string deviceName;
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        if (!g_app.authenticated)
        {
            if (errorMessage) *errorMessage = RpcAllocString(L"Пользователь не авторизован");
            return RPC_APP_NOT_AUTHENTICATED;
        }
        token = g_app.accessToken;
        deviceMac = g_app.deviceMac;
        deviceName = g_app.deviceName;
    }

    std::string key = WideToUtf8(RpcStringOrEmpty(activationKey));
    std::string body = "{\"activationKey\":\"" + JsonEscape(key) + "\",\"deviceMac\":\"" + JsonEscape(deviceMac) + "\",\"deviceName\":\"" + JsonEscape(deviceName) + "\"}";

    HttpResponse resp = HttpPostJson(L"/api/licenses/activate", body, token);

    if (!resp.transportOk)
    {
        if (errorMessage) *errorMessage = RpcAllocString(L"Нет соединения с сервером лицензирования");
        return RPC_APP_NETWORK_ERROR;
    }

    if (resp.status == 200)
    {
        unsigned long long generation = 0;
        int code = RPC_APP_OK;
        {
            std::lock_guard<std::mutex> lock(g_app.mutex);
            code = StoreTicketFromResponseLocked(resp.body);
            generation = g_app.licenseGeneration;
        }
        if (code == RPC_APP_OK)
            StartLicenseRefreshWorker(generation);
        if (errorMessage) *errorMessage = RpcAllocString(L"");
        return code;
    }

    std::wstring message;
    int code = MapActivationError(resp.status, resp.body, message);

    if (code == RPC_APP_SESSION_EXPIRED)
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        ClearAuthLocked();
    }
    else
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        ClearLicenseLocked();
        g_app.licenseStatusCode = code;
        g_app.licenseMessage = message;
    }

    if (errorMessage) *errorMessage = RpcAllocString(message);
    return code;
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

    g_serviceStopping = true;
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
