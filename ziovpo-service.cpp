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
#include <bcrypt.h>

#include <vector>
#include <string>
#include <map>
#include <array>
#include <mutex>
#include <thread>
#include <atomic>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <queue>
#include <cstdint>
#include <cctype>
#include <cwctype>
#include <cstdio>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

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

enum class AvObjectType : unsigned int
{
    Unknown = 0,
    PE = 1,
    PythonScript = 2
};

struct AvSignatureRecord
{
    unsigned long long objectSignaturePrefix = 0;
    unsigned int objectSignatureLength = 0;
    std::vector<BYTE> objectSignature;
    unsigned long long offsetBegin = 0;
    unsigned long long offsetEnd = 0;
    AvObjectType objectType = AvObjectType::Unknown;
    std::vector<BYTE> avRecordSignature;
    std::wstring threatName;
};

struct AvDatabaseState
{
    std::mutex mutex;
    std::map<unsigned long long, std::vector<AvSignatureRecord>> records;
    bool loaded = false;
    int recordCount = 0;
    std::wstring releaseDate;
    int statusCode = RPC_APP_AV_DATABASE_NOT_LOADED;
    std::wstring message = L"Антивирусные базы не загружены";
};

AvDatabaseState g_avDb;

struct AhoNode
{
    std::array<int, 256> next;
    int fail = 0;
    std::vector<unsigned long long> outputs;

    AhoNode()
    {
        next.fill(-1);
    }
};

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

HttpResponse HttpGetJson(const wchar_t* path, const std::string& bearerToken = "", const wchar_t* host = kApiHost)
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

    HINTERNET hConnect = WinHttpConnect(hSession, host, kApiPort, 0);
    if (!hConnect)
    {
        result.winError = GetLastError();
        WinHttpCloseHandle(hSession);
        return result;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
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

    WinHttpSetOption(
        hRequest,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &securityFlags,
        sizeof(securityFlags));

    std::wstring headers = L"Accept: application/json\r\n";
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
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
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

std::wstring ToLowerW(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return value;
}

int HexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool HexToBytes(const std::string& hex, std::vector<BYTE>& bytes)
{
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex)
    {
        if (!isspace(static_cast<unsigned char>(c)))
            clean.push_back(c);
    }

    if (clean.size() % 2 != 0) return false;

    std::vector<BYTE> out;
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2)
    {
        int hi = HexDigit(clean[i]);
        int lo = HexDigit(clean[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<BYTE>((hi << 4) | lo));
    }

    bytes = std::move(out);
    return true;
}

unsigned long long PrefixFromBytes(const BYTE* bytes)
{
    unsigned long long prefix = 0;
    for (int i = 0; i < 8; ++i)
    {
        prefix = (prefix << 8) | bytes[i];
    }
    return prefix;
}

std::array<BYTE, 8> BytesFromPrefix(unsigned long long prefix)
{
    std::array<BYTE, 8> bytes{};
    for (int i = 7; i >= 0; --i)
    {
        bytes[i] = static_cast<BYTE>(prefix & 0xFF);
        prefix >>= 8;
    }
    return bytes;
}

AvObjectType ParseAvObjectType(const std::string& value)
{
    std::string upper = value;
    std::transform(upper.begin(), upper.end(), upper.begin(),
        [](unsigned char c) { return static_cast<char>(toupper(c)); });

    if (upper == "PE" || upper == "PORTABLE_EXECUTABLE") return AvObjectType::PE;
    if (upper == "PY" || upper == "PYTHON" || upper == "PYTHON_SCRIPT" || upper == "PYTHONSCRIPT")
        return AvObjectType::PythonScript;

    return AvObjectType::Unknown;
}

std::wstring AvObjectTypeName(AvObjectType type)
{
    switch (type)
    {
    case AvObjectType::PE: return L"PE";
    case AvObjectType::PythonScript: return L"Python Script";
    default: return L"Unknown";
    }
}

std::vector<std::string> SplitTopLevelJsonObjects(const std::string& json)
{
    std::vector<std::string> objects;
    bool inString = false;
    bool escape = false;
    int depth = 0;
    size_t objectStart = std::string::npos;

    for (size_t i = 0; i < json.size(); ++i)
    {
        char c = json[i];

        if (inString)
        {
            if (escape)
            {
                escape = false;
            }
            else if (c == '\\')
            {
                escape = true;
            }
            else if (c == '"')
            {
                inString = false;
            }
            continue;
        }

        if (c == '"')
        {
            inString = true;
            continue;
        }

        if (c == '{')
        {
            if (depth == 0) objectStart = i;
            ++depth;
        }
        else if (c == '}')
        {
            --depth;
            if (depth == 0 && objectStart != std::string::npos)
            {
                objects.push_back(json.substr(objectStart, i - objectStart + 1));
                objectStart = std::string::npos;
            }
        }
    }

    return objects;
}

void SetAvDatabaseStatus(bool loaded, int recordCount, int statusCode, const std::wstring& message, const std::wstring& releaseDate = L"")
{
    std::lock_guard<std::mutex> lock(g_avDb.mutex);
    if (!loaded) g_avDb.records.clear();
    g_avDb.loaded = loaded;
    g_avDb.recordCount = recordCount;
    g_avDb.statusCode = statusCode;
    g_avDb.message = message;
    g_avDb.releaseDate = releaseDate;
}

int LoadAvDatabaseFromJson(const std::string& json)
{
    std::map<unsigned long long, std::vector<AvSignatureRecord>> nextRecords;
    int recordCount = 0;
    std::string newestUpdate;

    for (const std::string& objectJson : SplitTopLevelJsonObjects(json))
    {
        std::string status = ExtractJsonString(objectJson, "status");
        if (!status.empty() && status != "ACTUAL") continue;

        std::vector<BYTE> firstBytes;
        if (!HexToBytes(ExtractJsonString(objectJson, "firstBytesHex"), firstBytes) || firstBytes.size() < 8)
            continue;

        std::vector<BYTE> signatureHash;
        if (!HexToBytes(ExtractJsonString(objectJson, "remainderHashHex"), signatureHash) || signatureHash.empty())
            continue;

        long long remainderLength = ExtractJsonInt64(objectJson, "remainderLength");
        long long offsetStart = ExtractJsonInt64(objectJson, "offsetStart");
        long long offsetEnd = ExtractJsonInt64(objectJson, "offsetEnd");
        if (remainderLength < 0 || remainderLength > 0xFFFFFFFFLL - 8 || offsetStart < 0 || offsetEnd < offsetStart)
            continue;

        AvObjectType objectType = ParseAvObjectType(ExtractJsonString(objectJson, "fileType"));
        if (objectType == AvObjectType::Unknown)
            continue;

        AvSignatureRecord record;
        record.objectSignaturePrefix = PrefixFromBytes(firstBytes.data());
        record.objectSignatureLength = static_cast<unsigned int>(8 + remainderLength);
        record.objectSignature = std::move(signatureHash);
        record.offsetBegin = static_cast<unsigned long long>(offsetStart);
        record.offsetEnd = static_cast<unsigned long long>(offsetEnd);
        record.objectType = objectType;
        record.threatName = Utf8ToWide(ExtractJsonString(objectJson, "threatName"));
        if (record.threatName.empty())
            record.threatName = Utf8ToWide(ExtractJsonString(objectJson, "id"));

        std::string signatureBytes = Base64UrlDecode(ExtractJsonString(objectJson, "digitalSignatureBase64"));
        record.avRecordSignature.assign(signatureBytes.begin(), signatureBytes.end());

        std::string updatedAt = ExtractJsonString(objectJson, "updatedAt");
        if (updatedAt > newestUpdate) newestUpdate = updatedAt;

        nextRecords[record.objectSignaturePrefix].push_back(std::move(record));
        ++recordCount;
    }

    std::wstring releaseDate = newestUpdate.empty() ? TodayYmd() : Utf8ToWide(newestUpdate);

    {
        std::lock_guard<std::mutex> lock(g_avDb.mutex);
        g_avDb.records = std::move(nextRecords);
        g_avDb.loaded = true;
        g_avDb.recordCount = recordCount;
        g_avDb.releaseDate = releaseDate;
        g_avDb.statusCode = RPC_APP_OK;
        g_avDb.message = L"Антивирусные базы загружены";
    }

    return RPC_APP_OK;
}

int LoadAvDatabaseFromServer()
{
    std::string token;
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        if (!g_app.authenticated || !g_app.licenseActive)
        {
            SetAvDatabaseStatus(false, 0, RPC_APP_NO_LICENSE, L"Для загрузки баз нужна активная лицензия");
            return RPC_APP_NO_LICENSE;
        }
        token = g_app.accessToken;
    }

    HttpResponse resp = HttpGetJson(L"/api/signatures", token);
    if ((!resp.transportOk || resp.status == 404) && lstrcmpiW(kApiHost, L"localhost") != 0)
    {
        HttpResponse localResp = HttpGetJson(L"/api/signatures", token, L"localhost");
        if (localResp.transportOk || !resp.transportOk)
            resp = std::move(localResp);
    }

    if (!resp.transportOk)
    {
        SetAvDatabaseStatus(false, 0, RPC_APP_NETWORK_ERROR, L"Не удалось загрузить антивирусные базы: нет связи с сервером");
        return RPC_APP_NETWORK_ERROR;
    }

    if (resp.status == 401 || resp.status == 403)
    {
        SetAvDatabaseStatus(false, 0, RPC_APP_SESSION_EXPIRED, L"Сессия истекла. Выполните вход снова");
        return RPC_APP_SESSION_EXPIRED;
    }

    if (resp.status != 200)
    {
        SetAvDatabaseStatus(false, 0, RPC_APP_SERVER_ERROR, L"Сервер не вернул антивирусные базы: " + ExtractServerMessage(resp.body));
        return RPC_APP_SERVER_ERROR;
    }

    return LoadAvDatabaseFromJson(resp.body);
}

bool ComputeSha256(const std::vector<BYTE>& data, std::vector<BYTE>& hash)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD cbData = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return false;

    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &cbData, 0) != 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &cbData, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    std::vector<BYTE> hashObject(objectLength);
    hash.assign(hashLength, 0);

    if (BCryptCreateHash(alg, &hashHandle, hashObject.data(), objectLength, nullptr, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    NTSTATUS status = 0;
    if (!data.empty())
    {
        status = BCryptHashData(hashHandle, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
    }

    if (status == 0)
        status = BCryptFinishHash(hashHandle, hash.data(), hashLength, 0);

    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(alg, 0);
    return status == 0;
}

bool SignatureHashMatches(const BYTE* prefixBytes, const std::vector<BYTE>& remainder, const std::vector<BYTE>& expectedHash)
{
    std::vector<BYTE> hash;
    if (ComputeSha256(remainder, hash) && hash == expectedHash)
        return true;

    std::vector<BYTE> full;
    full.reserve(8 + remainder.size());
    full.insert(full.end(), prefixBytes, prefixBytes + 8);
    full.insert(full.end(), remainder.begin(), remainder.end());

    return ComputeSha256(full, hash) && hash == expectedHash;
}

AvObjectType DetectObjectType(const std::filesystem::path& path)
{
    std::wstring ext = ToLowerW(path.extension().wstring());
    if (ext == L".py" || ext == L".pyw")
        return AvObjectType::PythonScript;

    if (ext == L".exe" || ext == L".dll" || ext == L".sys")
        return AvObjectType::PE;

    std::ifstream file(path, std::ios::binary);
    if (!file) return AvObjectType::Unknown;

    char magic[2]{};
    file.read(magic, sizeof(magic));
    if (file.gcount() == 2 && magic[0] == 'M' && magic[1] == 'Z')
        return AvObjectType::PE;

    return AvObjectType::Unknown;
}

struct AvDatabaseSnapshot
{
    std::map<unsigned long long, std::vector<AvSignatureRecord>> records;
    std::vector<AhoNode> ahoNodes;
};

std::vector<AhoNode> BuildAhoAutomaton(const std::map<unsigned long long,  std::vector<AvSignatureRecord>>& records)
{
    std::vector<AhoNode> nodes(1);

    for (const auto& [prefix, group] : records)
    {
        if (group.empty()) continue;

        int state = 0;
        std::array<BYTE, 8> bytes = BytesFromPrefix(prefix);
        for (BYTE b : bytes)
        {
            int& next = nodes[state].next[b];
            if (next == -1)
            {
                next = static_cast<int>(nodes.size());
                nodes.emplace_back();
            }
            state = next;
        }
        nodes[state].outputs.push_back(prefix);
    }

    std::queue<int> q;
    for (int b = 0; b < 256; ++b)
    {
        int next = nodes[0].next[b];
        if (next != -1)
        {
            nodes[next].fail = 0;
            q.push(next);
        }
        else
        {
            nodes[0].next[b] = 0;
        }
    }

    while (!q.empty())
    {
        int state = q.front();
        q.pop();

        for (int b = 0; b < 256; ++b)
        {
            int next = nodes[state].next[b];
            if (next != -1)
            {
                int fail = nodes[state].fail;
                nodes[next].fail = nodes[fail].next[b];

                const auto& failOutputs = nodes[nodes[next].fail].outputs;
                nodes[next].outputs.insert(nodes[next].outputs.end(), failOutputs.begin(), failOutputs.end());

                q.push(next);
            }
            else
            {
                nodes[state].next[b] = nodes[nodes[state].fail].next[b];
            }
        }
    }

    return nodes;
}

int PrepareScanSnapshot(AvDatabaseSnapshot& snapshot, std::wstring& message)
{
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        if (!g_app.authenticated)
        {
            message = L"Пользователь не авторизован";
            return RPC_APP_NOT_AUTHENTICATED;
        }

        if (!g_app.licenseActive)
        {
            message = g_app.licenseMessage.empty() ? L"Нет активной лицензии" : g_app.licenseMessage;
            return g_app.licenseStatusCode == RPC_APP_OK ? RPC_APP_NO_LICENSE : g_app.licenseStatusCode;
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_avDb.mutex);
        if (!g_avDb.loaded)
        {
            message = g_avDb.message.empty() ? L"Антивирусные базы не загружены" : g_avDb.message;
            return RPC_APP_AV_DATABASE_NOT_LOADED;
        }

        snapshot.records = g_avDb.records;
    }

    snapshot.ahoNodes = BuildAhoAutomaton(snapshot.records);
    return RPC_APP_OK;
}

struct FileScanOutcome
{
    int statusCode = RPC_APP_OK;
    bool scanned = false;
    bool infected = false;
    std::wstring objectPath;
    std::wstring threatName;
    std::wstring message;
};

bool ScanStream(std::istream& stream, AvObjectType objectType, const AvDatabaseSnapshot& db, std::wstring& threatName)
{
    constexpr unsigned int kPrefixLength = 8;
    constexpr unsigned int kMaxSignatureRemainderRead = 16 * 1024 * 1024;

    if (objectType == AvObjectType::Unknown || db.records.empty() || db.ahoNodes.empty())
        return false;

    int state = 0;
    unsigned long long position = 0;
    char ch = 0;

    stream.clear();
    stream.seekg(0, std::ios::beg);

    while (stream.read(&ch, 1))
    {
        BYTE b = static_cast<BYTE>(ch);
        state = db.ahoNodes[state].next[b];

        if (!db.ahoNodes[state].outputs.empty() && position + 1 >= kPrefixLength)
        {
            unsigned long long offset = position + 1 - kPrefixLength;
            std::streampos savedPos = stream.tellg();

            for (unsigned long long prefix : db.ahoNodes[state].outputs)
            {
                auto it = db.records.find(prefix);
                if (it == db.records.end())
                    continue;

                std::array<BYTE, kPrefixLength> prefixBytes = BytesFromPrefix(prefix);
                for (const AvSignatureRecord& record : it->second)
                {
                    if (record.objectType != objectType)
                        continue;

                    if (offset < record.offsetBegin || offset > record.offsetEnd)
                        continue;

                    if (record.objectSignatureLength < kPrefixLength)
                        continue;

                    unsigned int remainderLength = record.objectSignatureLength - kPrefixLength;
                    if (remainderLength > kMaxSignatureRemainderRead)
                        continue;

                    std::vector<BYTE> remainder(remainderLength);
                    if (remainderLength > 0)
                    {
                        stream.clear();
                        stream.seekg(static_cast<std::streamoff>(offset + kPrefixLength), std::ios::beg);
                        if (!stream) continue;

                        stream.read(reinterpret_cast<char*>(remainder.data()), remainder.size());
                        if (stream.gcount() != static_cast<std::streamsize>(remainder.size()))
                            continue;
                    }

                    if (SignatureHashMatches(prefixBytes.data(), remainder, record.objectSignature))
                    {
                        threatName = record.threatName.empty() ? L"Unknown threat" : record.threatName;
                        return true;
                    }
                }
            }

            stream.clear();
            stream.seekg(savedPos, std::ios::beg);
        }

        ++position;
    }

    return false;
}

FileScanOutcome ScanFileInternal(const std::filesystem::path& path, const AvDatabaseSnapshot& db)
{
    FileScanOutcome outcome;
    outcome.objectPath = path.wstring();

    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
    {
        outcome.statusCode = RPC_APP_SCAN_ERROR;
        outcome.message = L"Файл не найден или не является обычным файлом";
        return outcome;
    }

    AvObjectType objectType = DetectObjectType(path);
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        outcome.statusCode = RPC_APP_SCAN_ERROR;
        outcome.message = L"Не удалось открыть файл для чтения";
        return outcome;
    }

    outcome.scanned = true;
    outcome.infected = ScanStream(file, objectType, db, outcome.threatName);
    outcome.message = outcome.infected
        ? L"Обнаружена угроза: " + outcome.threatName
        : L"Угроз не найдено";
    return outcome;
}

void AppendReportLine(std::wstring& report, const std::wstring& line)
{
    constexpr size_t kMaxReportChars = 12000;
    if (report.size() >= kMaxReportChars)
        return;

    if (report.size() + line.size() + 2 > kMaxReportChars)
    {
        report += L"... отчет обрезан\r\n";
        return;
    }

    report += line;
    report += L"\r\n";
}

std::wstring NowTimestamp()
{
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t buf[32]{};
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

struct AggregateScanOutcome
{
    int statusCode = RPC_APP_OK;
    bool infected = false;
    int scannedFiles = 0;
    int threatsFound = 0;
    std::wstring objectPath;
    std::wstring threatName;
    std::wstring message;
};

AggregateScanOutcome AggregateFromFileOutcome(const FileScanOutcome& file)
{
    AggregateScanOutcome result;
    result.statusCode = file.statusCode;
    result.infected = file.infected;
    result.scannedFiles = file.scanned ? 1 : 0;
    result.threatsFound = file.infected ? 1 : 0;
    result.objectPath = file.objectPath;
    result.threatName = file.threatName;
    result.message = file.message;
    return result;
}

AggregateScanOutcome ScanDirectoryTreeInternal(const std::filesystem::path& root, const AvDatabaseSnapshot& db)
{
    AggregateScanOutcome result;
    result.objectPath = root.wstring();

    std::error_code ec;
    if (!std::filesystem::is_directory(root, ec))
    {
        result.statusCode = RPC_APP_SCAN_ERROR;
        result.message = L"Папка не найдена или недоступна";
        return result;
    }

    std::wstring report;
    std::filesystem::recursive_directory_iterator it(
        root,
        std::filesystem::directory_options::skip_permission_denied,
        ec);
    std::filesystem::recursive_directory_iterator end;

    if (ec)
    {
        result.statusCode = RPC_APP_SCAN_ERROR;
        result.message = L"Не удалось начать обход папки";
        return result;
    }

    while (it != end)
    {
        std::error_code fileEc;
        bool regular = it->is_regular_file(fileEc);
        if (!fileEc && regular)
        {
            FileScanOutcome outcome = ScanFileInternal(it->path(), db);
            if (outcome.scanned)
                ++result.scannedFiles;

            if (outcome.infected)
            {
                ++result.threatsFound;
                result.infected = true;
                if (result.threatName.empty()) result.threatName = outcome.threatName;
                AppendReportLine(report, L"[УГРОЗА] " + outcome.objectPath + L" - " + outcome.threatName);
            }
            else if (outcome.statusCode != RPC_APP_OK)
            {
                AppendReportLine(report, L"[ПРОПУЩЕН] " + outcome.objectPath + L" - " + outcome.message);
            }
        }

        it.increment(ec);
        if (ec) ec.clear();
    }

    std::wstringstream summary;
    summary << L"Проверено файлов: " << result.scannedFiles << L". Найдено угроз: " << result.threatsFound << L".";
    if (!report.empty())
    {
        summary << L"\r\n\r\n" << report;
    }
    else if (result.threatsFound == 0)
    {
        summary << L"\r\nУгроз не найдено.";
    }

    result.message = summary.str();
    return result;
}

AggregateScanOutcome ScanFixedDrivesInternal(const AvDatabaseSnapshot& db)
{
    AggregateScanOutcome result;
    result.objectPath = L"Все несъемные диски";

    DWORD required = GetLogicalDriveStringsW(0, nullptr);
    if (required == 0)
    {
        result.statusCode = RPC_APP_SCAN_ERROR;
        result.message = L"Не удалось получить список дисков";
        return result;
    }

    std::vector<wchar_t> buffer(required + 2);
    if (GetLogicalDriveStringsW(static_cast<DWORD>(buffer.size()), buffer.data()) == 0)
    {
        result.statusCode = RPC_APP_SCAN_ERROR;
        result.message = L"Не удалось получить список дисков";
        return result;
    }

    int fixedDriveCount = 0;
    std::wstring report;
    for (const wchar_t* drive = buffer.data(); *drive; drive += wcslen(drive) + 1)
    {
        if (GetDriveTypeW(drive) != DRIVE_FIXED)
            continue;

        ++fixedDriveCount;
        AggregateScanOutcome driveResult = ScanDirectoryTreeInternal(std::filesystem::path(drive), db);
        result.scannedFiles += driveResult.scannedFiles;
        result.threatsFound += driveResult.threatsFound;
        result.infected = result.infected || driveResult.infected;
        if (result.threatName.empty()) result.threatName = driveResult.threatName;

        std::wstringstream line;
        line << L"Диск " << drive << L": проверено " << driveResult.scannedFiles
            << L", угроз " << driveResult.threatsFound;
        AppendReportLine(report, line.str());
        if (driveResult.infected)
            AppendReportLine(report, driveResult.message);
    }

    if (fixedDriveCount == 0)
    {
        result.statusCode = RPC_APP_SCAN_ERROR;
        result.message = L"Несъемные диски не найдены";
        return result;
    }

    std::wstringstream summary;
    summary << L"Проверено несъемных дисков: " << fixedDriveCount
        << L". Проверено файлов: " << result.scannedFiles
        << L". Найдено угроз: " << result.threatsFound << L".";
    if (!report.empty())
        summary << L"\r\n\r\n" << report;

    result.message = summary.str();
    return result;
}

AggregateScanOutcome ScanConfiguredTarget(bool scanFixedDrives, const std::wstring& path)
{
    std::wstring readyMessage;
    AvDatabaseSnapshot snapshot;
    int ready = PrepareScanSnapshot(snapshot, readyMessage);
    if (ready != RPC_APP_OK)
    {
        AggregateScanOutcome error;
        error.statusCode = ready;
        error.objectPath = scanFixedDrives ? L"Все несъемные диски" : path;
        error.message = readyMessage;
        return error;
    }

    if (scanFixedDrives)
        return ScanFixedDrivesInternal(snapshot);

    std::filesystem::path fsPath(path);
    std::error_code ec;
    if (std::filesystem::is_directory(fsPath, ec))
        return ScanDirectoryTreeInternal(fsPath, snapshot);

    return AggregateFromFileOutcome(ScanFileInternal(fsPath, snapshot));
}

void FillScanResult(RpcScanResult* result, int statusCode, bool infected, int scannedFiles, int threatsFound,
    const std::wstring& objectPath, const std::wstring& threatName, const std::wstring& message)
{
    if (!result) return;

    result->statusCode = statusCode;
    result->infected = infected ? 1 : 0;
    result->scannedFiles = scannedFiles;
    result->threatsFound = threatsFound;
    result->objectPath = RpcAllocString(objectPath);
    result->threatName = RpcAllocString(threatName);
    result->message = RpcAllocString(message);
}

void FillScanResult(RpcScanResult* result, const AggregateScanOutcome& scan)
{
    FillScanResult(
        result,
        scan.statusCode,
        scan.infected,
        scan.scannedFiles,
        scan.threatsFound,
        scan.objectPath,
        scan.threatName,
        scan.message);
}

struct ScheduledScanState
{
    std::mutex mutex;
    bool enabled = false;
    int intervalMinutes = 60;
    bool scanFixedDrives = false;
    std::wstring path;
    unsigned long long generation = 0;
    std::wstring lastRunTime;
    int lastStatusCode = RPC_APP_OK;
    int lastScannedFiles = 0;
    int lastThreatsFound = 0;
    std::wstring lastMessage = L"Сканирование по расписанию не выполнялось";
};

struct DirectoryMonitorState
{
    std::mutex mutex;
    bool enabled = false;
    std::wstring path;
    unsigned long long generation = 0;
    std::wstring lastEventTime;
    int lastStatusCode = RPC_APP_OK;
    int lastScannedFiles = 0;
    int lastThreatsFound = 0;
    std::wstring lastMessage = L"Мониторинг не выполнялся";
};

ScheduledScanState g_schedule;
DirectoryMonitorState g_monitor;

void StoreScheduledScanResult(const AggregateScanOutcome& scan)
{
    std::lock_guard<std::mutex> lock(g_schedule.mutex);
    g_schedule.lastRunTime = NowTimestamp();
    g_schedule.lastStatusCode = scan.statusCode;
    g_schedule.lastScannedFiles = scan.scannedFiles;
    g_schedule.lastThreatsFound = scan.threatsFound;
    g_schedule.lastMessage = scan.message;
}

void StoreMonitorScanResult(const AggregateScanOutcome& scan)
{
    std::lock_guard<std::mutex> lock(g_monitor.mutex);
    g_monitor.lastEventTime = NowTimestamp();
    g_monitor.lastStatusCode = scan.statusCode;
    g_monitor.lastScannedFiles = scan.scannedFiles;
    g_monitor.lastThreatsFound = scan.threatsFound;
    g_monitor.lastMessage = scan.message;
}

void StartScheduledScanWorker(unsigned long long generation)
{
    std::thread([generation]()
        {
            while (!g_serviceStopping.load())
            {
                int waitSeconds = 60;
                {
                    std::lock_guard<std::mutex> lock(g_schedule.mutex);
                    if (!g_schedule.enabled || g_schedule.generation != generation)
                        return;
                    waitSeconds = max(1, g_schedule.intervalMinutes) * 60;
                }

                for (int i = 0; i < waitSeconds && !g_serviceStopping.load(); ++i)
                {
                    Sleep(1000);
                    std::lock_guard<std::mutex> lock(g_schedule.mutex);
                    if (!g_schedule.enabled || g_schedule.generation != generation)
                        return;
                }

                bool scanFixedDrives = false;
                std::wstring path;
                {
                    std::lock_guard<std::mutex> lock(g_schedule.mutex);
                    if (!g_schedule.enabled || g_schedule.generation != generation)
                        return;
                    scanFixedDrives = g_schedule.scanFixedDrives;
                    path = g_schedule.path;
                }

                StoreScheduledScanResult(ScanConfiguredTarget(scanFixedDrives, path));
            }
        }).detach();
}

void StartDirectoryMonitorWorker(unsigned long long generation)
{
    std::thread([generation]()
        {
            std::wstring path;
            {
                std::lock_guard<std::mutex> lock(g_monitor.mutex);
                if (!g_monitor.enabled || g_monitor.generation != generation)
                    return;
                path = g_monitor.path;
            }

            HANDLE hChange = FindFirstChangeNotificationW(
                path.c_str(),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE);

            if (hChange == INVALID_HANDLE_VALUE)
            {
                AggregateScanOutcome error;
                error.statusCode = RPC_APP_SCAN_ERROR;
                error.objectPath = path;
                error.message = L"Не удалось запустить мониторинг папки";
                StoreMonitorScanResult(error);
                return;
            }

            while (!g_serviceStopping.load())
            {
                {
                    std::lock_guard<std::mutex> lock(g_monitor.mutex);
                    if (!g_monitor.enabled || g_monitor.generation != generation)
                        break;
                }

                DWORD wait = WaitForSingleObject(hChange, 2000);
                if (wait == WAIT_OBJECT_0)
                {
                    StoreMonitorScanResult(ScanConfiguredTarget(false, path));
                    if (!FindNextChangeNotification(hChange))
                        break;
                }
                else if (wait != WAIT_TIMEOUT)
                {
                    break;
                }
            }

            FindCloseChangeNotification(hChange);
        }).detach();
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
    {
        StartLicenseRefreshWorker(licGen);
        LoadAvDatabaseFromServer();
    }

    if (errorMessage) *errorMessage = RpcAllocString(L"");
    return RPC_APP_OK;
}

void Logout(handle_t)
{
    {
        std::lock_guard<std::mutex> lock(g_app.mutex);
        ClearAuthLocked();
    }
    SetAvDatabaseStatus(false, 0, RPC_APP_AV_DATABASE_NOT_LOADED, L"Антивирусные базы не загружены");
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
        {
            StartLicenseRefreshWorker(generation);
            LoadAvDatabaseFromServer();
        }
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

void GetAvDatabaseInfo(handle_t, RpcAvDatabaseInfo* info)
{
    if (!info) return;

    std::lock_guard<std::mutex> lock(g_avDb.mutex);
    info->loaded = g_avDb.loaded ? 1 : 0;
    info->recordCount = g_avDb.recordCount;
    info->releaseDate = RpcAllocString(g_avDb.releaseDate);
    info->statusCode = g_avDb.statusCode;
    info->message = RpcAllocString(g_avDb.message);
}

int ScanFile(handle_t, wchar_t* path, RpcScanResult* result)
{
    std::wstring wPath = RpcStringOrEmpty(path);
    std::wstring message;
    AvDatabaseSnapshot snapshot;

    int ready = PrepareScanSnapshot(snapshot, message);
    if (ready != RPC_APP_OK)
    {
        FillScanResult(result, ready, false, 0, 0, wPath, L"", message);
        return ready;
    }

    FileScanOutcome outcome = ScanFileInternal(std::filesystem::path(wPath), snapshot);
    FillScanResult(
        result,
        outcome.statusCode,
        outcome.infected,
        outcome.scanned ? 1 : 0,
        outcome.infected ? 1 : 0,
        outcome.objectPath,
        outcome.threatName,
        outcome.message);

    return outcome.statusCode;
}

int ScanDirectory(handle_t, wchar_t* path, RpcScanResult* result)
{
    std::wstring wPath = RpcStringOrEmpty(path);
    AggregateScanOutcome scan = ScanConfiguredTarget(false, wPath);
    FillScanResult(result, scan);
    return scan.statusCode;

    std::wstring message;
    AvDatabaseSnapshot snapshot;

    int ready = PrepareScanSnapshot(snapshot, message);
    if (ready != RPC_APP_OK)
    {
        FillScanResult(result, ready, false, 0, 0, wPath, L"", message);
        return ready;
    }

    std::filesystem::path root(wPath);
    std::error_code ec;
    if (!std::filesystem::is_directory(root, ec))
    {
        FillScanResult(result, RPC_APP_SCAN_ERROR, false, 0, 0, wPath, L"", L"Папка не найдена или недоступна");
        return RPC_APP_SCAN_ERROR;
    }

    int scannedFiles = 0;
    int threatsFound = 0;
    std::wstring firstThreat;
    std::wstring report;

    std::filesystem::recursive_directory_iterator it(
        root,
        std::filesystem::directory_options::skip_permission_denied,
        ec);
    std::filesystem::recursive_directory_iterator end;

    if (ec)
    {
        FillScanResult(result, RPC_APP_SCAN_ERROR, false, 0, 0, wPath, L"", L"Не удалось начать обход папки");
        return RPC_APP_SCAN_ERROR;
    }

    while (it != end)
    {
        std::error_code fileEc;
        bool regular = it->is_regular_file(fileEc);
        if (!fileEc && regular)
        {
            FileScanOutcome outcome = ScanFileInternal(it->path(), snapshot);
            if (outcome.scanned)
                ++scannedFiles;

            if (outcome.infected)
            {
                ++threatsFound;
                if (firstThreat.empty()) firstThreat = outcome.threatName;
                AppendReportLine(report, L"[УГРОЗА] " + outcome.objectPath + L" - " + outcome.threatName);
            }
            else if (outcome.statusCode != RPC_APP_OK)
            {
                AppendReportLine(report, L"[ПРОПУЩЕН] " + outcome.objectPath + L" - " + outcome.message);
            }
        }

        it.increment(ec);
        if (ec) ec.clear();
    }

    std::wstringstream summary;
    summary << L"Проверено файлов: " << scannedFiles << L". Найдено угроз: " << threatsFound << L".";
    if (!report.empty())
    {
        summary << L"\r\n\r\n" << report;
    }
    else if (threatsFound == 0)
    {
        summary << L"\r\nУгроз не найдено.";
    }

    FillScanResult(
        result,
        RPC_APP_OK,
        threatsFound > 0,
        scannedFiles,
        threatsFound,
        wPath,
        firstThreat,
        summary.str());

    return RPC_APP_OK;
}

int ScanFixedDrives(handle_t, RpcScanResult* result)
{
    AggregateScanOutcome scan = ScanConfiguredTarget(true, L"");
    FillScanResult(result, scan);
    return scan.statusCode;
}

int ConfigureScheduledScan(handle_t, int enabled, int intervalMinutes, int scanFixedDrives, wchar_t* path)
{
    std::wstring wPath = RpcStringOrEmpty(path);

    if (enabled)
    {
        if (intervalMinutes < 1) intervalMinutes = 1;
        if (!scanFixedDrives)
        {
            std::error_code ec;
            std::filesystem::path fsPath(wPath);
            if (wPath.empty() || (!std::filesystem::is_directory(fsPath, ec) &&
                !std::filesystem::is_regular_file(fsPath, ec)))
            {
                return RPC_APP_SCAN_ERROR;
            }
        }
    }

    unsigned long long generation = 0;
    {
        std::lock_guard<std::mutex> lock(g_schedule.mutex);
        g_schedule.enabled = enabled != 0;
        g_schedule.intervalMinutes = intervalMinutes < 1 ? 1 : intervalMinutes;
        g_schedule.scanFixedDrives = scanFixedDrives != 0;
        g_schedule.path = wPath;
        g_schedule.lastMessage = g_schedule.enabled
            ? L"Сканирование по расписанию настроено"
            : L"Сканирование по расписанию отключено";
        generation = ++g_schedule.generation;
    }

    if (enabled)
        StartScheduledScanWorker(generation);

    return RPC_APP_OK;
}

void GetScheduledScanInfo(handle_t, RpcScheduledScanInfo* info)
{
    if (!info) return;

    std::lock_guard<std::mutex> lock(g_schedule.mutex);
    info->enabled = g_schedule.enabled ? 1 : 0;
    info->intervalMinutes = g_schedule.intervalMinutes;
    info->scanFixedDrives = g_schedule.scanFixedDrives ? 1 : 0;
    info->path = RpcAllocString(g_schedule.path);
    info->lastRunTime = RpcAllocString(g_schedule.lastRunTime);
    info->lastStatusCode = g_schedule.lastStatusCode;
    info->lastScannedFiles = g_schedule.lastScannedFiles;
    info->lastThreatsFound = g_schedule.lastThreatsFound;
    info->lastMessage = RpcAllocString(g_schedule.lastMessage);
}

int ConfigureDirectoryMonitor(handle_t, int enabled, wchar_t* path)
{
    std::wstring wPath = RpcStringOrEmpty(path);

    if (enabled)
    {
        std::error_code ec;
        if (wPath.empty() || !std::filesystem::is_directory(std::filesystem::path(wPath), ec))
            return RPC_APP_SCAN_ERROR;
    }

    unsigned long long generation = 0;
    {
        std::lock_guard<std::mutex> lock(g_monitor.mutex);
        g_monitor.enabled = enabled != 0;
        g_monitor.path = wPath;
        g_monitor.lastMessage = g_monitor.enabled
            ? L"Мониторинг папки включен"
            : L"Мониторинг папки отключен";
        generation = ++g_monitor.generation;
    }

    if (enabled)
        StartDirectoryMonitorWorker(generation);

    return RPC_APP_OK;
}

void GetDirectoryMonitorInfo(handle_t, RpcDirectoryMonitorInfo* info)
{
    if (!info) return;

    std::lock_guard<std::mutex> lock(g_monitor.mutex);
    info->enabled = g_monitor.enabled ? 1 : 0;
    info->path = RpcAllocString(g_monitor.path);
    info->lastEventTime = RpcAllocString(g_monitor.lastEventTime);
    info->lastStatusCode = g_monitor.lastStatusCode;
    info->lastScannedFiles = g_monitor.lastScannedFiles;
    info->lastThreatsFound = g_monitor.lastThreatsFound;
    info->lastMessage = RpcAllocString(g_monitor.lastMessage);
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
