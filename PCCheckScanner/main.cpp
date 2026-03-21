/*
 * PCCheckScanner.cpp  |  made by vxti
 * Roblox Competitive League -- Forensic PC Checker
 * C++ / Dear ImGui + DirectX 11
 *
 * ── Visual Studio Setup ─────────────────────────────────────────────────────
 * 1. New project → Windows Desktop Application (C++)
 * 2. Download Dear ImGui from https://github.com/ocornut/imgui
 *    Add to project (Add Existing Item):
 *      imgui.cpp, imgui_draw.cpp, imgui_tables.cpp, imgui_widgets.cpp
 *      backends/imgui_impl_win32.cpp
 *      backends/imgui_impl_dx11.cpp
 *    Add include path for imgui root + backends/
 * 3. Linker → Additional Dependencies:
 *      d3d11.lib; d3dcompiler.lib; dwmapi.lib; winhttp.lib
 * 4. Build → Release x64
 * 5. Run as Administrator
 * ─────────────────────────────────────────────────────────────────────────────
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#ifndef SM_CXPADDEDBORDER
#define SM_CXPADDEDBORDER 92
#endif
#ifndef SM_CYPADDEDBORDER
#define SM_CYPADDEDBORDER 93
#endif
#include <winsock2.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <psapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <initguid.h>
#include <evntprov.h>
#include <winevt.h>
#include <d3d11.h>
#include <dwmapi.h>

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <functional>
#include <memory>
#include <cstdio>
#include <cassert>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "setupapi.lib")

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "Resource.h"

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  COLOUR PALETTE
// ─────────────────────────────────────────────────────────────────────────────
#define COL_BG          ImVec4(0.055f,0.062f,0.070f,1)
#define COL_PANEL       ImVec4(0.081f,0.091f,0.104f,1)
#define COL_HEADER      ImVec4(0.041f,0.048f,0.057f,1)
#define COL_BORDER      ImVec4(0.212f,0.224f,0.241f,1)
#define COL_ACCENT      ImVec4(0.867f,0.569f,0.161f,1)
#define COL_ACCENT2     ImVec4(0.651f,0.420f,0.102f,1)
#define COL_OK          ImVec4(0.188f,0.808f,0.490f,1)
#define COL_OK_BG       ImVec4(0.078f,0.224f,0.157f,1)
#define COL_WARN        ImVec4(0.925f,0.690f,0.216f,1)
#define COL_WARN_BG     ImVec4(0.286f,0.196f,0.063f,1)
#define COL_CRIT        ImVec4(0.922f,0.239f,0.239f,1)
#define COL_CRIT_BG     ImVec4(0.278f,0.078f,0.082f,1)
#define COL_SUSP        ImVec4(0.820f,0.514f,0.224f,1)
#define COL_SUSP_BG     ImVec4(0.251f,0.153f,0.071f,1)
#define COL_INFO        ImVec4(0.475f,0.659f,0.980f,1)
#define COL_INFO_BG     ImVec4(0.114f,0.169f,0.290f,1)
#define COL_DIM         ImVec4(0.451f,0.482f,0.522f,1)
#define COL_MUTED       ImVec4(0.188f,0.204f,0.227f,1)
#define COL_TEXT        ImVec4(0.804f,0.824f,0.859f,1)
#define COL_BRIGHT      ImVec4(0.933f,0.941f,0.965f,1)
#define COL_MAGENTA     ImVec4(0.690f,0.427f,0.898f,1)

// Scan speed defaults (shorter than legacy 10+ minute MFTECmd + full AppData walks)
static constexpr bool   PCC_SKIP_SLOW_USN_EXPORT   = true;
static constexpr int    PCC_MFT_EXPORT_MS          = 120000;
static constexpr int    PCC_PECMD_MS               = 60000;
static constexpr int    PCC_LECMD_MS               = 45000;
static constexpr int    PCC_JLECMD_MS              = 90000;
static constexpr int    PCC_AMCACHE_MS           = 45000;
static constexpr size_t PCC_MAX_FILETREE_ENTRIES = 100000;

// ─────────────────────────────────────────────────────────────────────────────
//  BLACKLIST / WHITELIST
// ─────────────────────────────────────────────────────────────────────────────
static const std::vector<std::wstring> BL_TERMS = {
    L"Wave",L"Velocity",L"Potassium",L"Volcano",L"Xeno",L"Seliware",L"Volt",
    L"SirHurt",L"Solara",L"Bunni",L"Synapse",L"Isaeva",L"DX9WARE",L"Photon",
    L"MatrixHub",L"Ronin",L"Matcha",L"Serotonin",L"Severe",L"RbxCli",
    L"loader",L"Executor",L"Injector",L"Sploit",L"newui",L"oldui",
    L"newuimatrix",L"mcache.dat",L"_license.dat",L"a5ad761e"
};
static const std::vector<std::wstring> WL_TERMS = {
    L"XIM Technologies",L"XIM MATRIX",L"XIMMatrix",L"XIM Matrix",L"XIMMATRIX",
    L"StabilityMatrix",L"stability.matrix",L"matrixssl",L"matrix.org",
    L"Razer Synapse",L"RazerApp",L"nvvad",L"QWAVE",L"BakkesMod",L"Voicemod",
    L"Sideloadly",L"iCloud",L"Apple",L"OneDrive",L"Medal",L"Discord"
};

static bool TestBL(const std::wstring& s) {
    std::wstring lo = s; for (auto& c : lo) c = towlower(c);
    for (auto& t : BL_TERMS) {
        std::wstring tl = t; for (auto& c : tl) c = towlower(c);
        if (lo.find(tl) != std::wstring::npos) return true;
    }
    return false;
}
static bool TestWL(const std::wstring& s) {
    std::wstring lo = s; for (auto& c : lo) c = towlower(c);
    for (auto& t : WL_TERMS) {
        std::wstring tl = t; for (auto& c : tl) c = towlower(c);
        if (lo.find(tl) != std::wstring::npos) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CHEAT DATABASE
// ─────────────────────────────────────────────────────────────────────────────
struct CheatEntry {
    std::wstring name;
    std::wstring sha256;
    std::wstring sha1;
    uint64_t     sizeB;
};
static const std::vector<CheatEntry> CHEAT_DB = {
    {L"Matcha (Usermode)",    L"802CD648A686AD0B6FA94A420283478666A6FB8FA80ED0D2E00BE78590480FCA", L"B78C5998FA3BEF5118394D0CAB79A64523ABE902", 12523520},
    {L"Matcha (Kernel)",      L"0FC4FA5E890810722D0D7E669B7DB4E64544794A5A9DDC69D78EA9F8643A77F8", L"DD9E86B2B6F0F443DAA47FAA848497A1BCF00E4A", 12655616},
    {L"Severe",               L"D5B0B581FE5649662E0EC88406A92E02E8012041D78A41BFEB9BC44DCFF8A440", L"3FA9C887DF0A054350B85A853A18D412FD43251D", 3613696},
    {L"Matrix (newui)",       L"86B734D08FC815C1F34D502B880A05E4C8A7AF078EAE63FAB800AD34EC94C76B", L"94C99C2A6F895383E8A43073B28B51C2292C4475", 27136},
    {L"Matcha (updater)",     L"170FD4117643A03D739AA35743727E48DCB783A20AD903D38A4EFE6D95E5288C", L"1336E6E96AE094B25B8B6973D619B5F29FB89A49", 12841984},
    {L"Matcha (login loader)",L"F387640B8A8D28F2902768DBC2F66DCE7DFC98503483BEFD74FE31B3A41C6A10", L"4539C32FFA789C6ACB6A8AC55741179D1EDDAB8B", 6083072},
    {L"Severe (updater)",     L"624B0DD70E0F69B97E1525DEBEB6692D8D04D81F028B269F30F3C540AB219574", L"54DCF18EFE7643B2A5F7E62353F144DEAA3EB323", 213504},
};

static const std::vector<std::wstring> MFT_APPDATA_KW = {
    L"seliware",L"potassium",L"volcano",L"xeno",L"solara",L"bunni",L"velocity"
};
static const std::vector<std::wstring> MFT_USER_KW = {
    L"matcha",L"severe",L"newui",L"oldui",L"software.exe"
};

// ─────────────────────────────────────────────────────────────────────────────
//  LOG ENTRY
// ─────────────────────────────────────────────────────────────────────────────
enum class Badge { OK, CRIT, SUSP, WARN, INFO, SKIP, NONE };

struct LogEntry {
    Badge       badge  = Badge::NONE;
    std::string label;
    std::string value;
    std::string phase;  // "02", "07", etc -- empty = no finding
};

struct Finding {
    std::string phase;
    std::string label;
    std::string value;
    Badge       badge;
};

// ─────────────────────────────────────────────────────────────────────────────
//  SHARED STATE  (written by scan thread, read by UI thread)
// ─────────────────────────────────────────────────────────────────────────────
struct ScanState {
    std::mutex              mtx;
    std::vector<LogEntry>   log;
    std::vector<Finding>    crits;
    std::vector<Finding>    warns;
    std::atomic<bool>       running{ false };
    std::atomic<bool>       stopReq{ false };
    std::string             phaseLabel{ "Idle" };
    std::string             statusMsg{ "Ready -- run as Administrator for full access" };
    std::chrono::steady_clock::time_point startTime;

    // per-phase state: 0=idle,1=running,2=done,3=crit,4=skip
    std::unordered_map<std::string,int> phaseState;

    void pushLog(Badge b, const std::string& label, const std::string& val, const std::string& ph="") {
        std::lock_guard<std::mutex> lk(mtx);
        log.push_back({b, label, val, ph});
        if (!ph.empty()) {
            Finding f{ph,label,val,b};
            if (b == Badge::CRIT) crits.push_back(f);
            else if (b == Badge::SUSP || b == Badge::WARN) warns.push_back(f);
        }
    }
    void pushSec(const std::string& num, const std::string& title) {
        std::lock_guard<std::mutex> lk(mtx);
        log.push_back({Badge::NONE, "§" + num, title, ""});
    }
    void pushSub(const std::string& title) {
        std::lock_guard<std::mutex> lk(mtx);
        log.push_back({Badge::NONE, "▶", title, ""});
    }
    void setPhase(const std::string& num, int state) {
        std::lock_guard<std::mutex> lk(mtx);
        phaseState[num] = state;
    }
    void setStatus(const std::string& s) {
        std::lock_guard<std::mutex> lk(mtx);
        statusMsg = s;
    }
    void setPhaseLbl(const std::string& s) {
        std::lock_guard<std::mutex> lk(mtx);
        phaseLabel = s;
    }
    void reset() {
        std::lock_guard<std::mutex> lk(mtx);
        log.clear(); crits.clear(); warns.clear();
        phaseState.clear(); phaseLabel = "Idle";
        statusMsg = "Scan starting...";
    }
    std::string elapsed() {
        if (!running) return "00:00";
        auto d = std::chrono::steady_clock::now() - startTime;
        int s = (int)std::chrono::duration_cast<std::chrono::seconds>(d).count();
        char buf[16]; snprintf(buf,sizeof(buf),"%02d:%02d",s/60,s%60);
        return buf;
    }
};

static ScanState G;

// ─────────────────────────────────────────────────────────────────────────────
//  UTILITY HELPERS
// ─────────────────────────────────────────────────────────────────────────────
static std::string WtoA(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8,0,w.data(),(int)w.size(),nullptr,0,nullptr,nullptr);
    std::string s(n,0);
    WideCharToMultiByte(CP_UTF8,0,w.data(),(int)w.size(),s.data(),n,nullptr,nullptr);
    return s;
}
static std::wstring AtoW(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0);
    std::wstring w(n,0);
    MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),w.data(),n);
    return w;
}
static std::wstring ToLower(std::wstring s) {
    for (auto& c:s) c=towlower(c); return s;
}
static std::string ToLowerA(std::string s) {
    for (auto& c:s) c=(char)tolower((unsigned char)c); return s;
}

// file_time_type is not directly comparable to system_clock; convert for logging/age checks.
static std::chrono::system_clock::time_point FileTimeToSystemClock(const fs::file_time_type& ft) {
    using namespace std::chrono;
    return time_point_cast<system_clock::duration>(
        ft - fs::file_time_type::clock::now() + system_clock::now()
    );
}
static std::string FileTimeToUtcIso8601(const fs::file_time_type& ft) {
    const auto tp = FileTimeToSystemClock(ft);
    const std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm gmt{};
    gmtime_s(&gmt, &tt);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &gmt);
    return buf;
}

// SHA-256 via BCrypt
static std::wstring SHA256File(const std::wstring& path) {
    BCRYPT_ALG_HANDLE hAlg=nullptr;
    BCRYPT_HASH_HANDLE hHash=nullptr;
    std::wstring result;
    if (BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_SHA256_ALGORITHM,nullptr,0)!=0) return {};
    DWORD hashLen=0, cbData=0;
    BCryptGetProperty(hAlg,BCRYPT_HASH_LENGTH,(PUCHAR)&hashLen,sizeof(DWORD),&cbData,0);
    HANDLE hFile=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
                             nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (hFile==INVALID_HANDLE_VALUE) {BCryptCloseAlgorithmProvider(hAlg,0);return {};}
    BCryptCreateHash(hAlg,&hHash,nullptr,0,nullptr,0,0);
    std::vector<BYTE> buf(65536);
    DWORD read=0;
    while (ReadFile(hFile,buf.data(),(DWORD)buf.size(),&read,nullptr) && read>0)
        BCryptHashData(hHash,buf.data(),read,0);
    CloseHandle(hFile);
    std::vector<BYTE> hash(hashLen);
    BCryptFinishHash(hHash,hash.data(),hashLen,0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg,0);
    wchar_t hex[3];
    for (auto b:hash) { swprintf(hex,3,L"%02X",b); result+=hex; }
    return result;
}

// resolve \Device\HarddiskVolumeX\... -> C:\...
static std::wstring ResolveDevice(const std::wstring& p) {
    if (p.empty()) return p;
    if (p.size()>2 && isalpha(p[0]) && p[1]==L':') return p;
    if (p.rfind(L"\\Device\\",0)==0) {
        for (wchar_t l=L'A'; l<=L'Z'; ++l) {
            wchar_t drive[4]={l,L':',0,0};
            wchar_t target[512]={};
            if (QueryDosDeviceW(drive,target,512)) {
                std::wstring t(target);
                if (ToLower(p).rfind(ToLower(t),0)==0)
                    return std::wstring(1,l)+L":"+p.substr(t.size());
            }
        }
    }
    return p;
}

// run command, capture output
static std::string RunCmd(const std::wstring& cmd, int timeoutMs=30000) {
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    HANDLE rPipe,wPipe;
    if (!CreatePipe(&rPipe,&wPipe,&sa,0)) return {};
    SetHandleInformation(rPipe,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOW si{}; si.cb=sizeof(si);
    si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    si.hStdOutput=wPipe; si.hStdError=wPipe;
    PROCESS_INFORMATION pi{};
    std::wstring cmdBuf=cmd;
    if (!CreateProcessW(nullptr,cmdBuf.data(),nullptr,nullptr,TRUE,
                        CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)) {
        CloseHandle(rPipe); CloseHandle(wPipe); return {};
    }
    CloseHandle(wPipe);
    DWORD w = WaitForSingleObject(pi.hProcess, (DWORD)timeoutMs);
    if (w == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, (UINT)-1);
        WaitForSingleObject(pi.hProcess, 8000);
    }
    std::string out;
    char buf[4096]; DWORD rd=0;
    while (ReadFile(rPipe,buf,sizeof(buf)-1,&rd,nullptr) && rd>0) {
        buf[rd]=0; out+=buf;
    }
    CloseHandle(rPipe);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return out;
}

// JLECmd --csvf X.csv creates X_AutomaticDestinations.csv / X_CustomDestinations.csv (see JLECmd Program.cs).
static std::vector<fs::path> CollectJleOutputCsvs(const fs::path& jleOut) {
    std::vector<fs::path> out;
    std::error_code ec;
    for (const auto& ent : fs::directory_iterator(jleOut, ec)) {
        if (ec || !ent.is_regular_file()) continue;
        if (ent.path().extension() != L".csv") continue;
        const std::wstring fn = ent.path().filename().wstring();
        if (fn.find(L"AutomaticDestinations") != std::wstring::npos ||
            fn.find(L"CustomDestinations") != std::wstring::npos)
            out.push_back(ent.path());
    }
    if (!out.empty()) return out;
    ec.clear();
    for (const auto& ent : fs::directory_iterator(jleOut, ec)) {
        if (ec || !ent.is_regular_file()) continue;
        if (ent.path().extension() == L".csv") out.push_back(ent.path());
    }
    return out;
}

// registry helpers
static std::vector<std::wstring> RegEnumSubkeys(HKEY hive, const std::wstring& path) {
    std::vector<std::wstring> ks;
    HKEY hk;
    if (RegOpenKeyExW(hive,path.c_str(),0,KEY_READ,&hk)!=ERROR_SUCCESS) return ks;
    DWORD i=0; wchar_t name[512]; DWORD nlen=512;
    while (RegEnumKeyExW(hk,i++,name,&nlen,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS){
        ks.emplace_back(name); nlen=512;
    }
    RegCloseKey(hk); return ks;
}
static std::unordered_map<std::wstring,std::wstring> RegEnumValues(HKEY hive,const std::wstring& path) {
    std::unordered_map<std::wstring,std::wstring> m;
    HKEY hk;
    if (RegOpenKeyExW(hive,path.c_str(),0,KEY_READ,&hk)!=ERROR_SUCCESS) return m;
    DWORD i=0;
    wchar_t vname[1024]; DWORD vnlen=1024;
    DWORD vtype; BYTE vdata[4096]; DWORD vdlen=sizeof(vdata);
    while (RegEnumValueW(hk,i++,vname,&vnlen,nullptr,&vtype,vdata,&vdlen)==ERROR_SUCCESS) {
        std::wstring val;
        if (vtype==REG_SZ||vtype==REG_EXPAND_SZ)
            val=(wchar_t*)vdata;
        else if (vtype==REG_DWORD)
            val=std::to_wstring(*(DWORD*)vdata);
        m[vname]=val;
        vnlen=1024; vdlen=sizeof(vdata);
    }
    RegCloseKey(hk); return m;
}
static bool RegKeyExists(HKEY hive, const std::wstring& path) {
    HKEY hk;
    bool ok = RegOpenKeyExW(hive,path.c_str(),0,KEY_READ,&hk)==ERROR_SUCCESS;
    if (ok) RegCloseKey(hk);
    return ok;
}
static std::wstring RegGetStr(HKEY hive,const std::wstring& path,const std::wstring& name) {
    HKEY hk;
    if (RegOpenKeyExW(hive,path.c_str(),0,KEY_READ,&hk)!=ERROR_SUCCESS) return {};
    DWORD t,sz=0;
    RegQueryValueExW(hk,name.c_str(),nullptr,&t,nullptr,&sz);
    if (sz==0){RegCloseKey(hk);return {};}
    std::vector<BYTE> buf(sz+2,0);
    RegQueryValueExW(hk,name.c_str(),nullptr,&t,buf.data(),&sz);
    RegCloseKey(hk);
    return std::wstring((wchar_t*)buf.data());
}

// Is admin?
static bool IsAdmin() {
    BOOL isAdmin=FALSE;
    PSID admins=nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth=SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth,2,SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&admins)) {
        CheckTokenMembership(nullptr,admins,&isAdmin);
        FreeSid(admins);
    }
    return isAdmin==TRUE;
}

// ROT13
static std::wstring Rot13(const std::wstring& s) {
    std::wstring r=s;
    for (auto& c:r) {
        if (c>=L'A'&&c<=L'Z') c=(wchar_t)(L'A'+(c-L'A'+13)%26);
        else if (c>=L'a'&&c<=L'z') c=(wchar_t)(L'a'+(c-L'a'+13)%26);
    }
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CSV PARSER  (lightweight, handles quoted fields)
// ─────────────────────────────────────────────────────────────────────────────
struct CsvRow {
    std::vector<std::string> fields;
    std::unordered_map<std::string,int> *header=nullptr;
    const std::string& get(const std::string& col) const {
        static std::string empty;
        if (!header) return empty;
        auto it=header->find(col);
        if (it==header->end()) return empty;
        int idx=it->second;
        if (idx<0||(size_t)idx>=fields.size()) return empty;
        return fields[idx];
    }
};
class CsvReader {
public:
    std::unordered_map<std::string,int> header;
    bool open(const std::wstring& path) {
        f_.open(WtoA(path), std::ios::binary);
        if (!f_.is_open()) return false;
        std::string hline;
        if (!std::getline(f_,hline)) return false;
        if (!hline.empty()&&hline.back()=='\r') hline.pop_back();
        auto cols=splitLine(hline);
        for (int i=0;i<(int)cols.size();i++) header[cols[i]]=i;
        return true;
    }
    bool next(CsvRow& row) {
        std::string line;
        if (!std::getline(f_,line)) return false;
        if (!line.empty()&&line.back()=='\r') line.pop_back();
        row.fields=splitLine(line);
        row.header=&header;
        return true;
    }
private:
    std::ifstream f_;
    std::vector<std::string> splitLine(const std::string& line) {
        std::vector<std::string> fields;
        std::string field;
        bool inQ=false;
        for (size_t i=0;i<line.size();++i) {
            char c=line[i];
            if (inQ) {
                if (c=='"'&&i+1<line.size()&&line[i+1]=='"'){field+='"';++i;}
                else if (c=='"') inQ=false;
                else field+=c;
            } else {
                if (c=='"') inQ=true;
                else if (c==',') { fields.push_back(field); field.clear(); }
                else field+=c;
            }
        }
        fields.push_back(field);
        return fields;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
//  SIGNATURE CHECK
// ─────────────────────────────────────────────────────────────────────────────
static std::string GetSig(const std::wstring& path) {
    if (path.empty()) return "NoPath";
    if (!PathFileExistsW(path.c_str())) return "NotOnDisk";
    WINTRUST_FILE_INFO fi{}; fi.cbStruct=sizeof(fi); fi.pcwszFilePath=path.c_str();
    WINTRUST_DATA wd{}; wd.cbStruct=sizeof(wd);
    wd.dwUIChoice=WTD_UI_NONE; wd.fdwRevocationChecks=WTD_REVOKE_NONE;
    wd.dwUnionChoice=WTD_CHOICE_FILE; wd.pFile=&fi;
    wd.dwStateAction=WTD_STATEACTION_VERIFY;
    GUID guid=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG res=WinVerifyTrust(nullptr,&guid,&wd);
    wd.dwStateAction=WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr,&guid,&wd);
    switch (res) {
        case ERROR_SUCCESS:       return "Valid";
        case TRUST_E_NOSIGNATURE: return "Unsigned";
        default: {char buf[32];snprintf(buf,sizeof(buf),"0x%08X",res);return buf;}
    }
}
#pragma comment(lib,"wintrust.lib")
#pragma comment(lib,"crypt32.lib")
#include <wintrust.h>

// ─────────────────────────────────────────────────────────────────────────────
//  EZTOOLS DOWNLOAD
// ─────────────────────────────────────────────────────────────────────────────
static bool DownloadFile(const std::wstring& url, const std::wstring& dest) {
    URL_COMPONENTSW uc{}; uc.dwStructSize=sizeof(uc);
    wchar_t host[256]={}, path[1024]={};
    uc.lpszHostName=host; uc.dwHostNameLength=256;
    uc.lpszUrlPath=path;  uc.dwUrlPathLength=1024;
    WinHttpCrackUrl(url.c_str(),(DWORD)url.size(),0,&uc);
    HINTERNET hSess=WinHttpOpen(L"PCCheckScanner/1.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if (!hSess) return false;
    HINTERNET hConn=WinHttpConnect(hSess,host,uc.nPort,0);
    if (!hConn){WinHttpCloseHandle(hSess);return false;}
    DWORD flags = (uc.nScheme==INTERNET_SCHEME_HTTPS)?WINHTTP_FLAG_SECURE:0;
    HINTERNET hReq=WinHttpOpenRequest(hConn,L"GET",path,nullptr,
                                       WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,flags);
    if (!hReq){WinHttpCloseHandle(hConn);WinHttpCloseHandle(hSess);return false;}
    WinHttpSendRequest(hReq,WINHTTP_NO_ADDITIONAL_HEADERS,0,nullptr,0,0,0);
    WinHttpReceiveResponse(hReq,nullptr);
    HANDLE hFile=CreateFileW(dest.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,nullptr);
    if (hFile==INVALID_HANDLE_VALUE){WinHttpCloseHandle(hReq);WinHttpCloseHandle(hConn);WinHttpCloseHandle(hSess);return false;}
    char buf[65536]; DWORD rd=0,wr=0;
    while (WinHttpReadData(hReq,buf,sizeof(buf),&rd)&&rd>0)
        WriteFile(hFile,buf,rd,&wr,nullptr);
    CloseHandle(hFile);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    return true;
}

static bool ExtractZip(const std::wstring& zip, const std::wstring& dir) {
    // Use Shell to extract (no libzip needed)
    IShellDispatch* pShell=nullptr;
    CoInitialize(nullptr);
    if (FAILED(CoCreateInstance(CLSID_Shell,nullptr,CLSCTX_INPROC_SERVER,
                                IID_IShellDispatch,(void**)&pShell))) return false;
    BSTR zipBSTR=SysAllocString(zip.c_str());
    BSTR dirBSTR=SysAllocString(dir.c_str());
    VARIANT vZip{}; vZip.vt=VT_BSTR; vZip.bstrVal=zipBSTR;
    VARIANT vDir{}; vDir.vt=VT_BSTR; vDir.bstrVal=dirBSTR;
    Folder *pDst=nullptr, *pSrc=nullptr;
    pShell->NameSpace(vDir,&pDst);
    pShell->NameSpace(vZip,&pSrc);
    bool ok=false;
    if (pDst&&pSrc) {
        FolderItems* pItems=nullptr;
        pSrc->Items(&pItems);
        if (pItems) {
            VARIANT vItems{}; vItems.vt=VT_DISPATCH; vItems.pdispVal=pItems;
            VARIANT vOpt{}; vOpt.vt=VT_I4; vOpt.lVal=4|16|512|1024;
            pDst->CopyHere(vItems,vOpt);
            Sleep(2000); // give shell time to finish
            pItems->Release(); ok=true;
        }
        if (pSrc) pSrc->Release();
        if (pDst) pDst->Release();
    }
    SysFreeString(zipBSTR); SysFreeString(dirBSTR);
    pShell->Release();
    return ok;
}
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")
#include <exdisp.h>
#include <shldisp.h>

// ─────────────────────────────────────────────────────────────────────────────
//  SCANNER  --  all phases
// ─────────────────────────────────────────────────────────────────────────────
class Scanner {
public:
    fs::path ezDir;
    ScanState& S;
    int okCount=0;

    Scanner(ScanState& s) : S(s) {
        wchar_t prof[MAX_PATH]={};
        SHGetFolderPathW(nullptr,CSIDL_PROFILE,nullptr,0,prof);
        ezDir = fs::path(prof) / L"Downloads" / L"EZTools";
    }

    void run() {
        S.running=true;
        S.startTime=std::chrono::steady_clock::now();
        okCount=0;

        Phase01(); if(S.stopReq) goto done;
        Phase02(); if(S.stopReq) goto done;
        Phase03(); if(S.stopReq) goto done;
        Phase04(); if(S.stopReq) goto done;
        Phase05(); if(S.stopReq) goto done;
        Phase06(); if(S.stopReq) goto done;
        Phase07(); if(S.stopReq) goto done;
        Phase08(); if(S.stopReq) goto done;
        Phase09(); if(S.stopReq) goto done;
        Phase10(); if(S.stopReq) goto done;
        Phase11(); if(S.stopReq) goto done;
        Phase12(); if(S.stopReq) goto done;
        Phase13(); if(S.stopReq) goto done;
        Phase14();

    done:
        S.setPhaseLbl("Done -- " + std::to_string(S.crits.size()) +
                      " confirmed | " + std::to_string(S.warns.size()) + " suspected");
        S.setStatus("Complete in " + S.elapsed());
        S.running=false;
    }

private:
    void ok (const std::string& l,const std::string& v,const std::string& ph="") { S.pushLog(Badge::OK,  l,v,ph); okCount++; }
    void crit(const std::string& l,const std::string& v,const std::string& ph)   { S.pushLog(Badge::CRIT,l,v,ph); }
    void warn(const std::string& l,const std::string& v,const std::string& ph)   { S.pushLog(Badge::WARN,l,v,ph); }
    void susp(const std::string& l,const std::string& v,const std::string& ph)   { S.pushLog(Badge::SUSP,l,v,ph); }
    void info(const std::string& l,const std::string& v)                          { S.pushLog(Badge::INFO,l,v); }
    void skip(const std::string& l,const std::string& v)                          { S.pushLog(Badge::SKIP,l,v); }
    void sec (const std::string& n,const std::string& t)                          { S.pushSec(n,t); }
    void sub (const std::string& t)                                                { S.pushSub(t); }

    // ── PHASE 01 ─────────────────────────────────────────────────────────────
    void Phase01() {
        S.setPhase("01",1); S.setPhaseLbl("01: Bootstrap"); sec("01","Environment & Bootstrap");
        if (IsAdmin()) { ok("Administrator","Elevated privileges"); }
        else           { crit("ACCESS DENIED","Not running as Administrator","01"); }

        fs::create_directories(ezDir);
        sub("EZTools Download");
        struct Tool { std::wstring name, url; };
        std::vector<Tool> tools = {
            {L"AmcacheParser",L"https://download.ericzimmermanstools.com/net9/AmcacheParser.zip"},
            {L"PECmd",        L"https://download.ericzimmermanstools.com/net9/PECmd.zip"},
            {L"MFTECmd",      L"https://download.ericzimmermanstools.com/net9/MFTECmd.zip"},
            {L"LECmd",        L"https://download.ericzimmermanstools.com/net9/LECmd.zip"},
            {L"JLECmd",       L"https://download.ericzimmermanstools.com/net9/JLECmd.zip"},
        };
        for (auto& t : tools) {
            fs::path exe = ezDir / (t.name + L".exe");
            if (fs::exists(exe)) { ok(WtoA(t.name),"Present"); continue; }
            info(WtoA(t.name),"Downloading...");
            S.setStatus("Downloading " + WtoA(t.name) + "...");
            fs::path zip = ezDir / (t.name + L".zip");
            if (DownloadFile(t.url, zip.wstring())) {
                ExtractZip(zip.wstring(), ezDir.wstring());
                fs::remove(zip);
                if (fs::exists(exe)) { ok(WtoA(t.name),"Downloaded & extracted"); }
                else { crit(WtoA(t.name),"Extract may need manual check","01"); }
            } else { warn(WtoA(t.name),"Download failed","01"); }
        }
        S.setPhase("01",2);
    }

    // ── PHASE 02 ─────────────────────────────────────────────────────────────
    void Phase02() {
        S.setPhase("02",1); S.setPhaseLbl("02: Defender"); sec("02","Windows Defender");

        sub("Real-Time Protection");
        std::string out = RunCmd(L"powershell -NoProfile -Command \"Get-MpComputerStatus|"
            L"Select RealTimeProtectionEnabled,AntivirusEnabled,AMProductVersion|ConvertTo-Json\"",15000);
        // parse JSON manually (no external lib)
        auto grab=[&](const std::string& key)->std::string {
            auto p=out.find("\""+key+"\""); if(p==std::string::npos) return {};
            auto c=out.find(":",p); if(c==std::string::npos) return {};
            auto s=out.find_first_not_of(" \t\r\n",c+1); if(s==std::string::npos) return {};
            auto e=out.find_first_of(",}\r\n",s);
            std::string v=out.substr(s,e-s);
            if(!v.empty()&&v.front()=='"') v=v.substr(1,v.size()-2);
            return v;
        };
        bool rtp=(grab("RealTimeProtectionEnabled")=="true");
        bool av =(grab("AntivirusEnabled")=="true");
        if (rtp) ok("Real-Time Protection","Enabled"); else crit("Real-Time Protection","DISABLED","02");
        if (av)  ok("Antivirus Engine","Enabled");     else crit("Antivirus Engine","DISABLED","02");
        info("Defender Version", grab("AMProductVersion"));

        sub("Exclusions");
        out=RunCmd(L"powershell -NoProfile -Command \"Get-MpPreference|"
                   L"Select ExclusionPath,ExclusionProcess|ConvertTo-Json\"",15000);
        // rough extraction
        for (auto& field : std::vector<std::string>{"ExclusionPath","ExclusionProcess"}) {
            auto p=out.find("\""+field+"\""); if(p==std::string::npos) continue;
            auto a=out.find('[',p); auto b=out.find(']',p);
            if(a==std::string::npos||b==std::string::npos){ok(field+" list","None");continue;}
            std::string arr=out.substr(a+1,b-a-1);
            if(arr.find_first_not_of(" \t\r\n\"")==std::string::npos){ok(field+" list","None");continue;}
            // extract quoted strings
            size_t pos=0;
            bool anyFound=false;
            while((pos=arr.find('"',pos))!=std::string::npos) {
                auto end=arr.find('"',pos+1);
                if(end==std::string::npos) break;
                std::string item=arr.substr(pos+1,end-pos-1);
                if(!item.empty()) {
                    anyFound=true;
                    std::wstring wi=AtoW(item);
                    if(TestBL(wi)&&!TestWL(wi)) crit(field+" BLACKLIST",item,"02");
                    else susp(field,item,"02");
                }
                pos=end+1;
            }
            if(!anyFound) ok(field+" list","None");
        }

        sub("Threat History -- 1116/1117/1008");
        int hits=0;
        for (auto& [eid,lbl] : std::vector<std::pair<int,std::string>>{{1116,"Detected"},{1117,"Action"},{1008,"ALLOWED"}}) {
            std::wstring cmd=L"powershell -NoProfile -Command \"Get-WinEvent -FilterHashtable "
                L"@{LogName='Microsoft-Windows-Windows Defender/Operational';Id="+
                std::to_wstring(eid)+L"} -MaxEvents 20 -EA SilentlyContinue|"
                L"Select TimeCreated,Message|ConvertTo-Json\"";
            std::string o=RunCmd(cmd,20000);
            if(o.find("TimeCreated")!=std::string::npos){
                hits++;
                if(eid==1008) crit("Defender "+lbl,o.substr(0,200),"02");
                else susp("Defender "+lbl,o.substr(0,200),"02");
            }
        }
        if(!hits) ok("Threat History","No events");
        S.setPhase("02",2);
    }

    // ── PHASE 03 ─────────────────────────────────────────────────────────────
    void Phase03() {
        S.setPhase("03",1); S.setPhaseLbl("03: Services"); sec("03","Service Status");
        std::vector<std::pair<std::string,std::string>> svcs={
            {"EventLog","Event Logging"},{"Sysmain","Superfetch"},
            {"Diagtrack","Telemetry"},{"DPS","Diagnostic Policy"},{"PcaSvc","Compat Assistant"}
        };
        for (auto& [name,desc]:svcs) {
            SC_HANDLE scm=OpenSCManager(nullptr,nullptr,SC_MANAGER_CONNECT);
            SC_HANDLE svc=OpenServiceA(scm,name.c_str(),SERVICE_QUERY_STATUS);
            bool running=false;
            if(svc){
                SERVICE_STATUS ss{}; QueryServiceStatus(svc,&ss);
                running=(ss.dwCurrentState==SERVICE_RUNNING);
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
            if(running) ok(name,"Running | "+desc);
            else crit(name,"NOT RUNNING | "+desc,"03");
        }
        S.setPhase("03",2);
    }

    // ── PHASE 04 ─────────────────────────────────────────────────────────────
    void Phase04() {
        S.setPhase("04",1); S.setPhaseLbl("04: Disk"); sec("04","Disk Forensics");
        sub("USN Journal");
        std::string o=RunCmd(L"fsutil usn queryjournal C:",10000);
        std::string ol=ToLowerA(o);

        std::string usnLastUtc="unknown";
        try {
            fs::path usnFile = L"C:\\$Extend\\$UsnJrnl:$J";
            std::error_code ec;
            if (fs::exists(usnFile, ec) && !ec) {
                usnLastUtc = FileTimeToUtcIso8601(fs::last_write_time(usnFile, ec));
            }
        } catch(...) {}

        const bool cleared =
            (ol.find("invalid")!=std::string::npos ||
             ol.find("no journal")!=std::string::npos ||
             ol.find("error")!=std::string::npos);
        if(cleared)
            crit("USN Journal cleared/disabled",
                 "Likely cleared/disabled. $UsnJrnl:$J last write UTC: " + usnLastUtc,
                 "04");
        else
            ok("USN Journal active",
               "Active on C:. $UsnJrnl:$J last write UTC: " + usnLastUtc,
               "04");
        S.setPhase("04",2);
    }

    // ── PHASE 05 ─────────────────────────────────────────────────────────────
    void Phase05() {
        S.setPhase("05",1); S.setPhaseLbl("05: VM Check"); sec("05","VM / Hyper-V Detection");
        int score=0; std::vector<std::string> hints;

        sub("Manufacturer / Model / BIOS");
        std::string o=RunCmd(L"powershell -NoProfile -Command \""
            L"Get-CimInstance Win32_ComputerSystem|Select Model,Manufacturer|ConvertTo-Json\"",10000);
        std::string ob=RunCmd(L"powershell -NoProfile -Command \""
            L"Get-CimInstance Win32_BIOS|Select Version|ConvertTo-Json\"",10000);
        std::string combined=ToLowerA(o+ob);
        for(auto& kw:std::vector<std::string>{"virtual","vmware","hyper-v","vbox","virtualbox","kvm","qemu","xen","parallels","innotek"}){
            if(combined.find(kw)!=std::string::npos){score++;hints.push_back("MfrModelBIOS:"+kw);break;}
        }
        info("System","(see Full Log for model details)");

        sub("VM Registry Keys");
        std::vector<std::wstring> vmKeys={
            L"SOFTWARE\\VMware, Inc.\\VMware Tools",
            L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
            L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
            L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
            L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
            L"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk"
        };
        bool regHit=false;
        for(auto& k:vmKeys){
            if(RegKeyExists(HKEY_LOCAL_MACHINE,k)){
                score++; regHit=true; hints.push_back("RegKey:"+WtoA(k));
                crit("VM Registry Key",WtoA(k),"05");
            }
        }
        if(!regHit) ok("VM Registry Keys","None found");

        sub("VM Drivers / Services");
        std::vector<std::string> vmDrvs={"vmbus","vmhgfs","vmmouse","vmrawdsk","vmusbmouse","vboxguest","vboxsf","vboxvideo","vioscsi","balloon","netkvm"};
        bool drvHit=false;
        for(auto& d:vmDrvs){
            SC_HANDLE scm=OpenSCManager(nullptr,nullptr,SC_MANAGER_CONNECT);
            SC_HANDLE svc=OpenServiceA(scm,d.c_str(),SERVICE_QUERY_STATUS);
            if(svc){score++;drvHit=true;hints.push_back("Driver:"+d);
                    crit("VM Driver Found",d,"05");CloseServiceHandle(svc);}
            CloseServiceHandle(scm);
        }
        if(!drvHit) ok("VM Drivers","None found");

        sub("VM Processes");
        std::vector<std::string> vmProcs={"vmtoolsd","vmwaretray","vmwareuser","vboxservice","vboxtray","xenservice","qemu-ga","prl_tools"};
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
        bool procHit=false;
        if(Process32FirstW(snap,&pe)){
            do {
                std::string nm=WtoA(pe.szExeFile); std::string nml=ToLowerA(nm);
                for(auto& vp:vmProcs){
                    if(nml==vp||nml==vp+".exe"){
                        score++;procHit=true;hints.push_back("Process:"+nm);
                        crit("VM Process Running","PID:"+std::to_string(pe.th32ProcessID)+" | "+nm,"05");
                    }
                }
            } while(Process32NextW(snap,&pe));
        }
        CloseHandle(snap);
        if(!procHit) ok("VM Processes","None found");

        sub("Hyper-V Feature");
        std::string hvOut=RunCmd(L"powershell -NoProfile -Command \""
            L"(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -EA SilentlyContinue).State\"",15000);
        if(hvOut.find("Enabled")!=std::string::npos){
            score++;hints.push_back("HyperV-Feature");
            warn("Hyper-V Feature","Enabled -- machine may be a hypervisor host","05");
        } else ok("Hyper-V Feature","Disabled");

        sub("Verdict");
        if(score>0){
            std::string h; for(auto& s:hints) h+=s+" / ";
            crit("VM ENVIRONMENT DETECTED",std::to_string(score)+" indicator(s): "+h,"05");
        } else ok("VM Verdict","No virtualisation indicators -- bare metal");
        S.setPhase("05",score>0?3:2);
    }

    // ── PHASE 06 ─────────────────────────────────────────────────────────────
    void Phase06() {
        S.setPhase("06",1); S.setPhaseLbl("06: Amcache"); sec("06","Amcache -- Execution Hash Records");
        fs::path amExe=ezDir/L"AmcacheParser.exe";
        fs::path amHve=L"C:\\Windows\\appcompat\\Programs\\Amcache.hve";
        if(!fs::exists(amExe)||!fs::exists(amHve)){skip("AmcacheParser","Not available");S.setPhase("06",4);return;}
        S.setStatus("Running AmcacheParser...");
        RunCmd(L"\""+amExe.wstring()+L"\" -f \""+amHve.wstring()+L"\" --csv \""+ezDir.wstring()+L"\"", PCC_AMCACHE_MS);

        std::string amHveLastUtc="unknown";
        uint64_t amHveSize=0;
        try {
            std::error_code ec;
            if (fs::exists(amHve, ec) && !ec) {
                amHveLastUtc = FileTimeToUtcIso8601(fs::last_write_time(amHve, ec));
                amHveSize = fs::file_size(amHve, ec);
            }
        } catch(...) {}

        // find UnassociatedFileEntries CSV
        fs::path csvPath;
        for(auto& f:fs::directory_iterator(ezDir)){
            if(f.path().extension()==L".csv"&&f.path().filename().wstring().find(L"UnassociatedFileEntries")!=std::wstring::npos){
                if(csvPath.empty()||fs::last_write_time(f)>fs::last_write_time(csvPath)) csvPath=f.path();
            }
        }
        if(csvPath.empty()){warn("Amcache","No CSV produced","06");S.setPhase("06",2);return;}

        CsvReader csv; int hits=0;
        if(csv.open(csvPath.wstring())) {
            CsvRow row;
            size_t amcacheRows = 0;
            while(csv.next(row)) {
                amcacheRows++;
                std::string sha256=row.get("SHA256"); for(auto&c:sha256) c=toupper(c);
                std::string sha1  =row.get("SHA1");   for(auto&c:sha1  ) c=toupper(c);
                std::string fpath =row.get("FullPath");
                std::wstring wp=AtoW(fpath);
                // hash match
                bool matched=false;
                for(auto& e:CHEAT_DB){
                    if((!sha256.empty()&&WtoA(e.sha256)==sha256)||
                       (!sha1.empty()&&WtoA(e.sha1)==sha1.substr(sha1.size()>4?4:0))){
                        hits++;matched=true;
                        bool on=fs::exists(wp);
                        crit("AMCACHE HASH MATCH",WtoA(e.name)+" | "+fpath+" | "+(on?"ON DISK":"DELETED"),"06");
                        break;
                    }
                }
                // BL match on path
                if(!matched&&TestBL(wp)&&!TestWL(wp)){
                    hits++;
                    bool on=fs::exists(wp);
                    crit("AMCACHE BLACKLIST",fpath+" | "+(on?"ON DISK":"DELETED"),"06");
                }
            }
            // Heuristic: if the hive was modified recently but contains very few rows,
            // it often indicates Amcache reset / rebuild (not proof, but useful context).
            try {
                const auto nowSys = std::chrono::system_clock::now();
                if(amHveLastUtc != "unknown" && amcacheRows < 200) {
                    std::error_code ec;
                    auto ft = fs::last_write_time(amHve, ec);
                    if(!ec) {
                        auto age = nowSys - FileTimeToSystemClock(ft);
                        if(age >= std::chrono::hours(0) && age <= std::chrono::hours(48)) {
                            susp("Amcache likely cleared/reset (heuristic)",
                                 "Amcache.hve last write UTC: " + amHveLastUtc +
                                 " | Rows scanned: " + std::to_string(amcacheRows) +
                                 " | Hive size bytes: " + std::to_string(amHveSize),
                                 "06");
                        }
                    }
                }
            } catch(...) {}
        }
        // Always record the hive timestamp for timeline correlation.
        if(amHveLastUtc != "unknown") {
            ok("Amcache.hve timestamp",
               "Amcache.hve last write UTC: " + amHveLastUtc + " | Hive size bytes: " + std::to_string(amHveSize),
               "06");
        }
        if(!hits) ok("Amcache","No matches");
        S.setPhase("06",hits?3:2);
    }

    // ── PHASE 07 ─────────────────────────────────────────────────────────────
    void Phase07() {
        S.setPhase("07",1); S.setPhaseLbl("07: Registry Exec Logs");
        sec("07","Registry Execution Logs");

        // helper lambda: scan a registry key's values against BL
        auto scanRegPaths=[&](const std::wstring& path,const std::string& ctx,const std::string& ph){
            auto vals=RegEnumValues(HKEY_CURRENT_USER,path);
            if(vals.empty()){skip(ctx,"No entries");return;}
            bool anyHit=false;
            for(auto& [name,_]:vals){
                std::wstring rp=ResolveDevice(name);
                // strip after .FriendlyAppName
                auto fa=rp.find(L".FriendlyAppName");
                if(fa!=std::wstring::npos) rp=rp.substr(0,fa);
                if(TestWL(rp)) continue;
                if(TestBL(rp)){
                    anyHit=true;
                    bool on=fs::exists(rp);
                    crit(ctx+" BL HIT",WtoA(rp)+" | "+(on?"ON DISK":"DELETED"),ph);
                }
            }
            if(!anyHit) ok(ctx,"No BL entries");
        };

        sub("AppCompatFlags Store");
        scanRegPaths(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store","ACF-Store","07");

        sub("AppCompatFlags Layers");
        scanRegPaths(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers","ACF-Layers","07");

        sub("MuiCache");
        {
            auto vals=RegEnumValues(HKEY_CURRENT_USER,
                L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
            int hits=0;
            for(auto& [name,_]:vals){
                std::wstring rp=ResolveDevice(name);
                auto fa=rp.find(L".FriendlyAppName"); if(fa!=std::wstring::npos) rp=rp.substr(0,fa);
                if(rp.find(L'\\')==std::wstring::npos) continue;
                if(TestWL(rp)) continue;
                if(TestBL(rp)){hits++;crit("MuiCache BL",WtoA(rp),"07");}
            }
            if(!hits) ok("MuiCache","No BL entries");
        }

        sub("BAM -- Background Activity Moderator");
        {
            std::wstring bamBase=L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
            auto sids=RegEnumSubkeys(HKEY_LOCAL_MACHINE,bamBase);
            for(auto& sid:sids){
                if(sid.find(L"1001")==std::wstring::npos) continue;
                auto vals=RegEnumValues(HKEY_LOCAL_MACHINE,bamBase+L"\\"+sid);
                for(auto& [name,_]:vals){
                    if(name.find(L'\\')==std::wstring::npos) continue;
                    std::wstring rp=ResolveDevice(name);
                    if(TestWL(rp)) continue;
                    if(TestBL(rp)){
                        bool on=fs::exists(rp);
                        crit("BAM BL",WtoA(rp)+" | "+(on?"ON DISK":"DELETED"),"07");
                    }
                    // also check against cheat DB
                    std::wstring rpl=ToLower(rp);
                    for(auto& e:CHEAT_DB){
                        std::wstring key=ToLower(e.name.substr(0,e.name.find(L' ')));
                        if(rpl.find(key)!=std::wstring::npos&&!TestWL(rp)){
                            bool on=fs::exists(rp);
                            crit("BAM MATCH",WtoA(e.name)+" | "+WtoA(rp)+" | "+(on?"ON DISK":"DELETED"),"07");
                        }
                    }
                }
            }
        }

        sub("ShellBags -- Folder Access History");
        {
            std::vector<std::wstring> sbRoots={
                L"Software\\Microsoft\\Windows\\Shell\\BagMRU",
                L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
            };
            int cnt=0,hits=0;
            for(auto& root:sbRoots){
                // enumerate first level only (recursive would be very slow)
                auto subs=RegEnumSubkeys(HKEY_CURRENT_USER,root);
                for(auto& s:subs){cnt++;
                    std::wstring full=root+L"\\"+s;
                    if(TestBL(full)){hits++;crit("ShellBag BL",WtoA(full),"07");}
                }
            }
            info("ShellBag Entries",std::to_string(cnt)+" scanned | "+std::to_string(hits)+" hits");
        }

        sub("RunMRU -- Win+R History");
        {
            auto vals=RegEnumValues(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
            if(vals.empty()) skip("RunMRU","No entries");
            else {
                int hits=0;
                for(auto& [name,val]:vals){
                    if(name==L"MRUList") continue;
                    std::wstring cmd=val; auto p=cmd.rfind(L"\\1");
                    if(p!=std::wstring::npos) cmd=cmd.substr(0,p);
                    if(TestBL(cmd)){hits++;crit("RunMRU BL",WtoA(cmd),"07");}
                    else info("RunMRU Entry",WtoA(cmd));
                }
                if(!hits) ok("RunMRU","No BL entries");
            }
        }
        S.setPhase("07",2);
    }

    // ── PHASE 08 ─────────────────────────────────────────────────────────────
    void Phase08() {
        S.setPhase("08",1); S.setPhaseLbl("08: Prefetch + PECmd"); sec("08","Prefetch Analysis");
        fs::path pfDir=L"C:\\Windows\\Prefetch";
        if(!fs::exists(pfDir)){skip("Prefetch","Directory not found");S.setPhase("08",4);return;}

        sub("Prefetch .pf Files");
        int flagged=0;
        for(auto& f:fs::directory_iterator(pfDir)){
            if(f.path().extension()!=L".pf") continue;
            std::wstring stem=f.path().stem().wstring();
            // strip -XXXXXXXX hash suffix
            auto dash=stem.rfind(L'-');
            if(dash!=std::wstring::npos) stem=stem.substr(0,dash);
            std::wstring exeName=stem+L".exe";
            std::wstring nameL=ToLower(exeName);
            bool bl=TestBL(nameL);
            std::string lastRun;
            auto lwt=fs::last_write_time(f);
            auto sctp=std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                lwt-fs::file_time_type::clock::now()+std::chrono::system_clock::now());
            std::time_t t=std::chrono::system_clock::to_time_t(sctp);
            char tbuf[32]; strftime(tbuf,sizeof(tbuf),"%Y-%m-%d %H:%M:%S",localtime(&t));
            lastRun=tbuf;

            if(!bl) continue;
            flagged++;
            crit("PREFETCH MATCH",WtoA(f.path().filename().wstring())+" | Last run: "+lastRun,"08");
        }
        if(!flagged) ok("Prefetch",".pf scan -- no BL matches");

        sub("PECmd -- Full Prefetch Parse");
        fs::path peExe=ezDir/L"PECmd.exe";
        if(!fs::exists(peExe)){skip("PECmd","Not available");S.setPhase("08",flagged?3:2);return;}

        fs::path pfOut=ezDir/L"PECmd_out"; fs::create_directories(pfOut);
        S.setStatus("Running PECmd...");
        RunCmd(L"\""+peExe.wstring()+L"\" -d \""+pfDir.wstring()+
               L"\" --csv \""+pfOut.wstring()+L"\" --csvf PECmd.csv", PCC_PECMD_MS);

        fs::path peCsv=pfOut/L"PECmd.csv";
        if(!fs::exists(peCsv)){warn("PECmd","No CSV output","08");S.setPhase("08",flagged?3:2);return;}

        static const std::unordered_set<std::string> SYS_EXES={
            "powershell.exe","explorer.exe","taskmgr.exe","cmd.exe","conhost.exe",
            "svchost.exe","dllhost.exe","wermgr.exe","msiexec.exe","consent.exe",
            "jlecmd.exe","wxtcmd.exe","mftecmd.exe","pecmd.exe","amcacheparser.exe","lecmd.exe"
        };
        CsvReader peCsv_r; int peHits=0;
        if(peCsv_r.open(peCsv.wstring())){
            CsvRow row;
            while(peCsv_r.next(row)){
                std::string exeN=row.get("ExecutableName");
                std::string exeP=row.get("SourceFilePath");
                std::string lr  =row.get("SourceLastRunDate");
                std::string exeNL=ToLowerA(exeN);
                if(SYS_EXES.count(exeNL)) continue;
                if(TestWL(AtoW(exeP))) continue;
                if(TestBL(AtoW(exeNL))){
                    peHits++;
                    crit("PECMD CHEAT FOUND","EXE:"+exeN+" | Path:"+exeP+" | LastRun:"+lr,"08");
                }
            }
        }
        if(!peHits) ok("PECmd","No BL executables found in prefetch");
        S.setPhase("08",(flagged+peHits)?3:2);
    }

    // ── PHASE 09 ─────────────────────────────────────────────────────────────
    void Phase09() {
        S.setPhase("09",1); S.setPhaseLbl("09: Processes / USB / PS History");
        sec("09","Process Scan, USB History and PowerShell History");

        sub("Running Processes -- Blacklist");
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
        int procHits=0;
        if(Process32FirstW(snap,&pe)){
            do {
                std::wstring nm=pe.szExeFile;
                if(!TestBL(nm)) continue;
                // get path
                HANDLE ph=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID);
                std::wstring path;
                if(ph){wchar_t buf[2048]={};DWORD sz=2048;QueryFullProcessImageNameW(ph,0,buf,&sz);path=buf;CloseHandle(ph);}
                if(TestWL(path)) continue;
                procHits++;
                std::string sig=GetSig(path);
                crit("PROCESS BLACKLISTED","PID:"+std::to_string(pe.th32ProcessID)+" | "+WtoA(nm)+" | "+WtoA(path)+" | Sig:"+sig,"09");
            } while(Process32NextW(snap,&pe));
        }
        CloseHandle(snap);
        if(!procHits) ok("Running Processes","No BL processes");

        sub("Loaded Modules -- Injected DLLs");
        snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        PROCESSENTRY32W pe2{}; pe2.dwSize=sizeof(pe2);
        int modHits=0; int procCount=0;
        if(Process32FirstW(snap,&pe2)){
            do {
                if(++procCount>48) break;
                HANDLE modSnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pe2.th32ProcessID);
                if(modSnap==INVALID_HANDLE_VALUE) continue;
                MODULEENTRY32W me{}; me.dwSize=sizeof(me);
                if(Module32FirstW(modSnap,&me)){
                    do {
                        std::wstring modPath=me.szExePath;
                        std::wstring modName=fs::path(modPath).stem().wstring();
                        std::wstring modPathL=ToLower(modPath);
                        if(modPathL.find(L"c:\\windows\\")==std::wstring::npos&&
                           TestBL(modName)&&!TestWL(modPath)){
                            modHits++;
                            std::string sig=GetSig(modPath);
                            crit("MODULE BLACKLISTED","PID:"+std::to_string(pe2.th32ProcessID)+" ("+WtoA(pe2.szExeFile)+") | "+WtoA(modPath)+" | Sig:"+sig,"09");
                        }
                    } while(Module32NextW(modSnap,&me));
                }
                CloseHandle(modSnap);
            } while(Process32NextW(snap,&pe2));
        }
        CloseHandle(snap);
        if(!modHits) ok("Loaded Modules","No BL DLLs found");

        sub("USB History -- USBSTOR");
        std::vector<std::wstring> usbBases={
            L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
            L"SYSTEM\\ControlSet001\\Enum\\USBSTOR",
            L"SYSTEM\\ControlSet002\\Enum\\USBSTOR"
        };
        std::unordered_set<std::wstring> usbSeen; int usbCount=0;
        for(auto& base:usbBases){
            auto devTypes=RegEnumSubkeys(HKEY_LOCAL_MACHINE,base);
            for(auto& devType:devTypes){
                auto insts=RegEnumSubkeys(HKEY_LOCAL_MACHINE,base+L"\\"+devType);
                for(auto& inst:insts){
                    std::wstring serial=inst;
                    auto amp=serial.rfind(L'&');
                    if(amp!=std::wstring::npos) serial=serial.substr(0,amp);
                    if(usbSeen.count(serial)) continue;
                    usbSeen.insert(serial);usbCount++;
                    std::wstring friendly=RegGetStr(HKEY_LOCAL_MACHINE,
                        base+L"\\"+devType+L"\\"+inst,L"FriendlyName");
                    if(friendly.empty()){
                        friendly=devType;
                        // clean up: remove Disk& prefix etc
                        auto p=friendly.find(L"Disk&"); if(p!=std::wstring::npos) friendly=friendly.substr(5);
                        auto r=friendly.find(L"&Rev_"); if(r!=std::wstring::npos) friendly=friendly.substr(0,r);
                    }
                    info("USB: "+WtoA(friendly),"Serial: "+WtoA(serial));
                }
            }
        }
        if(!usbCount) info("USB History","No USBSTOR devices found");
        else info("USB Devices Total",std::to_string(usbCount)+" unique device(s)");

        sub("PowerShell History -- All Profiles");
        std::string suspPat="iex |iwr |DownloadString|Invoke-Expression|Invoke-WebRequest|WebClient|bypass|hidden|encodedcommand|-enc ";
        for(auto& up:fs::directory_iterator(L"C:\\Users")){
            if(!up.is_directory()) continue;
            fs::path hist=up.path()/L"AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
            if(!fs::exists(hist)) continue;
            std::ifstream f(hist); std::string line; int lineCount=0,hits=0;
            while(std::getline(f,line)){
                lineCount++;
                std::string ll=ToLowerA(line);
                bool bl=TestBL(AtoW(line))&&!TestWL(AtoW(line));
                bool suspicious=false;
                for(auto& tok:std::vector<std::string>{"iex ","iwr ","downloadstring","invoke-expression",
                    "invoke-webrequest","webclient","bypass","hidden","encodedcommand","-enc "}){
                    if(ll.find(tok)!=std::string::npos){suspicious=true;break;}
                }
                if(bl){hits++;crit("PS HISTORY BL","("+WtoA(up.path().filename().wstring())+") "+line.substr(0,200),"09");}
                else if(suspicious){hits++;susp("PS HISTORY SUSP","("+WtoA(up.path().filename().wstring())+") "+line.substr(0,200),"09");}
            }
            if(!hits) ok("PS History ("+WtoA(up.path().filename().wstring())+")",std::to_string(lineCount)+" commands -- clean");
        }

        sub("Script Block Logging -- Event ID 4104");
        std::string sbPol=RunCmd(L"powershell -NoProfile -Command \""
            L"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging\"",10000);
        if(sbPol.find("1")!=std::string::npos){
            std::string evt4104=RunCmd(L"powershell -NoProfile -Command \"Get-WinEvent "
                L"-FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} "
                L"-MaxEvents 40 -EA SilentlyContinue|Select-Object Message|ConvertTo-Json\"",12000);
            if(!evt4104.empty()&&evt4104.find("Message")!=std::string::npos){
                // check for BL patterns
                if(TestBL(AtoW(evt4104)))
                    crit("4104 SCRIPT BLOCK","Suspicious content in PS script block log","09");
                else ok("Script Block Logging (4104)","Events checked -- clean");
            } else ok("Script Block Logging","Enabled but log empty");
        } else info("Script Block Logging","Not enabled (normal for home PCs)");

        S.setPhase("09",2);
    }

    // ── PHASE 10 ─────────────────────────────────────────────────────────────
    void Phase10() {
        S.setPhase("10",1); S.setPhaseLbl("10: UserAssist"); sec("10","UserAssist -- GUI Execution History");
        std::wstring base=L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
        auto keys=RegEnumSubkeys(HKEY_CURRENT_USER,base);
        int hits=0;
        for(auto& k:keys){
            auto vals=RegEnumValues(HKEY_CURRENT_USER,base+L"\\"+k+L"\\Count");
            for(auto& [nameEnc,_]:vals){
                std::wstring decoded=Rot13(nameEnc);
                std::wstring dl=ToLower(decoded);
                if(dl.find(L".exe")==std::wstring::npos&&dl.find(L".lnk")==std::wstring::npos) continue;
                if(TestWL(decoded)) continue;
                if(TestBL(decoded)){
                    hits++;
                    // read run count from binary value
                    HKEY hk; DWORD rc=0;
                    if(RegOpenKeyExW(HKEY_CURRENT_USER,(base+L"\\"+k+L"\\Count").c_str(),0,KEY_READ,&hk)==ERROR_SUCCESS){
                        DWORD t,sz=1024; std::vector<BYTE> buf(sz);
                        if(RegQueryValueExW(hk,nameEnc.c_str(),nullptr,&t,buf.data(),&sz)==ERROR_SUCCESS&&sz>=8)
                            rc=*(DWORD*)(buf.data()+4);
                        RegCloseKey(hk);
                    }
                    crit("USERASSIST BL",WtoA(decoded)+" | RunCount:"+std::to_string(rc),"10");
                }
            }
        }
        if(!hits) ok("UserAssist","No BL entries");
        S.setPhase("10",hits?3:2);
    }

    // ── PHASE 11 ─────────────────────────────────────────────────────────────
    void Phase11() {
        S.setPhase("11",1); S.setPhaseLbl("11: Programs"); sec("11","Installed Programs");
        struct HivePath{HKEY h;std::wstring p;};
        std::vector<HivePath> paths={
            {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
            {HKEY_LOCAL_MACHINE,L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
            {HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
        };
        std::unordered_set<std::wstring> seen; int hits=0,total=0;
        for(auto& hp:paths){
            auto ks=RegEnumSubkeys(hp.h,hp.p);
            for(auto& k:ks){
                std::wstring dn=RegGetStr(hp.h,hp.p+L"\\"+k,L"DisplayName");
                if(dn.empty()||seen.count(dn)) continue;
                seen.insert(dn); total++;
                std::wstring pub=RegGetStr(hp.h,hp.p+L"\\"+k,L"Publisher");
                std::wstring loc=RegGetStr(hp.h,hp.p+L"\\"+k,L"InstallLocation");
                std::wstring combo=dn+L" "+pub+L" "+loc;
                if(TestBL(combo)&&!TestWL(combo)){
                    hits++;
                    std::wstring ver=RegGetStr(hp.h,hp.p+L"\\"+k,L"DisplayVersion");
                    std::wstring date=RegGetStr(hp.h,hp.p+L"\\"+k,L"InstallDate");
                    std::string line=WtoA(dn);
                    if(!ver.empty()) line+=" | v"+WtoA(ver);
                    if(!date.empty()) line+=" | Installed:"+WtoA(date);
                    crit("INSTALLED BL",line,"11");
                }
            }
        }
        if(!hits) ok("Programs","No BL matches in "+std::to_string(total)+" entries");
        S.setPhase("11",hits?3:2);
    }

    // ── PHASE 12 ─────────────────────────────────────────────────────────────
    void Phase12() {
        S.setPhase("12",1); S.setPhaseLbl("12: Drivers"); sec("12","Kernel Driver Audit");

        sub("fltMC Minifilters");
        std::string flt=RunCmd(L"fltMC",10000); int fltHits=0;
        std::istringstream fss(flt); std::string line;
        while(std::getline(fss,line)){
            if(line.find("Filter Name")!=std::string::npos||line.find("---")!=std::string::npos) continue;
            std::istringstream ls(line); std::string tok; ls>>tok;
            if(tok.size()<3) continue;
            if(TestBL(AtoW(tok))&&!TestWL(AtoW(tok))){fltHits++;crit("FILTER DRIVER BL",tok,"12");}
        }
        if(!fltHits) ok("Filter Drivers","Clean");

        sub("driverquery");
        std::string dq=RunCmd(L"driverquery /fo csv",20000);
        int dqHits=0,dqTotal=0;
        std::istringstream dss(dq); bool hdr=true;
        std::string dqLine;
        while(std::getline(dss,dqLine)){
            if(hdr){hdr=false;continue;}
            // CSV: "Name","DisplayName","Type","Link Date"
            auto q1=dqLine.find('"'); auto q2=dqLine.find('"',q1+1);
            if(q1==std::string::npos||q2==std::string::npos) continue;
            std::string dn=dqLine.substr(q1+1,q2-q1-1);
            dqTotal++;
            if(TestBL(AtoW(dn))&&!TestWL(AtoW(dn))){dqHits++;crit("KERNEL DRIVER BL",dn,"12");}
        }
        if(!dqHits) ok("Kernel Drivers",std::to_string(dqTotal)+" checked -- clean");
        S.setPhase("12",(fltHits+dqHits)?3:2);
    }

    // ── PHASE 13 ─────────────────────────────────────────────────────────────
    void Phase13() {
        S.setPhase("13",1); S.setPhaseLbl("13: Hash Scan"); sec("13","Known Cheat File Signatures");

        sub("Matrix File Scan (newui/oldui)");
        std::vector<fs::path> roots;
        wchar_t prof[MAX_PATH]={},lapp[MAX_PATH]={},tmp[MAX_PATH]={};
        SHGetFolderPathW(nullptr,CSIDL_PROFILE,nullptr,0,prof);
        SHGetFolderPathW(nullptr,CSIDL_LOCAL_APPDATA,nullptr,0,lapp);
        GetTempPathW(MAX_PATH,tmp);
        const fs::path pProf(prof);
        auto addIf=[&roots](const fs::path& p){ if(fs::exists(p)) roots.push_back(p); };
        addIf(pProf/L"Downloads"); addIf(pProf/L"Desktop"); addIf(pProf/L"Documents");
        addIf(pProf/L"Roblox"); addIf(fs::path(lapp)/L"Roblox");
        addIf(fs::path(tmp));
        addIf(fs::path(L"C:\\Users\\Public")/L"Desktop");
        addIf(fs::path(L"C:\\Users\\Public")/L"Documents");
        addIf(fs::path(L"C:\\Users\\Public")/L"Downloads");
        addIf(pProf/L"AppData\\Local\\Temp");
        addIf(pProf/L"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs");
        info("Phase 13 roots", std::to_string(roots.size())+" path(s) — fast scope (no full AppData)");

        int mHits=0;
        size_t treeVisits=0;
        bool capHit=false;
        for(auto& root:roots){
            if(capHit||S.stopReq) break;
            try{for(auto& f:fs::recursive_directory_iterator(root,fs::directory_options::skip_permission_denied)){
                if(S.stopReq||capHit) break;
                if(++treeVisits>PCC_MAX_FILETREE_ENTRIES){capHit=true;info("Phase 13","File walk cap");break;}
                if(!f.is_regular_file()) continue;
                std::wstring fn=ToLower(f.path().filename().wstring());
                if(fn==L"newui.exe"){mHits++;crit("MATRIX FILE FOUND","Matrix (newui) | "+WtoA(f.path().wstring()),"13");}
                if(fn==L"oldui.exe"){mHits++;crit("MATRIX FILE FOUND","Matrix (oldui) | "+WtoA(f.path().wstring()),"13");}
            }}catch(...){}
        }
        if(!mHits) ok("Matrix File Scan","No newui.exe/oldui.exe found");

        sub("SHA256 Hash Scan");
        S.setStatus("Scanning files (SHA256)...");
        // build size lookup
        std::unordered_map<uint64_t,const CheatEntry*> szLu;
        for(auto& e:CHEAT_DB) if(e.sizeB>0) szLu[e.sizeB]=&e;

        int hHits=0;
        static const std::vector<std::wstring> SCAN_EXTS={L".exe",L".dll",L".dat"};
        treeVisits=0;
        capHit=false;
        for(auto& root:roots){
            if(capHit||S.stopReq) break;
            try{for(auto& f:fs::recursive_directory_iterator(root,fs::directory_options::skip_permission_denied)){
                if(S.stopReq||capHit) break;
                if(++treeVisits>PCC_MAX_FILETREE_ENTRIES){capHit=true;info("Phase 13","Hash walk cap");break;}
                if(!f.is_regular_file()) continue;
                std::wstring ext=ToLower(f.path().extension().wstring());
                if(std::find(SCAN_EXTS.begin(),SCAN_EXTS.end(),ext)==SCAN_EXTS.end()) continue;
                std::error_code ec; auto sz=fs::file_size(f,ec); if(ec) continue;
                auto it=szLu.find(sz); if(it==szLu.end()) continue;
                std::wstring h=SHA256File(f.path().wstring());
                if(!h.empty()&&h==it->second->sha256){
                    hHits++;
                    crit("CHEAT FILE FOUND",WtoA(it->second->name)+" | "+WtoA(f.path().wstring())+" | SHA256 verified","13");
                }
            }}catch(...){}
        }
        if(!hHits) ok("SHA256 Scan","No known cheat files on disk");
        info("DB Size",std::to_string(CHEAT_DB.size())+" signatures");
        S.setPhase("13",(mHits+hHits)?3:2);
    }

    // ── PHASE 14 ─────────────────────────────────────────────────────────────
    void Phase14() {
        S.setPhase("14",1); S.setPhaseLbl("14: MFT / LNK / Jump Lists");
        sec("14","Deleted File Recovery -- MFT / LNK / Jump Lists");

        // build size lookup
        std::unordered_map<uint64_t,const CheatEntry*> szLu;
        for(auto& e:CHEAT_DB) if(e.sizeB>0) szLu[e.sizeB]=&e;

        // fast pre-filter: build combined keyword set
        std::vector<std::wstring> kwList;
        for(auto& k:MFT_APPDATA_KW) kwList.push_back(ToLower(k));
        for(auto& k:MFT_USER_KW)    kwList.push_back(ToLower(k));
        for(auto& e:CHEAT_DB){
            std::wstring key=e.name.substr(0,e.name.find(L' '));
            kwList.push_back(ToLower(key));
        }

        auto fastMatch=[&](const std::string& line)->bool{
            std::string ll=ToLowerA(line);
            for(auto& k:kwList) if(ll.find(WtoA(k))!=std::string::npos) return true;
            for(auto& e:CHEAT_DB) if(ll.find(std::to_string(e.sizeB))!=std::string::npos) return true;
            return false;
        };

        auto isUserPath=[](const std::wstring& p)->bool{
            std::wstring pl=ToLower(p);
            for(auto& tok:std::vector<std::wstring>{L"\\users\\",L"\\appdata\\",L"\\downloads\\",
                L"\\desktop\\",L"\\documents\\",L"\\temp\\"})
                if(pl.find(tok)!=std::wstring::npos) return true;
            return false;
        };

        auto scanMFT=[&](const fs::path& csvPath, const std::string& key)->int{
            CsvReader csv; int hits=0,total=0;
            if(!csv.open(csvPath.wstring())) return 0;
            CsvRow row;
            while(csv.next(row)){
                total++;
                // fast pre-filter on raw line
                std::string flat;
                for(auto& f:row.fields) flat+=f+",";
                if(!fastMatch(flat)) continue;

                std::string fname  =row.get("FileName"); if(fname.empty()) fname=row.get("Name");
                std::string parent =row.get("ParentPath"); if(parent.empty()) parent=row.get("FullPath");
                std::string szStr  =row.get("FileSize");
                std::string isDel  =row.get("IsDeleted");
                std::string cre    =row.get("Created0x10");

                if(fname.empty()) continue;
                std::string fpath=parent+"\\"+fname;
                std::wstring wp=AtoW(fpath);
                if(!isUserPath(wp)) continue;
                if(TestWL(wp)) continue;

                // strip non-digits for size parse
                std::string szClean; for(char c:szStr) if(isdigit(c)) szClean+=c;
                uint64_t sz=szClean.empty()?0:std::stoull(szClean);

                std::string label,text;
                bool deleted=(isDel=="True"||isDel=="1");

                // 1. size match
                if(sz>0){
                    auto it=szLu.find(sz);
                    if(it!=szLu.end()){
                        if(!deleted&&fs::exists(wp)){
                            std::wstring h=SHA256File(wp);
                            if(!h.empty()&&h==it->second->sha256){
                                label="CRIT";
                                text=WtoA(it->second->name)+" | SHA256 verified | ON DISK";
                            }
                        } else {
                            label="SUSP";
                            text=WtoA(it->second->name)+" | Size match "+std::to_string(sz)+" | DELETED";
                        }
                    }
                }
                // 2. exact Matrix filenames
                if(label.empty()){
                    std::wstring fnl=ToLower(AtoW(fname));
                    if(fnl==L"newui.exe"){label="CRIT";text="Matrix (newui) -- exact filename";}
                    else if(fnl==L"oldui.exe"){label="CRIT";text="Matrix (oldui) -- exact filename";}
                }
                // 3. AppData folder KW
                if(label.empty()){
                    std::wstring pl=ToLower(wp);
                    for(auto& kw:MFT_APPDATA_KW){
                        if(pl.find(L"\\"+kw+L"\\")!=std::wstring::npos){
                            label="CRIT"; text="Cheat folder ("+WtoA(kw)+") in AppData path"; break;
                        }
                    }
                }
                // 4. user keyword in filename
                if(label.empty()){
                    std::wstring fnl=ToLower(AtoW(fname));
                    for(auto& kw:MFT_USER_KW){
                        if(fnl.find(kw)!=std::wstring::npos){
                            label="CRIT"; text="Cheat keyword ("+WtoA(kw)+") in filename"; break;
                        }
                    }
                }

                if(!label.empty()){
                    hits++;
                    std::string dlLbl=deleted?"DELETED":"ON DISK";
                    std::string out=text+" | "+fpath+" | "+dlLbl;
                    if(!cre.empty()) out+=" | "+cre;
                    out+=" | Source:"+key;
                    if(label=="SUSP") susp("MFT SUSPECTED",out,"14");
                    else              crit("MFT CONFIRMED",out,"14");
                }
            }
            info("MFT Records",key+": "+std::to_string(total)+" rows | "+std::to_string(hits)+" flagged");
            return hits;
        };

        // MFTECmd
        sub("MFTECmd");
        fs::path mftExe=ezDir/L"MFTECmd.exe";
        int mftHits=0;
        if(fs::exists(mftExe)){
            wchar_t sysDrive[16]={};
            GetEnvironmentVariableW(L"SystemDrive",sysDrive,16);
            std::wstring sd=sysDrive; if(sd.empty()) sd=L"C:";

            struct MRun{std::string key;std::wstring args;};
            std::vector<MRun> runs;
            if(!PCC_SKIP_SLOW_USN_EXPORT)
                runs.push_back({"USN", L"\""+mftExe.wstring()+L"\" -f \""+sd+L"\\$Extend\\$USNJrnl:$J\" --csv \""+ezDir.wstring()+L"\""});
            else
                info("MFTECmd","Skipping USN export (fast mode)");
            runs.push_back({"MFT", L"\""+mftExe.wstring()+L"\" --at -f \""+sd+L"\\$MFT\" --csv \""+ezDir.wstring()+L"\""});
            for(auto& r:runs){
                if(S.stopReq) break;
                info("MFTECmd","Running "+r.key+"...");
                S.setStatus("MFTECmd "+r.key+"...");
                auto t0=std::chrono::steady_clock::now();
                RunCmd(r.args, PCC_MFT_EXPORT_MS);
                int el=(int)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()-t0).count();
                // find newest CSV
                fs::path newest; std::filesystem::file_time_type nt{};
                for(auto& f:fs::directory_iterator(ezDir)){
                    if(f.path().extension()==L".csv"){
                        auto wt=fs::last_write_time(f);
                        if(newest.empty()||wt>nt){newest=f.path();nt=wt;}
                    }
                }
                if(!newest.empty()){
                    ok("MFTECmd",r.key+" done ("+std::to_string(el)+"s) -- scanning "+WtoA(newest.filename().wstring()));
                    mftHits+=scanMFT(newest,r.key);
                } else warn("MFTECmd","No CSV for "+r.key,"14");
            }
            if(!mftHits) ok("MFT Scan","No cheat signatures found");
        } else skip("MFTECmd","Not available");

        // LECmd
        sub("LECmd -- LNK / Recent Files");
        fs::path leExe=ezDir/L"LECmd.exe";
        if(fs::exists(leExe)){
            wchar_t appdata[MAX_PATH]={};
            SHGetFolderPathW(nullptr,CSIDL_APPDATA,nullptr,0,appdata);
            fs::path lnkDir=fs::path(appdata)/L"Microsoft\\Windows\\Recent";
            fs::path leOut=ezDir/L"le_out"; fs::create_directories(leOut);
            S.setStatus("Running LECmd...");
            RunCmd(L"\""+leExe.wstring()+L"\" -d \""+lnkDir.wstring()+
                   L"\" --csv \""+leOut.wstring()+L"\" --csvf LE.csv --all", PCC_LECMD_MS);
            fs::path leCsv=leOut/L"LE.csv";
            int lHits=0;
            if(fs::exists(leCsv)){
                CsvReader csv;
                if(csv.open(leCsv.wstring())){
                    CsvRow row;
                    while(csv.next(row)){
                        std::string tgt=row.get("LocalPath");
                        if(tgt.empty()) tgt=row.get("TargetIDAbsolutePath");
                        std::wstring fn=fs::path(AtoW(tgt)).filename().wstring();
                        std::string szS=row.get("TargetFileSize");
                        std::string szC; for(char c:szS) if(isdigit(c)) szC+=c;
                        uint64_t sz=szC.empty()?0:std::stoull(szC);
                        std::wstring fnl=ToLower(fn);
                        bool hit=(fnl==L"newui.exe"||fnl==L"oldui.exe");
                        if(!hit&&sz>0) hit=(szLu.count(sz)>0);
                        if(hit){lHits++;bool on=fs::exists(AtoW(tgt));
                            crit("LNK MATCH",WtoA(fn)+" | "+tgt+" | "+(on?"ON DISK":"DELETED"),"14");}
                    }
                }
                if(!lHits) ok("LNK Scan","No matches");
            } else warn("LECmd","No CSV generated","14");
        } else skip("LECmd","Not available");

        // JLECmd -- jump lists (WxTCmd is Timeline / ActivitiesCache.db only, not jump lists)
        sub("JLECmd -- Jump Lists");
        fs::path jleExe=ezDir/L"JLECmd.exe";
        if(fs::exists(jleExe)){
            wchar_t appdata2[MAX_PATH]={};
            SHGetFolderPathW(nullptr,CSIDL_APPDATA,nullptr,0,appdata2);
            fs::path recentDir=fs::path(appdata2)/L"Microsoft\\Windows\\Recent";
            fs::path jleOut=ezDir/L"jle_out"; fs::create_directories(jleOut);
            std::error_code dec;
            for(auto& f:fs::directory_iterator(jleOut,dec))
                if(f.path().extension()==L".csv"){ std::error_code rem; fs::remove(f.path(),rem); }
            const auto runJle=[&](const fs::path& dir)->std::string{
                return RunCmd(L"\""+jleExe.wstring()+L"\" -d \""+dir.wstring()+L"\" --csv \""+
                    jleOut.wstring()+L"\" --csvf jle_jumplist.csv -q", PCC_JLECMD_MS);
            };
            std::string jleLog;
            if(!fs::exists(recentDir)) skip("JLECmd","Recent folder missing");
            else{
                S.setStatus("Running JLECmd (jump lists)...");
                jleLog=runJle(recentDir);
                std::vector<fs::path> csvFiles=CollectJleOutputCsvs(jleOut);
                if(csvFiles.empty()){
                    info("JLECmd","No JLECmd CSV yet; staging jump list copies...");
                    fs::path stage=jleOut/L"_staged_jump_lists";
                    fs::remove_all(stage,dec);
                    fs::create_directories(stage);
                    int copied=0;
                    const fs::path jlDirs[]={recentDir,recentDir/L"AutomaticDestinations"};
                    for(const fs::path& d:jlDirs){
                        std::error_code ec;
                        if(!fs::exists(d)) continue;
                        for(const auto& ent:fs::directory_iterator(d,ec)){
                            if(ec) break;
                            if(!ent.is_regular_file()) continue;
                            auto ext=ent.path().extension();
                            if(ext!=L".automaticDestinations-ms"&&ext!=L".customDestinations-ms") continue;
                            std::error_code ce;
                            fs::copy_file(ent.path(),stage/ent.path().filename(),fs::copy_options::overwrite_existing,ce);
                            if(!ce) ++copied;
                        }
                    }
                    if(copied>0){jleLog=runJle(stage);csvFiles=CollectJleOutputCsvs(jleOut);}
                    else warn("JLECmd","Could not copy jump list files","14");
                }else info("JLECmd",std::to_string(csvFiles.size())+" CSV export file(s)");
                int wHits=0;
                if(!csvFiles.empty()){
                    for(const fs::path& jleCsv:csvFiles){
                        CsvReader csv;
                        if(!csv.open(jleCsv.wstring())){warn("JLECmd","Open failed: "+WtoA(jleCsv.filename().wstring()),"14");continue;}
                        CsvRow row;
                        while(csv.next(row)){
                            std::string tgt=row.get("LocalPath");
                            if(tgt.empty()) tgt=row.get("TargetIDAbsolutePath");
                            if(tgt.empty()) tgt=row.get("Path");
                            std::wstring fn=fs::path(AtoW(tgt)).filename().wstring();
                            std::string szS=row.get("FileSize");
                            if(szS.empty()) szS=row.get("TargetFileSize");
                            std::string szC; for(char c:szS) if(isdigit((unsigned char)c)) szC+=c;
                            uint64_t sz=szC.empty()?0:std::stoull(szC);
                            std::wstring fnl=ToLower(fn);
                            bool hit=(fnl==L"newui.exe"||fnl==L"oldui.exe"||(sz>0&&szLu.count(sz)>0)
                                ||(TestBL(fn)&&!TestWL(fn)));
                            if(hit){wHits++;bool on=fs::exists(AtoW(tgt));
                                crit("JUMP LIST MATCH",WtoA(fn)+" | "+tgt+" | "+(on?"ON DISK":"DELETED"),"14");}
                        }
                    }
                    if(!wHits) ok("Jump Lists","No matches");
                    std::string names;
                    for(const auto& p:csvFiles) names+=WtoA(p.filename().wstring())+" ";
                    info("Jump List Records",std::to_string(wHits)+" hit(s), "+std::to_string(csvFiles.size())+" file(s): "+names);
                }else{
                    std::string tail=jleLog.size()>500?jleLog.substr(jleLog.size()-500):jleLog;
                    for(char& c:tail) if(c=='\n'||c=='\r') c=' ';
                    warn("JLECmd",std::string("No CSV produced. ")+(tail.empty()?"":("Output: "+tail)),"14");
                }
            }
        } else skip("JLECmd","JLECmd.exe not found");

        S.setPhase("14",2);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
//  DIRECTX 11 STATE
// ─────────────────────────────────────────────────────────────────────────────
static ID3D11Device*            g_pd3dDevice    = nullptr;
static ID3D11DeviceContext*     g_pd3dCtx       = nullptr;
static IDXGISwapChain*          g_pSwapChain    = nullptr;
static ID3D11RenderTargetView*  g_mainRTV       = nullptr;
static HWND                     g_hWndMain      = nullptr;

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd={};
    sd.BufferCount=2; sd.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT; sd.OutputWindow=hWnd;
    sd.SampleDesc.Count=1; sd.Windowed=TRUE;
    sd.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL fl; UINT flags=0;
    if(D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,flags,
        nullptr,0,D3D11_SDK_VERSION,&sd,&g_pSwapChain,&g_pd3dDevice,&fl,&g_pd3dCtx)!=S_OK) return false;
    ID3D11Texture2D* bb=nullptr; g_pSwapChain->GetBuffer(0,IID_PPV_ARGS(&bb));
    g_pd3dDevice->CreateRenderTargetView(bb,nullptr,&g_mainRTV); bb->Release();
    return true;
}
static void CleanupDeviceD3D() {
    if(g_mainRTV){g_mainRTV->Release();g_mainRTV=nullptr;}
    if(g_pSwapChain){g_pSwapChain->Release();g_pSwapChain=nullptr;}
    if(g_pd3dCtx){g_pd3dCtx->Release();g_pd3dCtx=nullptr;}
    if(g_pd3dDevice){g_pd3dDevice->Release();g_pd3dDevice=nullptr;}
}
static void ResizeRTV() {
    if(g_mainRTV){g_mainRTV->Release();g_mainRTV=nullptr;}
    g_pSwapChain->ResizeBuffers(0,0,0,DXGI_FORMAT_UNKNOWN,0);
    ID3D11Texture2D* bb=nullptr; g_pSwapChain->GetBuffer(0,IID_PPV_ARGS(&bb));
    g_pd3dDevice->CreateRenderTargetView(bb,nullptr,&g_mainRTV); bb->Release();
}
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND,UINT,WPARAM,LPARAM);

#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWCP_ROUND
#define DWMWCP_ROUND 2
#endif

static LRESULT CALLBACK WndProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    if(ImGui_ImplWin32_WndProcHandler(hWnd,msg,wParam,lParam)) return true;
    switch(msg){
    case WM_GETMINMAXINFO: {
        auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        mmi->ptMinTrackSize.x = 960;
        mmi->ptMinTrackSize.y = 600;
        return 0;
    }
    case WM_NCHITTEST: {
        if (ImGui::GetCurrentContext()) {
            ImGuiIO& io = ImGui::GetIO();
            if (io.WantCaptureMouse)
                return DefWindowProcW(hWnd, msg, wParam, lParam);
        }
        POINT pt{};
        pt.x = (int)(short)LOWORD(lParam);
        pt.y = (int)(short)HIWORD(lParam);
        ScreenToClient(hWnd, &pt);
        RECT rc{};
        GetClientRect(hWnd, &rc);
        const int dx = GetSystemMetrics(SM_CXFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
        const int dy = GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CYPADDEDBORDER);
        if (pt.y < dy) {
            if (pt.x < dx) return HTTOPLEFT;
            if (pt.x > rc.right - dx) return HTTOPRIGHT;
            return HTTOP;
        }
        if (pt.y > rc.bottom - dy) {
            if (pt.x < dx) return HTBOTTOMLEFT;
            if (pt.x > rc.right - dx) return HTBOTTOMRIGHT;
            return HTBOTTOM;
        }
        if (pt.x < dx) return HTLEFT;
        if (pt.x > rc.right - dx) return HTRIGHT;
        return HTCLIENT;
    }
    case WM_SIZE: if(g_pd3dDevice&&wParam!=SIZE_MINIMIZED) ResizeRTV(); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

static void DrawCustomTitleBar(float capH, const char* title) {
    if (!g_hWndMain) return;
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 wp = ImGui::GetWindowPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 bg = ImGui::ColorConvertFloat4ToU32(COL_HEADER);
    const ImU32 ln = ImGui::ColorConvertFloat4ToU32(ImVec4(COL_BORDER.x, COL_BORDER.y, COL_BORDER.z, 0.6f));
    dl->AddRectFilled(wp, ImVec2(wp.x + io.DisplaySize.x, wp.y + capH), bg);
    dl->AddLine(ImVec2(wp.x, wp.y + capH - 1), ImVec2(wp.x + io.DisplaySize.x, wp.y + capH - 1), ln);

    const float btnW = 48.f;
    const float btnRegion = btnW * 3.f + 6.f;
    const float dragW = io.DisplaySize.x - btnRegion;

    ImGui::SetCursorScreenPos(wp);
    ImGui::InvisibleButton("##cap_drag", ImVec2(dragW, capH));
    if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        ReleaseCapture();
        SendMessageW(g_hWndMain, WM_NCLBUTTONDOWN, HTCAPTION, 0);
    }
    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
        ShowWindow(g_hWndMain, IsZoomed(g_hWndMain) ? SW_RESTORE : SW_MAXIMIZE);

    const float fs = ImGui::GetFontSize();
    dl->AddText(ImVec2(wp.x + 16.f, wp.y + (capH - fs) * 0.5f),
        ImGui::ColorConvertFloat4ToU32(COL_BRIGHT), title);

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, (capH - fs) * 0.5f));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1, 1, 1, 0.07f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1, 1, 1, 0.11f));

    ImGui::SetCursorScreenPos(ImVec2(wp.x + dragW, wp.y + 2.f));
    if (ImGui::Button("##min", ImVec2(btnW, capH - 4.f))) ShowWindow(g_hWndMain, SW_MINIMIZE);
    {
        ImVec2 p = ImGui::GetItemRectMin();
        dl->AddLine(ImVec2(p.x + 16, p.y + capH * 0.5f), ImVec2(p.x + btnW - 16, p.y + capH * 0.5f),
            ImGui::ColorConvertFloat4ToU32(COL_TEXT), 1.2f);
    }
    ImGui::SameLine(0, 0);
    if (ImGui::Button("##max", ImVec2(btnW, capH - 4.f)))
        ShowWindow(g_hWndMain, IsZoomed(g_hWndMain) ? SW_RESTORE : SW_MAXIMIZE);
    {
        ImVec2 p = ImGui::GetItemRectMin();
        if (IsZoomed(g_hWndMain)) {
            dl->AddRect(ImVec2(p.x + 18, p.y + 12), ImVec2(p.x + btnW - 14, p.y + capH - 14),
                ImGui::ColorConvertFloat4ToU32(COL_TEXT), 0, 0, 1.2f);
            dl->AddRect(ImVec2(p.x + 14, p.y + 10), ImVec2(p.x + btnW - 18, p.y + capH - 18),
                ImGui::ColorConvertFloat4ToU32(COL_TEXT), 0, 0, 1.2f);
        } else {
            dl->AddRect(ImVec2(p.x + 16, p.y + 10), ImVec2(p.x + btnW - 16, p.y + capH - 12),
                ImGui::ColorConvertFloat4ToU32(COL_TEXT), 0, 0, 1.2f);
        }
    }
    ImGui::SameLine(0, 0);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.22f, 0.22f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.95f, 0.12f, 0.12f, 1.f));
    if (ImGui::Button("##close", ImVec2(btnW, capH - 4.f))) PostMessageW(g_hWndMain, WM_CLOSE, 0, 0);
    {
        ImVec2 p = ImGui::GetItemRectMin();
        float cx = p.x + btnW * 0.5f, cy = p.y + (capH - 4.f) * 0.5f;
        dl->AddLine(ImVec2(cx - 6, cy - 6), ImVec2(cx + 6, cy + 6), IM_COL32(235, 235, 240, 255), 1.4f);
        dl->AddLine(ImVec2(cx + 6, cy - 6), ImVec2(cx - 6, cy + 6), IM_COL32(235, 235, 240, 255), 1.4f);
    }
    ImGui::PopStyleColor(2);
    ImGui::PopStyleColor(3);
    ImGui::PopStyleVar(2);
}

// ─────────────────────────────────────────────────────────────────────────────
//  IMGUI STYLE
// ─────────────────────────────────────────────────────────────────────────────
static void SetupStyle() {
    ImGuiStyle& s=ImGui::GetStyle();
    s.WindowRounding=3; s.FrameRounding=2; s.PopupRounding=2;
    s.ScrollbarRounding=2; s.GrabRounding=2; s.TabRounding=2;
    s.WindowBorderSize=1; s.FrameBorderSize=0; s.PopupBorderSize=1;
    s.WindowPadding={10,8}; s.FramePadding={8,5};
    s.ItemSpacing={8,5}; s.IndentSpacing=12;
    s.ScrollbarSize=10; s.GrabMinSize=8;

    ImVec4* c=s.Colors;
    c[ImGuiCol_WindowBg]            =COL_BG;
    c[ImGuiCol_ChildBg]             =COL_PANEL;
    c[ImGuiCol_PopupBg]             =COL_PANEL;
    c[ImGuiCol_Border]              =ImVec4(COL_BORDER.x,COL_BORDER.y,COL_BORDER.z,0.65f);
    c[ImGuiCol_FrameBg]             =ImVec4(0.102f,0.112f,0.129f,1);
    c[ImGuiCol_FrameBgHovered]      =ImVec4(COL_ACCENT2.x,COL_ACCENT2.y,COL_ACCENT2.z,0.28f);
    c[ImGuiCol_FrameBgActive]       =ImVec4(COL_ACCENT2.x,COL_ACCENT2.y,COL_ACCENT2.z,0.40f);
    c[ImGuiCol_TitleBg]             =COL_HEADER;
    c[ImGuiCol_TitleBgActive]       =COL_HEADER;
    c[ImGuiCol_MenuBarBg]           =COL_HEADER;
    c[ImGuiCol_ScrollbarBg]         =COL_BG;
    c[ImGuiCol_ScrollbarGrab]       =COL_MUTED;
    c[ImGuiCol_ScrollbarGrabHovered]=ImVec4(COL_ACCENT2.x,COL_ACCENT2.y,COL_ACCENT2.z,0.75f);
    c[ImGuiCol_ScrollbarGrabActive] =COL_ACCENT2;
    c[ImGuiCol_CheckMark]           =COL_ACCENT;
    c[ImGuiCol_SliderGrab]          =COL_ACCENT2;
    c[ImGuiCol_SliderGrabActive]    =COL_ACCENT;
    c[ImGuiCol_Button]              =COL_ACCENT2;
    c[ImGuiCol_ButtonHovered]       =COL_ACCENT;
    c[ImGuiCol_ButtonActive]        =ImVec4(0.949f,0.690f,0.247f,1);
    c[ImGuiCol_Header]              =ImVec4(COL_ACCENT2.x,COL_ACCENT2.y,COL_ACCENT2.z,0.35f);
    c[ImGuiCol_HeaderHovered]       =ImVec4(COL_ACCENT.x,COL_ACCENT.y,COL_ACCENT.z,0.45f);
    c[ImGuiCol_HeaderActive]        =ImVec4(COL_ACCENT.x,COL_ACCENT.y,COL_ACCENT.z,0.65f);
    c[ImGuiCol_Separator]           =ImVec4(COL_BORDER.x,COL_BORDER.y,COL_BORDER.z,0.65f);
    c[ImGuiCol_Tab]                 =ImVec4(0.069f,0.078f,0.090f,1);
    c[ImGuiCol_TabHovered]          =ImVec4(COL_ACCENT2.x,COL_ACCENT2.y,COL_ACCENT2.z,0.68f);
    c[ImGuiCol_TabActive]           =ImVec4(0.133f,0.106f,0.078f,1);
    c[ImGuiCol_TabUnfocusedActive]  =ImVec4(0.102f,0.089f,0.074f,1);
    c[ImGuiCol_Text]                =COL_TEXT;
    c[ImGuiCol_TextDisabled]        =COL_DIM;
    c[ImGuiCol_PlotLines]           =COL_ACCENT;
    c[ImGuiCol_PlotHistogram]       =COL_ACCENT;
}

// ─────────────────────────────────────────────────────────────────────────────
//  UI  --  per-tab badge filtering
// ─────────────────────────────────────────────────────────────────────────────
static const std::unordered_map<std::string,std::vector<std::string>> TAB_PHASES={
    {"Host Surface",       {"02","03","04","05"}},
    {"Execution Evidence", {"06","07","08","09","10"}},
    {"Artifact Sweep",     {"11","12","13"}},
    {"Recovery Trails",    {"14"}},
};

static ImVec4 BadgeColor(Badge b) {
    switch(b){
    case Badge::OK:   return COL_OK;
    case Badge::CRIT: return COL_CRIT;
    case Badge::WARN: return COL_WARN;
    case Badge::SUSP: return COL_SUSP;
    case Badge::INFO: return COL_INFO;
    case Badge::SKIP: return COL_DIM;
    default:          return COL_DIM;
    }
}
static ImVec4 BadgeBgColor(Badge b) {
    switch(b){
    case Badge::OK:   return COL_OK_BG;
    case Badge::CRIT: return COL_CRIT_BG;
    case Badge::WARN: return COL_WARN_BG;
    case Badge::SUSP: return COL_SUSP_BG;
    case Badge::INFO: return COL_INFO_BG;
    case Badge::SKIP: return COL_MUTED;
    default:          return COL_MUTED;
    }
}
static const char* BadgeStr(Badge b) {
    switch(b){
    case Badge::OK:   return " OK ";
    case Badge::CRIT: return "CRIT";
    case Badge::WARN: return "WARN";
    case Badge::SUSP: return "SUSP";
    case Badge::INFO: return "INFO";
    case Badge::SKIP: return "SKIP";
    default:          return " -- ";
    }
}

// height <= 0: match log rows to frame height; explicit height aligns pill with title row in finding cards.
static ImVec2 MeasureBadgePill(Badge b, float height) {
    const char* s = BadgeStr(b);
    const ImVec2 ts = ImGui::CalcTextSize(s);
    const float padX = 8.0f;
    const float h = (height > 0.f) ? height : ImGui::GetFrameHeight();
    return ImVec2(ts.x + padX * 2.0f, h);
}

static void DrawBadgePill(Badge b, float height = 0.f) {
    const char* s = BadgeStr(b);
    const ImVec2 sz = MeasureBadgePill(b, height);
    const ImVec2 ts = ImGui::CalcTextSize(s);
    const float padX = 8.0f;
    const ImVec2 pos = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(pos, ImVec2(pos.x + sz.x, pos.y + sz.y),
        ImGui::ColorConvertFloat4ToU32(BadgeBgColor(b)), 4.0f);
    dl->AddText(ImVec2(pos.x + padX, pos.y + (sz.y - ts.y) * 0.5f),
        ImGui::ColorConvertFloat4ToU32(BadgeColor(b)), s);
    ImGui::Dummy(ImVec2(sz.x, sz.y));
}

static void DrawFindingCard(const std::string& label, const std::string& value, Badge badge, ImGuiID uid) {
    ImGui::PushID(uid);
    const float availW = ImGui::GetContentRegionAvail().x;
    const ImVec2 start = ImGui::GetCursorScreenPos();
    const float lineH = ImGui::GetTextLineHeight();
    const float pillH = lineH + 8.0f;
    const ImVec2 pillSz = MeasureBadgePill(badge, pillH);

    const float accentW = 4.0f;
    const float accentInsetY = 6.0f;
    // Clear gap so badge never visually meets the rail (rounding + AA used to bleed right)
    const float gutterAfterAccent = 28.0f;
    const float gapAfterBadge = 14.0f;
    const float padY = 10.0f;
    const float rowGap = 6.0f;
    const float padRight = 12.0f;

    const float contentX0 = start.x + accentW + gutterAfterAccent;
    const float textLeft = contentX0 + pillSz.x + gapAfterBadge;
    const float textMaxW = std::max(80.0f, (start.x + availW - padRight) - textLeft);

    const float textH = ImGui::CalcTextSize(value.c_str(), nullptr, false, textMaxW).y;
    const float cardH = padY + lineH + rowGap + textH + padY;
    const ImVec4 sig = BadgeColor(badge);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(start, { start.x + availW, start.y + cardH },
        ImGui::ColorConvertFloat4ToU32(ImVec4(0.078f, 0.086f, 0.098f, 1.0f)), 3.0f);
    if (accentInsetY * 2.0f + 4.0f < cardH) {
        dl->AddRectFilled({ start.x, start.y + accentInsetY },
            { start.x + accentW, start.y + cardH - accentInsetY },
            ImGui::ColorConvertFloat4ToU32(sig), 0.0f, ImDrawFlags_None);
    } else {
        dl->AddRectFilled({ start.x, start.y }, { start.x + accentW, start.y + cardH },
            ImGui::ColorConvertFloat4ToU32(sig), 0.0f, ImDrawFlags_None);
    }
    dl->AddRect(start, { start.x + availW, start.y + cardH },
        ImGui::ColorConvertFloat4ToU32(ImVec4(COL_BORDER.x, COL_BORDER.y, COL_BORDER.z, 0.45f)), 3.0f);

    ImGui::Dummy({ availW, cardH });

    const float yLabel = start.y + padY;
    const float pillY = yLabel + (lineH - pillSz.y) * 0.5f;

    ImGui::SetCursorScreenPos({ contentX0, pillY });
    DrawBadgePill(badge, pillH);

    ImGui::SetCursorScreenPos({ textLeft, yLabel });
    ImGui::PushStyleColor(ImGuiCol_Text, COL_BRIGHT);
    ImGui::TextUnformatted(label.c_str());
    ImGui::PopStyleColor();

    ImGui::SetCursorScreenPos({ textLeft, yLabel + lineH + rowGap });
    ImGui::PushTextWrapPos(start.x + availW - padRight);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::TextUnformatted(value.c_str());
    ImGui::PopStyleColor();
    ImGui::PopTextWrapPos();

    ImGui::SetCursorScreenPos({ start.x, start.y + cardH });
    ImGui::PopID();
}

// Draw findings pane filtered by tab phase list
static void DrawFindingsPane(const std::vector<Finding>& crits, const std::vector<Finding>& warns,
                              const std::vector<std::string>& phases, ImGuiID& nextId) {
    auto inPhase=[&](const std::string& ph)->bool{
        if(phases.empty()) return true;
        return std::find(phases.begin(),phases.end(),ph)!=phases.end();
    };
    bool any=false;
    for(auto& f:crits) if(inPhase(f.phase)){any=true; DrawFindingCard(f.label,f.value,Badge::CRIT, nextId++);}
    for(auto& f:warns) if(inPhase(f.phase)){any=true; DrawFindingCard(f.label,f.value,f.badge, nextId++);}
    if(!any){
        ImGui::PushStyleColor(ImGuiCol_Text,COL_DIM);
        ImGui::TextUnformatted("\n  No findings for this category.\n");
        ImGui::PopStyleColor();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN RENDER LOOP
// ─────────────────────────────────────────────────────────────────────────────
static void RenderUI() {
    // snapshot state under lock
    std::vector<LogEntry>   logSnap;
    std::vector<Finding>    critsSnap, warnsSnap;
    std::string             phaseLbl, statusMsg, elapsed;
    std::unordered_map<std::string,int> phaseState;
    bool running;
    {
        std::lock_guard<std::mutex> lk(G.mtx);
        logSnap    = G.log;
        critsSnap  = G.crits;
        warnsSnap  = G.warns;
        phaseLbl   = G.phaseLabel;
        statusMsg  = G.statusMsg;
        phaseState = G.phaseState;
        running    = G.running;
    }
    elapsed = G.elapsed();

    ImGuiIO& io=ImGui::GetIO();
    ImGui::SetNextWindowPos({0,0}); ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin("##main",nullptr,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|
                 ImGuiWindowFlags_NoBringToFrontOnFocus|ImGuiWindowFlags_NoNav);

    const float capH = 36.f;
    DrawCustomTitleBar(capH, "PC Check Scanner  |  vxti");

    // ── HEADER ────────────────────────────────────────────────────────────────
    ImDrawList* dl=ImGui::GetWindowDrawList();
    ImVec2 winPos=ImGui::GetWindowPos();
    const float hdrY = winPos.y + capH;
    // accent bar
    dl->AddRectFilled({winPos.x,hdrY},{winPos.x+4,hdrY+72},
                      ImGui::ColorConvertFloat4ToU32(COL_ACCENT));

    ImGui::SetCursorPos({14, capH + 8.f});
    ImGui::PushStyleColor(ImGuiCol_Text,COL_ACCENT);
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size>1?ImGui::GetIO().Fonts->Fonts[1]:ImGui::GetIO().Fonts->Fonts[0]);
    ImGui::Text("PCCHECKSCANNER");
    ImGui::PopFont();
    ImGui::PopStyleColor();

    ImGui::SetCursorPos({14, capH + 32.f});
    ImGui::PushStyleColor(ImGuiCol_Text,COL_DIM);
    ImGui::Text("Digital Integrity Audit Console  |  Competitive Roblox League");
    ImGui::PopStyleColor();

    // host / user
    wchar_t comp[256]={},user[256]={};
    DWORD cs=256,us=256;
    GetComputerNameW(comp,&cs); GetUserNameW(user,&us);
    ImGui::SetCursorPos({14, capH + 48.f});
    ImGui::PushStyleColor(ImGuiCol_Text,COL_MUTED);
    ImGui::Text("Case Target  %s\\%s", WtoA(comp).c_str(), WtoA(user).c_str());
    ImGui::PopStyleColor();

    // timer + admin
    ImGui::SetCursorPos({io.DisplaySize.x-160, capH + 10.f});
    ImGui::PushStyleColor(ImGuiCol_Text,COL_ACCENT);
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size>1?ImGui::GetIO().Fonts->Fonts[1]:ImGui::GetIO().Fonts->Fonts[0]);
    ImGui::Text("%s", elapsed.c_str());
    ImGui::PopFont(); ImGui::PopStyleColor();

    ImGui::SetCursorPos({io.DisplaySize.x-160, capH + 50.f});
    if(IsAdmin()){ImGui::PushStyleColor(ImGuiCol_Text,COL_OK);ImGui::Text("[ ELEVATED ]");}
    else{ImGui::PushStyleColor(ImGuiCol_Text,COL_WARN);ImGui::Text("[ LIMITED ]");}
    ImGui::PopStyleColor();

    // header separator
    ImGui::SetCursorPos({0, capH + 72.f});
    ImGui::PushStyleColor(ImGuiCol_Separator,COL_BORDER);
    ImGui::Separator(); ImGui::PopStyleColor();

    // ── BODY LAYOUT ───────────────────────────────────────────────────────────
    float bodyTop = capH + 76.f, bodyH = io.DisplaySize.y - bodyTop - 24.f;
    float sideW=220;
    float mainW=io.DisplaySize.x-sideW-1;

    // ── MAIN  (notebook) ──────────────────────────────────────────────────────
    ImGui::SetCursorPos({0,bodyTop});
    ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.039f,0.039f,0.039f,1));
    ImGui::BeginChild("##nb",{mainW,bodyH},false);

    if(ImGui::BeginTabBar("##tabs")) {

        // ── OVERVIEW TAB ──────────────────────────────────────────────────────
        if(ImGui::BeginTabItem("  Caseboard  ")) {
            ImGuiID fcId = 0;
            // stat cards
            float cardW=(ImGui::GetContentRegionAvail().x-32)/4;
            struct StatDef{const char* lbl;size_t count;ImVec4 fg,bg;};
            std::vector<StatDef> stats={
                {"CONFIRMED",critsSnap.size(),COL_CRIT,COL_CRIT_BG},
                {"SUSPECTED",warnsSnap.size(),COL_SUSP,COL_SUSP_BG},
                {"WARN",      0,               COL_WARN,COL_WARN_BG},
                {"PASS",      (size_t)(size_t)0,COL_OK, COL_OK_BG},
            };
            // count clean
            {int oks=0;std::lock_guard<std::mutex> lk(G.mtx);
             for(auto& e:G.log) if(e.badge==Badge::OK) oks++;
             stats[3].count=oks;}
            ImGui::Dummy({0,4});
            for(int i=0;i<4;i++){
                ImGui::SameLine(i*(cardW+8)+8);
                ImGui::PushStyleColor(ImGuiCol_ChildBg,stats[i].bg);
                ImGui::BeginChild(("##card"+std::to_string(i)).c_str(),{cardW,70},true);
                // top accent
                ImVec2 cp=ImGui::GetCursorScreenPos();
                ImGui::GetWindowDrawList()->AddRectFilled(cp,{cp.x+cardW,cp.y+2},
                    ImGui::ColorConvertFloat4ToU32(stats[i].fg));
                ImGui::Dummy({0,4});
                ImGui::PushStyleColor(ImGuiCol_Text,stats[i].fg);
                ImGui::Text("%s", stats[i].lbl);
                ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size>1?ImGui::GetIO().Fonts->Fonts[1]:ImGui::GetIO().Fonts->Fonts[0]);
                ImGui::Text("%zu", stats[i].count);
                ImGui::PopFont(); ImGui::PopStyleColor();
                ImGui::EndChild(); ImGui::PopStyleColor();
            }
            ImGui::NewLine();

            // two-column findings split
            float colW=(ImGui::GetContentRegionAvail().x-12)/2;
            ImGui::PushStyleColor(ImGuiCol_Text,COL_CRIT);
            ImGui::Text("  CONFIRMED EVIDENCE");
            ImGui::SameLine(colW+6);
            ImGui::PushStyleColor(ImGuiCol_Text,COL_SUSP);
            ImGui::Text("  SUSPECTED SIGNALS");
            ImGui::PopStyleColor(2);

            ImGui::BeginChild("##ov_crit",{colW,bodyH-140},true);
            if(critsSnap.empty()){ImGui::PushStyleColor(ImGuiCol_Text,COL_DIM);ImGui::Text("\n  No confirmed cheats.");ImGui::PopStyleColor();}
            else for(auto& f:critsSnap) DrawFindingCard(f.label,f.value,Badge::CRIT, fcId++);
            ImGui::EndChild(); ImGui::SameLine(0,6);
            ImGui::BeginChild("##ov_susp",{colW,bodyH-140},true);
            if(warnsSnap.empty()){ImGui::PushStyleColor(ImGuiCol_Text,COL_DIM);ImGui::Text("\n  No suspected findings.");ImGui::PopStyleColor();}
            else for(auto& f:warnsSnap) DrawFindingCard(f.label,f.value,f.badge, fcId++);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        // ── SYSTEM / EXECUTION / FILES / MFT TABS ─────────────────────────────
        for(auto& [tabName,phases]:TAB_PHASES){
            if(ImGui::BeginTabItem(("  "+tabName+"  ").c_str())){
                ImGuiID fcId = 0;
                ImGui::BeginChild(("##t_"+tabName).c_str(),{0,0},false);
                DrawFindingsPane(critsSnap,warnsSnap,phases, fcId);
                ImGui::EndChild(); ImGui::EndTabItem();
            }
        }

        // ── FULL LOG TAB ──────────────────────────────────────────────────────
        if(ImGui::BeginTabItem("  Raw Event Log  ")){
            ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.024f,0.024f,0.024f,1));
            ImGui::BeginChild("##log",{0,0},false);
            ImGui::PushStyleColor(ImGuiCol_Text,COL_DIM);
            ImGui::Text("  %zu entries", logSnap.size());
            ImGui::PopStyleColor();
            ImGui::Separator();
            int logRow = 0;
            for(auto& e:logSnap){
                ImGui::PushID(logRow++);
                if(e.badge==Badge::NONE){
                    if(!e.label.empty()&&e.label[0]=='§'){
                        ImGui::PushStyleColor(ImGuiCol_Text,COL_ACCENT);
                        ImGui::Text("  [%s]  %s", e.label.substr(1).c_str(), e.value.c_str());
                        ImGui::PopStyleColor();
                        ImGui::PushStyleColor(ImGuiCol_Separator,COL_BORDER);
                        ImGui::Separator(); ImGui::PopStyleColor();
                    } else if(e.label=="▶"){
                        ImGui::PushStyleColor(ImGuiCol_Text,COL_ACCENT);
                        ImGui::Text("  ▶  ");ImGui::SameLine(0,0);
                        ImGui::PushStyleColor(ImGuiCol_Text,COL_BRIGHT);
                        ImGui::TextUnformatted(e.value.c_str());
                        ImGui::PopStyleColor(2);
                    }
                } else {
                    DrawBadgePill(e.badge);
                    ImGui::SameLine(0,8);
                    ImGui::PushStyleColor(ImGuiCol_Text,COL_DIM);
                    ImGui::Text("%s", e.label.c_str());
                    ImGui::PopStyleColor();
                    ImGui::SameLine(0,8);
                    ImGui::PushStyleColor(ImGuiCol_Text,COL_TEXT);
                    ImGui::TextUnformatted(e.value.c_str());
                    ImGui::PopStyleColor();
                }
                ImGui::PopID();
            }
            // auto-scroll
            if(ImGui::GetScrollY()>=ImGui::GetScrollMaxY()-10)
                ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild(); ImGui::PopStyleColor();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::EndChild(); ImGui::PopStyleColor();

    // ── SIDEBAR ───────────────────────────────────────────────────────────────
    ImGui::SetCursorPos({mainW+1,bodyTop});
    ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.059f,0.059f,0.059f,1));
    ImGui::BeginChild("##sidebar",{sideW,bodyH},true);

    // accent top line
    ImVec2 sbp=ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddRectFilled(sbp,{sbp.x+sideW,sbp.y+2},
        ImGui::ColorConvertFloat4ToU32(COL_ACCENT));
    ImGui::Dummy({0,4});

    // scan button
    ImGui::PushStyleColor(ImGuiCol_Button, running?COL_CRIT:
        ImVec4(0.000f,0.784f,0.831f,1));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, running?
        ImVec4(0.8f,0.1f,0.2f,1):ImVec4(0.000f,0.902f,0.463f,1));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0,0,0,1));
    if(ImGui::Button(running?"  STOP  ":"  START SCAN  ",{ImGui::GetContentRegionAvail().x,36})){
        if(running){
            G.stopReq=true;
        } else {
            G.reset(); G.stopReq=false;
            std::thread([]{
                Scanner sc(G); sc.run();
            }).detach();
        }
    }
    ImGui::PopStyleColor(3);

    // progress bar
    ImGui::Dummy({0,2});
    ImVec2 pPos=ImGui::GetCursorScreenPos();
    float pW=ImGui::GetContentRegionAvail().x;
    static float pAnim=0;
    if(running){pAnim+=0.008f; if(pAnim>1.0f) pAnim=0;}
    float pFill=running?fabsf(sinf(pAnim*3.14159f))*0.85f+0.1f:0;
    ImGui::GetWindowDrawList()->AddRectFilled(pPos,{pPos.x+pW,pPos.y+4},
        ImGui::ColorConvertFloat4ToU32(ImVec4(0.06f,0.06f,0.06f,1)));
    if(pFill>0)
        ImGui::GetWindowDrawList()->AddRectFilled(pPos,{pPos.x+pW*pFill,pPos.y+4},
            ImGui::ColorConvertFloat4ToU32(COL_ACCENT2));
    ImGui::Dummy({0,6});

    ImGui::PushStyleColor(ImGuiCol_Text,COL_MUTED);
    ImGui::TextWrapped("%s", phaseLbl.c_str());
    ImGui::PopStyleColor();
    ImGui::Separator();

    // phases list
    ImGui::PushStyleColor(ImGuiCol_Text,COL_ACCENT);
    ImGui::Text("  PHASE CHECKLIST");
    ImGui::PopStyleColor();

    static const std::vector<std::pair<std::string,std::string>> PHASE_DEFS={
        {"01","Bootstrap"}, {"02","Defender"},  {"03","Services"},
        {"04","Disk"},      {"05","VM Check"},  {"06","Amcache"},
        {"07","Reg Logs"},  {"08","Prefetch"},  {"09","Processes"},
        {"10","UserAssist"},{"11","Programs"},  {"12","Drivers"},
        {"13","Hash Scan"}, {"14","MFT / LNK"},
    };
    for(auto& [num,name]:PHASE_DEFS){
        int st=0;
        auto it=phaseState.find(num);
        if(it!=phaseState.end()) st=it->second;
        const char* dot="○";
        ImVec4 clr=COL_MUTED;
        switch(st){
        case 1: dot="◐"; clr=COL_INFO; break;
        case 2: dot="●"; clr=COL_OK;   break;
        case 3: dot="●"; clr=COL_CRIT; break;
        case 4: dot="─"; clr=COL_DIM;  break;
        }
        ImGui::PushStyleColor(ImGuiCol_Text,COL_DIM);
        ImGui::Text("  %s", num.c_str()); ImGui::SameLine(0,4);
        ImGui::PushStyleColor(ImGuiCol_Text,COL_TEXT);
        ImGui::Text("%-12s", name.c_str()); ImGui::SameLine(0,4);
        ImGui::PushStyleColor(ImGuiCol_Text,clr);
        ImGui::Text("%s", dot);
        ImGui::PopStyleColor(3);
    }

    ImGui::EndChild(); ImGui::PopStyleColor();

    // ── STATUS BAR ────────────────────────────────────────────────────────────
    ImGui::SetCursorPos({0,io.DisplaySize.y-24});
    ImGui::PushStyleColor(ImGuiCol_ChildBg,COL_HEADER);
    ImGui::BeginChild("##status",{io.DisplaySize.x,24},false);
    ImVec2 sp=ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddRectFilled(sp,{sp.x+3,sp.y+24},
        ImGui::ColorConvertFloat4ToU32(COL_ACCENT));
    ImGui::SetCursorPosX(8);
    ImGui::PushStyleColor(ImGuiCol_Text,COL_MUTED);
    ImGui::TextUnformatted(statusMsg.c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine(io.DisplaySize.x-110);
    ImGui::PushStyleColor(ImGuiCol_Text,COL_ACCENT);
    ImGui::Text("vxti // PCCheckScanner");
    ImGui::PopStyleColor();
    ImGui::EndChild(); ImGui::PopStyleColor();

    ImGui::End();
}

// ─────────────────────────────────────────────────────────────────────────────
//  ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE,LPSTR,int) {
    // Request elevation if not admin
    if(!IsAdmin()){
        wchar_t path[MAX_PATH]={};
        GetModuleFileNameW(nullptr,path,MAX_PATH);
        ShellExecuteW(nullptr,L"runas",path,nullptr,nullptr,SW_SHOW);
        return 0;
    }

    WNDCLASSEXW wc={sizeof(wc),CS_CLASSDC,WndProc,0,0,hInst,
        LoadIconW(hInst,MAKEINTRESOURCEW(IDI_PCCHECKSCANNER)),
        LoadCursorW(nullptr,IDC_ARROW),
        nullptr,nullptr,L"PCCheck",
        LoadIconW(hInst,MAKEINTRESOURCEW(IDI_PCCHECKSCANNER))};
    RegisterClassExW(&wc);
    HWND hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName,
        L"PC Check Scanner",
        WS_POPUP | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
        100, 100, 1380, 840, nullptr, nullptr, wc.hInst, nullptr);
    g_hWndMain = hWnd;

    BOOL dark = TRUE;
    DwmSetWindowAttribute(hWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    DWORD cornerPref = DWMWCP_ROUND;
    DwmSetWindowAttribute(hWnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cornerPref, sizeof(cornerPref));

    if(!CreateDeviceD3D(hWnd)){CleanupDeviceD3D();UnregisterClassW(wc.lpszClassName,wc.hInstance);return 1;}
    ShowWindow(hWnd,SW_SHOWDEFAULT); UpdateWindow(hWnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io=ImGui::GetIO();
    io.ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename=nullptr;

    // Load fonts -- Consolas 13 (default) + 16 (bold header)
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf",13.0f);
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consolab.ttf",16.0f);
    if(io.Fonts->Fonts.Size<2) io.Fonts->AddFontDefault();

    SetupStyle();
    ImGui_ImplWin32_Init(hWnd);
    ImGui_ImplDX11_Init(g_pd3dDevice,g_pd3dCtx);

    MSG msg; bool done=false;
    while(!done){
        while(PeekMessage(&msg,nullptr,0,0,PM_REMOVE)){
            TranslateMessage(&msg); DispatchMessage(&msg);
            if(msg.message==WM_QUIT) done=true;
        }
        if(done) break;
        ImGui_ImplDX11_NewFrame(); ImGui_ImplWin32_NewFrame(); ImGui::NewFrame();
        RenderUI();
        ImGui::Render();
        const float clear[4]={0.039f,0.039f,0.039f,1};
        g_pd3dCtx->OMSetRenderTargets(1,&g_mainRTV,nullptr);
        g_pd3dCtx->ClearRenderTargetView(g_mainRTV,clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1,0);
    }

    ImGui_ImplDX11_Shutdown(); ImGui_ImplWin32_Shutdown(); ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hWnd); UnregisterClassW(wc.lpszClassName,wc.hInstance);
    return 0;
}
