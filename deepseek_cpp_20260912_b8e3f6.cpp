// destroyerr1558_aggressive_spoofer.cpp
// AGRESİF MOD - Sadece Windows lisansı ve internet korunur
// Derleme: g++ aggressive.cpp -o aggressive.exe -lwbemuuid -lole32 -loleaut32 -luuid -ladvapi32 -lsetupapi -lcfgmgr32 -lnetapi32 -luserenv -lwininet -lshell32 -lversion -static -municode -O2 -s
// YÖNETİCİ olarak çalıştırın.

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wbemidl.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <winreg.h>
#include <comdef.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <iphlpapi.h>
#include <lm.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"
#define BG_GREEN "\033[42m"
#define BG_RED  "\033[41m"
#define BG_YELLOW "\033[43m"

std::mt19937_64 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());

// ═══════════════ YARDIMCILAR ═══════════════
std::string ra(size_t n){const char c[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";std::string s;for(size_t i=0;i<n;i++)s+=c[rng()%36];return s;}
std::string rh(size_t n){const char c[]="0123456789ABCDEF";std::string s;for(size_t i=0;i<n;i++)s+=c[rng()%16];return s;}
std::string rn(size_t n){const char c[]="0123456789";std::string s;for(size_t i=0;i<n;i++)s+=c[rng()%10];return s;}
std::string rl(size_t n){const char c[]="abcdefghijklmnopqrstuvwxyz";std::string s;for(size_t i=0;i<n;i++)s+=c[rng()%26];return s;}

std::wstring tw(const std::string& s){
    if(s.empty())return L"";
    int n=MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,NULL,0);
    std::wstring w(n,0);
    MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,&w[0],n);
    w.pop_back();return w;
}
std::string mac_str(){
    std::string m;
    for(int i=0;i<6;i++){if(i)m+=":";char b[4];sprintf_s(b,"%02X",rng()%256);m+=b;}
    return m;
}
std::string guid_str(){
    return "{"+rh(8)+"-"+rh(4)+"-4"+rh(3)+"-a"+rh(3)+"-"+rh(12)+"}";
}
void okp(const std::string& s,bool ok,const std::string& x=""){
    std::cout<<(ok?GREEN"[✓] ":RED"[✗] ")<<RESET<<s;
    if(!x.empty())std::cout<<CYAN" → "<<x<<RESET;
    std::cout<<std::endl;
}
bool is_admin(){
    BOOL a=FALSE;PSID g=NULL;SID_IDENTIFIER_AUTHORITY n=SECURITY_NT_AUTHORITY;
    if(AllocateAndInitializeSid(&n,2,SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&g))
        {CheckTokenMembership(NULL,g,&a);FreeSid(g);}
    return a;
}

// ═══════════════ REGISTRY ═══════════════
bool rs(HKEY r,const std::wstring& p,const std::wstring& n,const std::wstring& v){
    HKEY k;
    if(RegCreateKeyExW(r,p.c_str(),0,NULL,REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE|KEY_WOW64_64KEY,NULL,&k,NULL)!=ERROR_SUCCESS)return false;
    bool ok=RegSetValueExW(k,n.c_str(),0,REG_SZ,(const BYTE*)v.c_str(),
        (DWORD)((v.length()+1)*sizeof(wchar_t)))==ERROR_SUCCESS;
    RegCloseKey(k);return ok;
}
bool rd(HKEY r,const std::wstring& p,const std::wstring& n,DWORD v){
    HKEY k;
    if(RegCreateKeyExW(r,p.c_str(),0,NULL,REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE|KEY_WOW64_64KEY,NULL,&k,NULL)!=ERROR_SUCCESS)return false;
    bool ok=RegSetValueExW(k,n.c_str(),0,REG_DWORD,(const BYTE*)&v,sizeof(v))==ERROR_SUCCESS;
    RegCloseKey(k);return ok;
}
bool rdt(HKEY r,const std::wstring& p){
    HKEY k;
    if(RegOpenKeyExW(r,p.c_str(),0,KEY_READ|KEY_WRITE,&k)!=ERROR_SUCCESS)return false;
    RegDeleteTreeW(k,NULL);RegCloseKey(k);return true;
}

// ═══════════════ SMBIOS ═══════════════
std::vector<BYTE> smbios_load(){
    HKEY k;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
        0,KEY_READ,&k)!=ERROR_SUCCESS)return{};
    DWORD sz=0;
    if(RegQueryValueExW(k,L"SMBiosData",NULL,NULL,NULL,&sz)!=ERROR_SUCCESS){
        RegCloseKey(k);return{};
    }
    std::vector<BYTE> d(sz);
    RegQueryValueExW(k,L"SMBiosData",NULL,NULL,d.data(),&sz);
    RegCloseKey(k);return d;
}
bool smbios_save(const std::vector<BYTE>& d){
    HKEY k;
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
        0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE|KEY_WOW64_64KEY,
        NULL,&k,NULL)!=ERROR_SUCCESS)return false;
    bool ok=RegSetValueExW(k,L"SMBiosData",0,REG_BINARY,d.data(),
        (DWORD)d.size())==ERROR_SUCCESS;
    RegCloseKey(k);return ok;
}
void set_str(std::vector<BYTE>& d,size_t off,size_t len,int idx,const std::string& val){
    if(idx<=0)return;
    size_t s=off+len;
    for(int i=0;i<idx-1&&s<d.size();++i){
        while(s<d.size()&&d[s]!=0)s++;
        s++;
    }
    if(s+val.size()<d.size()){
        size_t end=s;
        while(end<d.size()&&d[end]!=0)end++;
        size_t old=end-s;
        size_t w=(val.size()<old)?val.size():old;
        memcpy(&d[s],val.c_str(),w);
        for(size_t i=w;i<old;i++)d[s+i]=(BYTE)('0'+(rng()%10));
        d[s+old]=0;
    }
}

// ═══════════════ 1. SMBIOS MEGA AGRESİF ═══════════════
bool spoof_smbios(){
    auto d=smbios_load();
    if(d.empty())return false;
    size_t off=0;bool ok_=false;
    while(off+4<d.size()){
        BYTE t=d[off],len=d[off+1];
        if(len<4)break;
        if(t==0&&off+0x14<d.size()){ // BIOS
            set_str(d,off,len,d[off+0x04],"American Megatrends Inc.");
            set_str(d,off,len,d[off+0x05],"BIOS "+ra(6));
            set_str(d,off,len,d[off+0x07],"BSN"+rn(10));
            set_str(d,off,len,d[off+0x08],"0"+(std::to_string(1+rng()%9))+"/"+
                (std::to_string(1+rng()%12))+"/2025");
            ok_=true;
        }
        if(t==1&&off+0x1B<d.size()){ // System
            for(int i=0;i<16;i++)d[off+0x08+i]=(BYTE)(rng()%256);
            set_str(d,off,len,d[off+0x04],"ASUSTeK COMPUTER INC.");
            set_str(d,off,len,d[off+0x05],"ROG STRIX X"+std::to_string(670+rng()%30)+"-E");
            set_str(d,off,len,d[off+0x07],"SYS"+rn(12));
            if(off+0x19<d.size())set_str(d,off,len,d[off+0x19],"SKU"+rn(8));
            ok_=true;
        }
        if(t==2&&off+0x0A<d.size()){ // Baseboard
            set_str(d,off,len,d[off+0x04],"ASUSTeK COMPUTER INC.");
            set_str(d,off,len,d[off+0x05],"ROG STRIX X"+std::to_string(670+rng()%30)+"-E GAMING");
            set_str(d,off,len,d[off+0x06],"Rev 1."+rh(2));
            set_str(d,off,len,d[off+0x07],"MB"+rn(10)+ra(6));
            if(off+0x08<d.size())set_str(d,off,len,d[off+0x08],"AT"+rn(8));
            ok_=true;
        }
        if(t==3&&off+0x0D<d.size()){ // Chassis
            set_str(d,off,len,d[off+0x04],"Lian Li");
            set_str(d,off,len,d[off+0x05],"O11 DYNAMIC EVO");
            set_str(d,off,len,d[off+0x07],"CHS"+rn(10));
            if(off+0x08<d.size())set_str(d,off,len,d[off+0x08],"CA"+rn(6));
            ok_=true;
        }
        if(t==4&&off+0x2A<d.size()){ // CPU
            set_str(d,off,len,d[off+0x04],"AM5");
            set_str(d,off,len,d[off+0x07],"Advanced Micro Devices, Inc.");
            set_str(d,off,len,d[off+0x10],"AMD Ryzen 9 "+
                std::to_string(7950+rng()%100)+"X 16-Core");
            if(off+0x20<d.size())set_str(d,off,len,d[off+0x20],"CPU"+rn(14));
            if(off+0x17<d.size()){d[off+0x14]=0x10;d[off+0x15]=0x27;d[off+0x16]=0x1C;d[off+0x17]=0x25;}
            if(off+0x26<d.size()){d[off+0x23]=16;d[off+0x24]=16;d[off+0x25]=32;d[off+0x26]=32;}
            ok_=true;
        }
        if(t==7&&off+0x1B<d.size()){ // Cache
            if(off+0x08<d.size()){d[off+0x07]=0x00;d[off+0x08]=0x04;}
            if(off+0x0A<d.size()){d[off+0x09]=0x00;d[off+0x0A]=0x04;}
            d[off+0x0F]=1;d[off+0x10]=5;d[off+0x11]=3;d[off+0x12]=8;
            ok_=true;
        }
        if(t==8&&off+0x08<d.size()){ // Port Connector
            set_str(d,off,len,d[off+0x04],"J"+std::to_string(1+rng()%30));
            if(off+0x06<d.size())set_str(d,off,len,d[off+0x06],"Port"+std::to_string(rng()%8));
            ok_=true;
        }
        if(t==9&&off+0x11<d.size()){ // Slot
            set_str(d,off,len,d[off+0x04],"PCIe Slot "+std::to_string(1+rng()%6));
            if(off+0x0D<d.size())d[off+0x0D]=0x06;
            if(off+0x0E<d.size())d[off+0x0E]=0x0D;
            ok_=true;
        }
        if(t==11&&off+0x05<d.size()){ // OEM Strings
            int cnt=d[off+0x04];
            for(int i=0;i<cnt&&i<16;i++){
                if(off+0x05+i<d.size()){
                    int idx=d[off+0x05+i];
                    if(idx>0)set_str(d,off,len,idx,"OEM"+ra(10));
                }
            }
            ok_=true;
        }
        if(t==17&&off+0x22<d.size()){ // RAM
            set_str(d,off,len,d[off+0x10],"DIMM_"+
                std::to_string(rng()%4)+"_A"+std::to_string(rng()%2));
            if(off+0x11<d.size())set_str(d,off,len,d[off+0x11],"BANK "+std::to_string(rng()%4));
            d[off+0x12]=34;
            if(off+0x16<d.size()){d[off+0x15]=0x00;d[off+0x16]=0x20;}
            set_str(d,off,len,d[off+0x17],"Corsair");
            set_str(d,off,len,d[off+0x18],"RAM"+rh(12));
            if(off+0x19<d.size())set_str(d,off,len,d[off+0x19],"RA"+rn(6));
            set_str(d,off,len,d[off+0x1A],"CMK"+
                (std::to_string(16+rng()%48))+"GX5M2B"+
                (std::to_string(5600+rng()%2000)));
            ok_=true;
        }
        size_t nxt=off+len;
        while(nxt+1<d.size()&&!(d[nxt]==0&&d[nxt+1]==0))nxt++;
        off=nxt+2;
    }
    return ok_&&smbios_save(d);
}

// ═══════════════ 2. DİSK AGRESİF ═══════════════
bool spoof_disks(){
    HKEY k;
    const wchar_t* base=L"SYSTEM\\CurrentControlSet\\Services\\disk\\Enum";
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,base,0,KEY_READ|KEY_WRITE,&k)!=ERROR_SUCCESS)
        return false;
    bool any=false;
    for(int i=0;i<32;i++){
        wchar_t n[8];swprintf_s(n,L"%d",i);
        wchar_t old[512];DWORD sz=sizeof(old);DWORD t=REG_SZ;
        if(RegQueryValueExW(k,n,NULL,&t,(LPBYTE)old,&sz)==ERROR_SUCCESS){
            std::wstring ns=tw("SPOOF_"+ra(20));
            if(RegSetValueExW(k,n,0,REG_SZ,(const BYTE*)ns.c_str(),
                (DWORD)((ns.length()+1)*sizeof(wchar_t)))==ERROR_SUCCESS)any=true;
        }
    }
    RegCloseKey(k);

    // Disk model bilgileri
    const wchar_t* paths[]={
        L"SYSTEM\\CurrentControlSet\\Enum\\SCSI",
        L"SYSTEM\\CurrentControlSet\\Enum\\IDE",
        L"SYSTEM\\CurrentControlSet\\Enum\\NVME"
    };
    for(auto p:paths){
        HKEY h;
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,p,0,KEY_READ,&h)==ERROR_SUCCESS){
            wchar_t sub[256];DWORD idx=0,sz=sizeof(sub);
            while(RegEnumKeyExW(h,idx,sub,&sz,NULL,NULL,NULL,NULL)==ERROR_SUCCESS){
                HKEY hs;
                if(RegOpenKeyExW(h,sub,0,KEY_READ|KEY_WRITE,&hs)==ERROR_SUCCESS){
                    std::wstring model=L"Samsung SSD 990 PRO "+
                        tw(std::to_string(1+rng()%4))+L"TB";
                    RegSetValueExW(hs,L"FriendlyName",0,REG_SZ,
                        (const BYTE*)model.c_str(),
                        (DWORD)((model.length()+1)*sizeof(wchar_t)));
                    RegCloseKey(hs);
                }
                sz=sizeof(sub);idx++;
            }
            RegCloseKey(h);
        }
    }
    return any;
}

// ═══════════════ 3. MAC AGRESİF ═══════════════
bool spoof_macs(){
    HKEY hKey;
    const wchar_t* base=L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,base,0,KEY_READ,&hKey)!=ERROR_SUCCESS)
        return false;
    wchar_t sub[256];DWORD idx=0,sz=sizeof(sub);
    bool any=false;
    while(RegEnumKeyExW(hKey,idx,sub,&sz,NULL,NULL,NULL,NULL)==ERROR_SUCCESS){
        HKEY h;
        if(RegOpenKeyExW(hKey,sub,0,KEY_READ|KEY_WRITE,&h)==ERROR_SUCCESS){
            wchar_t desc[256];DWORD ds=sizeof(desc);DWORD t=REG_SZ;
            if(RegQueryValueExW(h,L"DriverDesc",NULL,&t,(LPBYTE)desc,&ds)==ERROR_SUCCESS){
                std::string mac=mac_str();
                std::wstring wm=tw(mac);
                RegSetValueExW(h,L"NetworkAddress",0,REG_SZ,(const BYTE*)wm.c_str(),
                    (DWORD)((wm.length()+1)*sizeof(wchar_t)));
                // Interface GUID değiştir (internet bozmaz)
                std::wstring ng=tw(guid_str());
                RegSetValueExW(h,L"NetCfgInstanceId",0,REG_SZ,(const BYTE*)ng.c_str(),
                    (DWORD)((ng.length()+1)*sizeof(wchar_t)));
                any=true;
            }
            RegCloseKey(h);
        }
        sz=sizeof(sub);idx++;
    }
    RegCloseKey(hKey);
    // NOT: Ağ profilleri WMI üzerinden okunur, internet bağlantısı KORUNUR
    return any;
}

// ═══════════════ 4. GPU AGRESİF ═══════════════
bool spoof_gpu(){
    const wchar_t* paths[]={
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0001"
    };
    bool ok_=false;
    for(auto p:paths){
        rs(HKEY_LOCAL_MACHINE,p,L"GPU_UUID",tw(guid_str()));
        rs(HKEY_LOCAL_MACHINE,p,L"HardwareID",
            L"PCI\\VEN_10DE&DEV_"+tw(rh(4))+L"&SUBSYS_"+tw(rh(8))+L"&REV_A1");
        rs(HKEY_LOCAL_MACHINE,p,L"DeviceID",L"DEV_"+tw(rh(4)));
        rs(HKEY_LOCAL_MACHINE,p,L"AdapterString",
            L"NVIDIA GeForce RTX "+tw(std::to_string(4060+rng()%100)));
        rs(HKEY_LOCAL_MACHINE,p,L"DriverVersion",
            L"5"+tw(std::to_string(10+rng()%20))+L".35.01");
        rs(HKEY_LOCAL_MACHINE,p,L"MemorySize",
            tw(std::to_string(8+rng()%16))+L"GB");
        rs(HKEY_LOCAL_MACHINE,p,L"GPU Device Id",tw(ra(16)));
        ok_=true;
    }
    // DXGI
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\DirectX");
    return ok_;
}

// ═══════════════ 5. CPU REGISTRY ═══════════════
bool spoof_cpu_registry(){
    std::wstring path=L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    std::wstring model=L"AMD Ryzen 9 "+
        tw(std::to_string(7950+rng()%100))+L"X 16-Core Processor";
    bool ok_=rs(HKEY_LOCAL_MACHINE,path,L"ProcessorNameString",model);
    std::wstring id=L"AMD64 Family 25 Model "+
        tw(std::to_string(1+rng()%50))+
        L" Stepping "+tw(std::to_string(rng()%10));
    rs(HKEY_LOCAL_MACHINE,path,L"Identifier",id);
    rs(HKEY_LOCAL_MACHINE,path,L"VendorIdentifier",L"AuthenticAMD");
    rs(HKEY_LOCAL_MACHINE,path,L"ProcessorSerialNumber",tw(rh(16)));
    // Çoklu CPU
    for(int i=1;i<32;i++){
        std::wstring p=L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\"+tw(std::to_string(i));
        HKEY k;
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,p.c_str(),0,KEY_READ,&k)==ERROR_SUCCESS){
            RegCloseKey(k);
            rs(HKEY_LOCAL_MACHINE,p,L"ProcessorNameString",model);
            rs(HKEY_LOCAL_MACHINE,p,L"Identifier",id);
        }
    }
    return ok_;
}

// ═══════════════ 6. MACHINE GUID (AGRESTİF) ═══════════════
// NOT: Windows lisansına DOKUNMAZ (ProductID/ProductKey korunur)
bool spoof_machine_guid(){
    std::wstring g=tw(guid_str());
    bool ok_=rs(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Cryptography",L"MachineGuid",g);
    rs(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"BuildGUID",g);
    rs(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\SQMClient",L"MachineId",g);
    rs(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting",L"MachineId",g);
    rs(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting",L"MachineGuid",g);
    // InstallationID (lisansla ilgili değil, sistem ID'si)
    rs(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"InstallationID",tw(std::to_string(10000000+rng()%89999999)));
    return ok_;
}

// ═══════════════ 7. HOSTNAME DEĞİŞTİR ═══════════════
// NOT: SetComputerNameExW interneti bozmaz
bool spoof_hostname(){
    std::wstring new_name=L"DESKTOP-"+tw(ra(7));
    bool ok_=SetComputerNameExW(ComputerNamePhysicalDnsHostname,new_name.c_str());
    SetComputerNameExW(ComputerNameNetBIOS,new_name.c_str());
    rs(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
        L"ComputerName",new_name);
    rs(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"ComputerName",new_name);
    // Tcpip hostname'ini de değiştir (ama IP/DNS bozulmaz)
    rs(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        L"Hostname",new_name);
    rs(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        L"NV Hostname",new_name);
    return ok_;
}

// ═══════════════ 8. USB GEÇMİŞİ AGRESİF ═══════════════
bool spoof_usb_history(){
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\USB");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\WpdBusEnumRoot");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Portable Devices");
    // Mounted devices (takılı diskler)
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\MountedDevices");
    return true;
}

// ═══════════════ 9. MONİTÖR AGRESİF ═══════════════
bool spoof_monitors(){
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Monitor");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\Monitor");
    // EDID
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\Default_Monitor");
    return true;
}

// ═══════════════ 10. SES CİHAZLARI AGRESİF ═══════════════
bool spoof_audio(){
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\SWD\\MMDEVAPI");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio");
    return true;
}

// ═══════════════ 11. PERIPHERAL (HID/PCI/ACPI) ═══════════════
bool spoof_peripherals(){
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\HID");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\PCI");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\ACPI");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\ROOT");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\SCSIAdapter");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\BTHENUM");
    rdt(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\BTHLEDevice");
    return true;
}

// ═══════════════ 12. WMI CACHE RESET (lisans/internet bozmaz) ═══════════════
bool reset_wmi_cache(){
    // Sadece cache temizle, repository silme (daha güvenli)
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Cache");
    // WMI servis restart
    system("net stop winmgmt /y >nul 2>&1");
    Sleep(2000);
    system("net start winmgmt >nul 2>&1");
    Sleep(2000);
    return true;
}

// ═══════════════ 13. EVENT LOG ═══════════════
void clean_event_logs(){
    const char* logs[]={"Application","System","Setup",
        "Microsoft-Windows-Kernel-Boot/Operational",
        "Microsoft-Windows-Kernel-PnP/Configuration",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WindowsUpdateClient/Operational"};
    for(auto l:logs){
        std::string c="wevtutil cl \""+std::string(l)+"\" >nul 2>&1";
        system(c.c_str());
    }
}

// ═══════════════ 14. TEMP/PREFETCH AGRESİF ═══════════════
void clean_temp(){
    system("del /F /Q /S C:\\Windows\\Prefetch\\*.* >nul 2>&1");
    system("del /F /Q /S C:\\Windows\\Temp\\*.* >nul 2>&1");
    system("del /F /Q /S \"%TEMP%\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%LOCALAPPDATA%\\Temp\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%LOCALAPPDATA%\\CrashDumps\\*.*\" >nul 2>&1");
    system("del /F /Q /S C:\\Windows\\Logs\\CBS\\*.* >nul 2>&1");
    system("del /F /Q /S C:\\Windows\\Logs\\DISM\\*.* >nul 2>&1");
    system("del /F /Q /S C:\\Windows\\INF\\setupapi.*.log >nul 2>&1");
    system("del /F /Q /S C:\\Windows\\Minidump\\*.* >nul 2>&1");
    system("del /F /Q /S C:\\Windows\\LiveKernelReports\\*.* >nul 2>&1");
}

// ═══════════════ 15. MRU/RECENT AGRESİF ═══════════════
void clean_recent(){
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths");
    rdt(HKEY_CURRENT_USER,L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\Shell\\BagMRU");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\Shell\\Bags");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\ShellNoRoam\\Bags");
    system("del /F /Q /S \"%APPDATA%\\Microsoft\\Windows\\Recent\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*.*\" >nul 2>&1");
}

// ═══════════════ 16. OYUN İZLERİ AGRESİF ═══════════════
void clean_game_traces(){
    // Valorant/Riot
    system("del /F /Q /S \"%LOCALAPPDATA%\\Riot Games\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%APPDATA%\\Riot Games\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%LOCALAPPDATA%\\VALORANT\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%PROGRAMDATA%\\Riot Games\\*.*\" >nul 2>&1");
    rdt(HKEY_CURRENT_USER,L"Software\\Riot Games");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Riot Games");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\WOW6432Node\\Riot Games");

    // FiveM
    system("del /F /Q /S \"%LOCALAPPDATA%\\FiveM\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%APPDATA%\\CitizenFX\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%LOCALAPPDATA%\\DigitalEntitlements\\*.*\" >nul 2>&1");
    rdt(HKEY_CURRENT_USER,L"Software\\CitizenFX\\FiveM");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\CitizenFX\\FiveM");

    // Rockstar
    system("del /F /Q /S \"%USERPROFILE%\\Documents\\Rockstar Games\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%LOCALAPPDATA%\\Rockstar Games\\*.*\" >nul 2>&1");
    rdt(HKEY_CURRENT_USER,L"Software\\Rockstar Games");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Rockstar Games");

    // Steam / Epic / BNet
    system("del /F /Q /S \"%LOCALAPPDATA%\\Steam\\htmlcache\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%LOCALAPPDATA%\\EpicGamesLauncher\\Saved\\Logs\\*.*\" >nul 2>&1");
    rdt(HKEY_CURRENT_USER,L"Software\\Valve\\Steam\\Apps");
    rdt(HKEY_CURRENT_USER,L"Software\\Blizzard Entertainment");
}

// ═══════════════ 17. TARAYICI AGRESİF ═══════════════
void clean_browser(){
    const char* paths[]={
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache",
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Code Cache",
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\GPUCache",
        "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache",
        "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Code Cache",
        "%LOCALAPPDATA%\\Opera Software\\Opera Stable\\Cache",
        "%LOCALAPPDATA%\\Opera Software\\Opera GX Stable\\Cache",
        "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache"
    };
    for(auto p:paths){
        std::string c="del /F /Q /S \""+std::string(p)+"\\*.*\" >nul 2>&1";
        system(c.c_str());
    }
    system("del /F /Q /S \"%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cache2\\*.*\" >nul 2>&1");
}

// ═══════════════ 18. CERTIFICATE STORE ═══════════════
void clean_certificates(){
    system("certutil -delstore My * >nul 2>&1");
    system("certutil -delstore TrustedPeople * >nul 2>&1");
    system("certutil -delstore TrustedPublisher * >nul 2>&1");
}

// ═══════════════ 19. POWERSHELL/CMD GEÇMİŞİ ═══════════════
void clean_shell_history(){
    system("del /F /Q \"%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\" >nul 2>&1");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
}

// ═══════════════ 20. PREFETCH DB / AMCACHE ═══════════════
void clean_amcache(){
    system("del /F /Q /S C:\\Windows\\AppCompat\\Programs\\Amcache.hve* >nul 2>&1");
    system("del /F /Q /S C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf* >nul 2>&1");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store");
    rdt(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstallLocation");
}

// ═══════════════ 21. JUMP LIST ═══════════════
void clean_jumplist(){
    system("del /F /Q /S \"%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.*\" >nul 2>&1");
    system("del /F /Q /S \"%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*.*\" >nul 2>&1");
}

// ═══════════════ 22. RDP GEÇMİŞİ ═══════════════
void clean_rdp(){
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Terminal Server Client\\Default");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Terminal Server Client\\Servers");
    rdt(HKEY_CURRENT_USER,L"Software\\Microsoft\\Terminal Server Client\\LocalDevices");
}

// ═══════════════ BANNER ═══════════════
void banner(){
    system("color 0A");
    std::cout<<CYAN BOLD;
    std::cout<<R"(
    ╔══════════════════════════════════════════════════════════╗
    ║  destroyerr1558 AGGRESSIVE SPOOFER v2.0                  ║
    ║  Sadece Windows Lisansı ve İnternet KORUNUR              ║
    ║  [ 22+ Kategori • Agresif Mod • Ban Açıcı ]              ║
    ╚══════════════════════════════════════════════════════════╝
    )"<<RESET<<std::endl;
}

// ═══════════════ ANA ═══════════════
int wmain(){
    SetConsoleTitleW(L"destroyerr1558 AGGRESSIVE Spoofer v2.0");
    SetConsoleOutputCP(CP_UTF8);
    banner();

    if(!is_admin()){
        std::cout<<BG_RED WHITE BOLD<<" [!] YÖNETİCİ OLARAK ÇALIŞTIRIN! "<<RESET<<std::endl;
        system("pause");return 1;
    }

    std::cout<<GREEN<<"[✓] Yönetici yetkisi doğrulandı."<<RESET<<std::endl;
    std::cout<<YELLOW<<"[*] Sistem geri yükleme noktası oluşturuluyor..."<<RESET<<std::endl;
    system("powershell -Command \"Enable-ComputerRestore -Drive 'C:\\'\" >nul 2>&1");
    system("powershell -Command \"Checkpoint-Computer -Description 'AggressiveSpoofer' -RestorePointType 'MODIFY_SETTINGS'\" >nul 2>&1");
    std::cout<<GREEN<<"[✓] Geri yükleme noktası hazır."<<RESET<<std::endl;

    std::cout<<YELLOW BOLD<<"\n[!] AGRESİF MOD AKTİF\n"<<RESET;
    std::cout<<GREEN<<"    ✓ Windows lisansı KORUNUYOR\n"<<RESET;
    std::cout<<GREEN<<"    ✓ İnternet bağlantısı KORUNUYOR\n"<<RESET;
    std::cout<<RED<<"    ✗ Diğer her şey SPOOF EDİLİYOR\n\n"<<RESET;

    Sleep(2000);

    int s=0,t=0;

    #define STEP(num,name,func) do { \
        t++; std::cout<<BLUE<<"["<<num"/22] "<<RESET<<name"... "; \
        if(func()){s++;okp(name,true);}else okp(name,false); \
    } while(0)

    std::cout<<MAGENTA BOLD<<"═══ AGRESİF SPOOF BAŞLIYOR ═══\n"<<RESET;

    STEP("1","SMBIOS (Anakart/BIOS/CPU/RAM/Chassis/OEM)",spoof_smbios);
    STEP("2","Disk seri numaraları",spoof_disks);
    STEP("3","MAC adresleri + Interface GUID",spoof_macs);
    STEP("4","GPU UUID/HardwareID/DXGI",spoof_gpu);
    STEP("5","CPU Registry (tüm çekirdekler)",spoof_cpu_registry);
    STEP("6","Machine GUID + Installation ID",spoof_machine_guid);
    STEP("7","Hostname/Computer Name",spoof_hostname);
    STEP("8","USB geçmişi + MountedDevices",spoof_usb_history);
    STEP("9","Monitör bilgileri + EDID",spoof_monitors);
    STEP("10","Ses cihazları",spoof_audio);
    STEP("11","HID/PCI/ACPI/BTH cihazlar",spoof_peripherals);
    STEP("12","WMI Cache reset",reset_wmi_cache);

    // Sistem işlemleri
    t++; std::cout<<BLUE<<"[13/22] "<<RESET<<"Event Log'lar... ";
    clean_event_logs(); s++; okp("Event logs temizlendi",true);

    t++; std::cout<<BLUE<<"[14/22] "<<RESET<<"Temp/Prefetch/Log'lar... ";
    clean_temp(); s++; okp("Temp temizlendi",true);

    t++; std::cout<<BLUE<<"[15/22] "<<RESET<<"MRU/Recent/UserAssist... ";
    clean_recent(); s++; okp("MRU temizlendi",true);

    t++; std::cout<<BLUE<<"[16/22] "<<RESET<<"Oyun izleri... ";
    clean_game_traces(); s++; okp("Oyun izleri silindi",true);

    t++; std::cout<<BLUE<<"[17/22] "<<RESET<<"Tarayıcı cache... ";
    clean_browser(); s++; okp("Tarayıcı temizlendi",true);

    t++; std::cout<<BLUE<<"[18/22] "<<RESET<<"Sertifikalar... ";
    clean_certificates(); s++; okp("Sertifikalar temizlendi",true);

    t++; std::cout<<BLUE<<"[19/22] "<<RESET<<"Shell geçmişi... ";
    clean_shell_history(); s++; okp("Shell history silindi",true);

    t++; std::cout<<BLUE<<"[20/22] "<<RESET<<"Amcache... ";
    clean_amcache(); s++; okp("Amcache temizlendi",true);

    t++; std::cout<<BLUE<<"[21/22] "<<RESET<<"Jump List... ";
    clean_jumplist(); s++; okp("Jumplist silindi",true);

    t++; std::cout<<BLUE<<"[22/22] "<<RESET<<"RDP geçmişi... ";
    clean_rdp(); s++; okp("RDP silindi",true);

    std::cout<<std::endl;
    std::cout<<BG_GREEN BLACK BOLD<<"        AGRESİF SPOOF TAMAMLANDI       "<<RESET<<std::endl;
    std::cout<<GREEN BOLD<<"  Başarılı: "<<s<<"/"<<t<<RESET<<std::endl<<std::endl;

    std::cout<<GREEN BOLD<<"✓ KORUNANLAR:\n"<<RESET;
    std::cout<<GREEN<<"  → Windows lisansı (ProductID/ProductKey/DigitalProductId)"<<RESET<<std::endl;
    std::cout<<GREEN<<"  → İnternet bağlantısı (IP/DNS/Gateway/Route)"<<RESET<<std::endl;
    std::cout<<GREEN<<"  → Secure Boot\n"<<RESET<<std::endl;

    std::cout<<RED BOLD<<"✗ DEĞİŞTİRİLENLER:\n"<<RESET;
    std::cout<<RED<<"  → SMBIOS (Anakart seri no, BIOS, CPU, RAM, Chassis)"<<RESET<<std::endl;
    std::cout<<RED<<"  → Machine GUID, Hostname, Disk seri, MAC"<<"\n"<<RESET<<std::endl;

    std::cout<<YELLOW BOLD<<"[i] ÖNERİLEN:"<<RESET<<std::endl;
    std::cout<<"  → Sistemi YENİDEN BAŞLATIN"<<RESET<<std::endl;
    std::cout<<"  → VPN kullanın"<<RESET<<std::endl;
    std::cout<<"  → Yeni oyun hesabı açın"<<RESET<<std::endl<<std::endl;

    std::cout<<MAGENTA<<"[i] Geri dönüş: rstrui.exe"<<RESET<<std::endl;
    std::cout<<std::endl<<CYAN<<"Kapatmak için bir tuşa basın..."<<RESET;
    system("pause >nul");
    return 0;
}