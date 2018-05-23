//*****************************************************************************
// FILE:            WinMTRNet.cpp
//
//*****************************************************************************
#include "WinMTRGlobal.h"
#include "WinMTRNet.h"
#include "WinMTRDialog.h"
#include <iostream>
#include <sstream>

#ifdef _DEBUG
#	define TRACE_MSG(msg)										\
	{															\
		std::ostringstream dbg_msg(std::ostringstream::out);	\
		dbg_msg << msg << std::endl;							\
		OutputDebugString(dbg_msg.str().c_str());				\
	}
#else
#	define TRACE_MSG(msg)
#endif

#define IPFLAG_DONT_FRAGMENT	0x02
#define MAX_HOPS				30

struct trace_thread {
	WinMTRNet*	winmtr;
	in_addr		address;
	int			ttl;
};
struct trace_thread6 {
	WinMTRNet*		winmtr;
	sockaddr_in6	address;
	int				ttl;
};

struct dns_resolver_thread {
	WinMTRNet*	winmtr;
	int			index;
};

unsigned WINAPI TraceThread(void* p);
unsigned WINAPI TraceThread6(void* p);
void DnsResolverThread(void* p);

WinMTRNet::WinMTRNet(WinMTRDialog* wp)
{

	ghMutex = CreateMutex(NULL, FALSE, NULL);
	hasIPv6=true;
	tracing=false;
	initialized = false;
	wmtrdlg = wp;
	WSADATA wsaData;

	if(WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		AfxMessageBox("Failed initializing windows sockets library!");
		return;
	}
	OSVERSIONINFOEX osvi= {0};
	osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	if(!GetVersionEx((OSVERSIONINFO*) &osvi)) {
		AfxMessageBox("Failed to get Windows version!");
		return;
	}
	if(osvi.dwMajorVersion==5 && osvi.dwMinorVersion==0) { //w2k
		hICMP_DLL=LoadLibrary(_T("ICMP.DLL"));
		if(!hICMP_DLL) {
			AfxMessageBox("Failed: Unable to locate ICMP.DLL!");
			return;
		}
	} else {
		hICMP_DLL=LoadLibrary(_T("Iphlpapi.dll"));
		if(!hICMP_DLL) {
			AfxMessageBox("Failed: Unable to locate Iphlpapi.dll!");
			return;
		}
	}

	/*
	 * Get pointers to ICMP.DLL functions
	 */
	//IPv4
	lpfnIcmpCreateFile  = (LPFNICMPCREATEFILE)GetProcAddress(hICMP_DLL,"IcmpCreateFile");
	lpfnIcmpCloseHandle = (LPFNICMPCLOSEHANDLE)GetProcAddress(hICMP_DLL,"IcmpCloseHandle");
	lpfnIcmpSendEcho2   = (LPFNICMPSENDECHO2)GetProcAddress(hICMP_DLL,"IcmpSendEcho2");
	if(!lpfnIcmpCreateFile || !lpfnIcmpCloseHandle || !lpfnIcmpSendEcho2) {
		AfxMessageBox("Wrong ICMP system library !");
		return;
	}
	//IPv6
	lpfnIcmp6CreateFile=(LPFNICMP6CREATEFILE)GetProcAddress(hICMP_DLL,"Icmp6CreateFile");
	lpfnIcmp6SendEcho2=(LPFNICMP6SENDECHO2)GetProcAddress(hICMP_DLL,"Icmp6SendEcho2");
	if(!lpfnIcmp6CreateFile || !lpfnIcmp6SendEcho2) {
		hasIPv6=false;
		AfxMessageBox("IPv6 support not found!");
		return;//@todo : soft fail
	}

	/*
	 * IcmpCreateFile() - Open the ping service
	 */
	hICMP = (HANDLE) lpfnIcmpCreateFile();
	if(hICMP == INVALID_HANDLE_VALUE) {
		AfxMessageBox("Error in ICMP module!");
		return;
	}
	if(hasIPv6) {
		hICMP6=(HANDLE)lpfnIcmp6CreateFile();
		if(hICMP6==INVALID_HANDLE_VALUE) {
			AfxMessageBox("Error in ICMPv6 module!");
			return;//@todo : soft fail
		}
	}

	ResetHops();

	initialized = true;
	return;
}

WinMTRNet::~WinMTRNet()
{
	if(initialized) {
		/*
		 * IcmpCloseHandle - Close the ICMP handle
		 */
		if(hasIPv6) lpfnIcmpCloseHandle(hICMP6);
		lpfnIcmpCloseHandle(hICMP);

		// Shut down...
		FreeLibrary(hICMP_DLL);

		WSACleanup();

		CloseHandle(ghMutex);
	}
}

void WinMTRNet::ResetHops()
{
	memset(host,0,sizeof(host));
}

void WinMTRNet::DoTrace(sockaddr* sockaddr)
{
	HANDLE hThreads[MAX_HOPS];
	unsigned char hops=0;
	tracing = true;
	ResetHops();
	if(sockaddr->sa_family==AF_INET6) {
		host[0].addr6.sin6_family=AF_INET6;
		last_remote_addr6=((sockaddr_in6*)sockaddr)->sin6_addr;
		for(; hops<MAX_HOPS;) {// one thread per TTL value
			trace_thread6* current=new trace_thread6;
			current->address=*(sockaddr_in6*)sockaddr;
			current->winmtr=this;
			current->ttl=hops+1;
			hThreads[hops]=(HANDLE)_beginthreadex(NULL,0,TraceThread6,current,0,NULL);
			Sleep(30);
			if(++hops>this->GetMax()) break;
		}
	} else {
		host[0].addr.sin_family=AF_INET;
		last_remote_addr=((sockaddr_in*)sockaddr)->sin_addr;
		for(; hops<MAX_HOPS;) {// one thread per TTL value
			trace_thread* current=new trace_thread;
			current->address=((sockaddr_in*)sockaddr)->sin_addr;
			current->winmtr=this;
			current->ttl=hops+1;
			hThreads[hops]=(HANDLE)_beginthreadex(NULL,0,TraceThread,current,0,NULL);
			Sleep(30);
			if(++hops>this->GetMax()) break;
		}
	}
	WaitForMultipleObjects(hops, hThreads, TRUE, INFINITE);
	for(; hops;) CloseHandle(hThreads[--hops]);
}

void WinMTRNet::StopTrace()
{
	tracing = false;
}

unsigned WINAPI TraceThread(void* p)
{
	trace_thread* current = (trace_thread*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " started.");

	IPINFO			stIPInfo, *lpstIPInfo;
	char			achReqData[8192];
	WORD			nDataLen = wmtrnet->wmtrdlg->pingsize;
	union {
		ICMP_ECHO_REPLY icmp_echo_reply;
		char achRepData[sizeof(ICMPECHO)+8192];
	};

	lpstIPInfo				= &stIPInfo;
	stIPInfo.Ttl			= (UCHAR)current->ttl;
	stIPInfo.Tos			= 0;
	stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
	stIPInfo.OptionsSize	= 0;
	stIPInfo.OptionsData	= NULL;
	for(int i=0; i<nDataLen; ++i) achReqData[i]=32;//whitespaces
	while(wmtrnet->tracing) {
		// For some strange reason, ICMP API is not filling the TTL for icmp echo reply
		// Check if the current thread should be closed
		if(current->ttl > wmtrnet->GetMax()) break;
		// NOTE: some servers does not respond back everytime, if TTL expires in transit; e.g. :
		// ping -n 20 -w 5000 -l 64 -i 7 www.chinapost.com.tw  -> less that half of the replies are coming back from 219.80.240.93
		// but if we are pinging ping -n 20 -w 5000 -l 64 219.80.240.93  we have 0% loss
		// A resolution would be:
		// - as soon as we get a hop, we start pinging directly that hop, with a greater TTL
		// - a drawback would be that, some servers are configured to reply for TTL transit expire, but not to ping requests, so,
		// for these servers we'll have 100% loss
		DWORD dwReplyCount = wmtrnet->lpfnIcmpSendEcho2(wmtrnet->hICMP, 0,NULL,NULL, current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), ECHO_REPLY_TIMEOUT);
		wmtrnet->AddXmit(current->ttl - 1);
		if(dwReplyCount) {
			TRACE_MSG("TTL " << (int)current->ttl << " reply TTL " << (int)icmp_echo_reply.Options.Ttl << " Status " << icmp_echo_reply.Status << " Reply count " << dwReplyCount);
			switch(icmp_echo_reply.Status) {
			case IP_SUCCESS:
			case IP_TTL_EXPIRED_TRANSIT:
				wmtrnet->UpdateRTT(current->ttl - 1, icmp_echo_reply.RoundTripTime);
				wmtrnet->AddReturned(current->ttl - 1);
				wmtrnet->SetAddr(current->ttl - 1, icmp_echo_reply.Address);
				break;
			default:
				wmtrnet->SetErrorName(current->ttl - 1, icmp_echo_reply.Status);
			}
			if((DWORD)(wmtrnet->wmtrdlg->interval * 1000) > icmp_echo_reply.RoundTripTime)
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000) - icmp_echo_reply.RoundTripTime);
		} else {
			DWORD err=GetLastError();
			wmtrnet->SetErrorName(current->ttl - 1, err);
			switch(err) {
			case IP_REQ_TIMED_OUT: break;
			default:
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000));
			}
		}
	}//end loop
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " stopped.");
	delete p;
	return 0;
}

unsigned WINAPI TraceThread6(void* p)
{
	static sockaddr_in6 sockaddrfrom= {AF_INET6,0,0,in6addr_any,0};
	trace_thread6* current = (trace_thread6*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " started.");

	IPINFO			stIPInfo, *lpstIPInfo;
	char			achReqData[8192];
	WORD			nDataLen = wmtrnet->wmtrdlg->pingsize;
	union {
		ICMPV6_ECHO_REPLY icmpv6_echo_reply;
		char achRepData[sizeof(PICMPV6_ECHO_REPLY) + 8192];
	};

	lpstIPInfo				= &stIPInfo;
	stIPInfo.Ttl			= (UCHAR)current->ttl;
	stIPInfo.Tos			= 0;
	stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
	stIPInfo.OptionsSize	= 0;
	stIPInfo.OptionsData	= NULL;
	for(int i=0; i<nDataLen; ++i) achReqData[i]=32;//whitespaces
	while(wmtrnet->tracing) {
		if(current->ttl > wmtrnet->GetMax()) break;
		DWORD dwReplyCount = wmtrnet->lpfnIcmp6SendEcho2(wmtrnet->hICMP6, 0,NULL,NULL, &sockaddrfrom, &current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), ECHO_REPLY_TIMEOUT);
		wmtrnet->AddXmit(current->ttl - 1);
		if(dwReplyCount) {
			TRACE_MSG("TTL " << (int)current->ttl << " Status " << icmpv6_echo_reply.Status << " Reply count " << dwReplyCount);
			switch(icmpv6_echo_reply.Status) {
			case IP_SUCCESS:
			case IP_TTL_EXPIRED_TRANSIT:
				wmtrnet->UpdateRTT(current->ttl - 1, icmpv6_echo_reply.RoundTripTime);
				wmtrnet->AddReturned(current->ttl - 1);
				wmtrnet->SetAddr6(current->ttl - 1, icmpv6_echo_reply.Address);
				break;
			default:
				wmtrnet->SetErrorName(current->ttl - 1, icmpv6_echo_reply.Status);
			}
			if((DWORD)(wmtrnet->wmtrdlg->interval * 1000) > icmpv6_echo_reply.RoundTripTime)
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000) - icmpv6_echo_reply.RoundTripTime);
		} else {
			DWORD err=GetLastError();
			wmtrnet->SetErrorName(current->ttl - 1, err);
			switch(err) {
			case IP_REQ_TIMED_OUT: break;
			default:
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000));
			}
		}
	}//end loop
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " stopped.");
	delete p;
	return 0;
}

sockaddr* WinMTRNet::GetAddr(int at)
{
	return (sockaddr*)&host[at].addr;
}

int WinMTRNet::GetName(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(n, host[at].name);
	ReleaseMutex(ghMutex);
	return 0;
}

int WinMTRNet::GetBest(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].best;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetWorst(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].worst;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetAvg(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned == 0 ? 0 : host[at].total / host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetPercent(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = (host[at].xmit == 0) ? 0 : (100 - (100 * host[at].returned / host[at].xmit));
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetLast(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].last;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].xmit;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetMax()
{
	// @todo : improve this (last hop guess)
	WaitForSingleObject(ghMutex, INFINITE);
	int max=0;//first try to find target, if not found, find best guess (doesn't work actually :P)
	if(host[0].addr6.sin6_family==AF_INET6) {
		for(; max<MAX_HOPS && memcmp(&host[max++].addr6.sin6_addr,&last_remote_addr6,sizeof(in6_addr)););
		if(max==MAX_HOPS) {
			while(max>1 && !memcmp(&host[max-1].addr6.sin6_addr,&host[max-2].addr6.sin6_addr,sizeof(in6_addr)) && (host[max-1].addr6.sin6_addr.u.Word[0]|host[max-1].addr6.sin6_addr.u.Word[1]|host[max-1].addr6.sin6_addr.u.Word[2]|host[max-1].addr6.sin6_addr.u.Word[3]|host[max-1].addr6.sin6_addr.u.Word[4]|host[max-1].addr6.sin6_addr.u.Word[5]|host[max-1].addr6.sin6_addr.u.Word[6]|host[max-1].addr6.sin6_addr.u.Word[7])) --max;
		}
	} else {
		for(; max<MAX_HOPS && host[max++].addr.sin_addr.s_addr!=last_remote_addr.s_addr;);
		if(max==MAX_HOPS) {
			while(max>1 && host[max-1].addr.sin_addr.s_addr==host[max-2].addr.sin_addr.s_addr && host[max-1].addr.sin_addr.s_addr) --max;
		}
	}
	ReleaseMutex(ghMutex);
	return max;
}

void WinMTRNet::SetAddr(int at, u_long addr)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(host[at].addr.sin_addr.s_addr==0) {
		TRACE_MSG("Start DnsResolverThread for new address " << addr << ". Old addr value was " << host[at].addr.sin_addr.s_addr);
		host[at].addr.sin_family=AF_INET;
		host[at].addr.sin_addr.s_addr=addr;
		dns_resolver_thread* dnt=new dns_resolver_thread;
		dnt->index=at;
		dnt->winmtr=this;
		if(wmtrdlg->useDNS) _beginthread(DnsResolverThread, 0, dnt);
		else DnsResolverThread(dnt);
	}
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetAddr6(int at, IPV6_ADDRESS_EX addrex)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(!(host[at].addr6.sin6_addr.u.Word[0]|host[at].addr6.sin6_addr.u.Word[1]|host[at].addr6.sin6_addr.u.Word[2]|host[at].addr6.sin6_addr.u.Word[3]|host[at].addr6.sin6_addr.u.Word[4]|host[at].addr6.sin6_addr.u.Word[5]|host[at].addr6.sin6_addr.u.Word[6]|host[at].addr6.sin6_addr.u.Word[7])) {
		TRACE_MSG("Start DnsResolverThread for new address " << addrex.sin6_addr[0] << ". Old addr value was " << host[at].addr6.sin6_addr.u.Word[0]);
		host[at].addr6.sin6_family=AF_INET6;
		host[at].addr6.sin6_addr=*(in6_addr*)&addrex.sin6_addr;
		dns_resolver_thread* dnt=new dns_resolver_thread;
		dnt->index=at;
		dnt->winmtr=this;
		if(wmtrdlg->useDNS) _beginthread(DnsResolverThread,0,dnt);
		else DnsResolverThread(dnt);
	}
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetName(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(host[at].name, n);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetErrorName(int at, DWORD errnum)
{
	const char* name;
	switch(errnum) {
	case IP_BUF_TOO_SMALL:
		name="Reply buffer too small."; break;
	case IP_DEST_NET_UNREACHABLE:
		name="Destination network unreachable."; break;
	case IP_DEST_HOST_UNREACHABLE:
		name="Destination host unreachable."; break;
	case IP_DEST_PROT_UNREACHABLE:
		name="Destination protocol unreachable."; break;
	case IP_DEST_PORT_UNREACHABLE:
		name="Destination port unreachable."; break;
	case IP_NO_RESOURCES:
		name="Insufficient IP resources were available."; break;
	case IP_BAD_OPTION:
		name="Bad IP option was specified."; break;
	case IP_HW_ERROR:
		name="Hardware error occurred."; break;
	case IP_PACKET_TOO_BIG:
		name="Packet was too big."; break;
	case IP_REQ_TIMED_OUT:
		name="Request timed out."; break;
	case IP_BAD_REQ:
		name="Bad request."; break;
	case IP_BAD_ROUTE:
		name="Bad route."; break;
	case IP_TTL_EXPIRED_REASSEM:
		name="The time to live expired during fragment reassembly."; break;
	case IP_PARAM_PROBLEM:
		name="Parameter problem."; break;
	case IP_SOURCE_QUENCH:
		name="Datagrams are arriving too fast to be processed and datagrams may have been discarded."; break;
	case IP_OPTION_TOO_BIG:
		name="An IP option was too big."; break;
	case IP_BAD_DESTINATION:
		name="Bad destination."; break;
	case IP_GENERAL_FAILURE:
		name="General failure."; break;
	default:
		TRACE_MSG("==UNKNOWN ERROR== " << errnum);
		name="Unknown error! (please report)"; break;
	}
	WaitForSingleObject(ghMutex, INFINITE);
	if(!*host[at].name)
		strcpy(host[at].name,name);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::UpdateRTT(int at, int rtt)
{
	WaitForSingleObject(ghMutex, INFINITE);
	host[at].last=rtt;
	host[at].total+=rtt;
	if(host[at].best>rtt || host[at].xmit==1)
		host[at].best=rtt;
	if(host[at].worst<rtt)
		host[at].worst=rtt;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].returned;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].xmit;
	ReleaseMutex(ghMutex);
}

typedef unsigned char byte;
typedef unsigned int uint;
#define B2IL(b) (((b)[0] & 0xFF) | (((b)[1] << 8) & 0xFF00) | (((b)[2] << 16) & 0xFF0000) | (((b)[3] << 24) & 0xFF000000))
#define B2IU(b) (((b)[3] & 0xFF) | (((b)[2] << 8) & 0xFF00) | (((b)[1] << 16) & 0xFF0000) | (((b)[0] << 24) & 0xFF000000))

struct {
    byte *data;
    byte *index;
    uint *flag;
    uint offset;
} ipip;

static int ipipdb_destroy() {
    if (!ipip.offset) {
        return 0;
    }
    free(ipip.flag);
    free(ipip.index);
    free(ipip.data);
    ipip.offset = 0;
    return 0;
}

static int ipipdb_init() {
    if (ipip.offset) {
        return 0;
    }

    FILE *file;
	HMODULE hModule = GetModuleHandle(NULL);
	TCHAR path[MAX_PATH];
	GetModuleFileName(hModule, path, MAX_PATH);
	PathRemoveFileSpec(path);
	PathAppend(path, _T("17monipdb.datx"));
	file = _tfopen(path, _T("rb"));
	if (!file) {
		file = _tfopen(_T("17monipdb.datx"), _T("rb"));
	}
	if (!file) {
		return 0;
	}
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    ipip.data = (byte *) malloc(size * sizeof(byte));
    size_t r = fread(ipip.data, sizeof(byte), (size_t) size, file);

    if (r == 0) {
        return 0;
    }

    fclose(file);

    uint length = B2IU(ipip.data);

    ipip.index = (byte *) malloc(length * sizeof(byte));
    memcpy(ipip.index, ipip.data + 4, length);

    ipip.offset = length;

    ipip.flag = (uint *) malloc(65536 * sizeof(uint));
    memcpy(ipip.flag, ipip.index, 65536 * sizeof(uint));

    return 0;
}

static int ipipdb_find(const uint ip, char *result) {
    uint ip_prefix_value = (ip & 0xFF000000) >> 24;
    uint start = ipip.flag[ip_prefix_value];
    uint max_comp_len = ipip.offset - 262144 - 4;
    uint index_offset = 0;
    uint index_length = 0;
    for (start = start * 9 + 262144; start < max_comp_len; start += 9) {
        if (B2IU(ipip.index + start) >= ip) {
            index_offset = B2IL(ipip.index + start + 4) & 0x00FFFFFF;
            index_length = (ipip.index[start + 7] << 8) + ipip.index[start + 8];
            break;
        }
    }
    memcpy(result, ipip.data + ipip.offset + index_offset - 262144, index_length);
    result[index_length] = '\0';
	int seeker = 0;
    for (int i = 0; i < index_length; i++) {
        if (result[i] == '\t') {
			result[i] = ' ';
			seeker++;
			if (seeker == 5) {
				result[i] = 0;
			}
        }
    }
    return 0;
}


static wchar_t * change_encoding_from_UTF8_to_UCS2(char *szU8) {
    int wcsLen = ::MultiByteToWideChar(CP_UTF8, NULL, szU8, strlen(szU8), NULL, 0);
    wchar_t* wszString = new wchar_t[wcsLen + 1];
    ::MultiByteToWideChar(CP_UTF8, NULL, szU8, strlen(szU8), wszString, wcsLen);
    wszString[wcsLen] = '\0';
    return wszString;
}

static char* change_encoding_from_UTF8_to_ANSI(char* szU8) {
    wchar_t *wszString = change_encoding_from_UTF8_to_UCS2(szU8);
    int ansiLen = ::WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), NULL, 0, NULL, NULL);
    char* szAnsi = new char[ansiLen + 1];
    ::WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), szAnsi, ansiLen, NULL, NULL);
    szAnsi[ansiLen] = '\0';
    delete[] wszString;
    return szAnsi;
}
static LPCTSTR ipip_get_location(uint ip) {
    ipipdb_init();
    char buf[192];
    buf[0] = '\0';
    strcpy(buf, " [");
    ipipdb_find(ip, buf + 2);
    strcat(buf, "]");
#ifdef _UNICODE
    return change_encoding_from_UTF8_to_UCS2(buf);
#else
    return change_encoding_from_UTF8_to_ANSI(buf);
#endif
}


void DnsResolverThread(void* p)
{
	dns_resolver_thread* dnt=(dns_resolver_thread*)p;
	WinMTRNet* wn=dnt->winmtr;
	char hostname[NI_MAXHOST];
	if(!getnameinfo(wn->GetAddr(dnt->index),sizeof(sockaddr_in6),hostname,NI_MAXHOST,NULL,0,NI_NUMERICHOST)) {
		wn->SetName(dnt->index,hostname);
	}
	if(wn->wmtrdlg->useDNS) {
		TRACE_MSG("DNS resolver thread started.");
		if(!getnameinfo(wn->GetAddr(dnt->index),sizeof(sockaddr_in6),hostname,NI_MAXHOST,NULL,0,0)) {
			wn->SetName(dnt->index,hostname);
		}
		TRACE_MSG("DNS resolver thread stopped.");
	}
	sockaddr *sAddr = wn->GetAddr(dnt->index);
	if (sAddr->sa_family == AF_INET) {
		sockaddr_in *sAddr4 = (sockaddr_in *) sAddr;
		uint realAddr = ntohl(sAddr4->sin_addr.s_addr);
		LPCTSTR ipGeo = ipip_get_location(realAddr);
		_tcscat(hostname, ipGeo);
		delete[] ipGeo;
		wn->SetName(dnt->index,hostname);
	}
	delete p;
}
