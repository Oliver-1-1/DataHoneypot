#include <Windows.h>
#include <iostream>
#include <thread>	
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#include <libloaderapi.h>
#pragma comment(lib,"ntdll.lib")


void DoSuspendThread(DWORD targetProcessId, DWORD targetThreadId, BOOL suspend) {
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
					if (te.th32ThreadID != targetThreadId && te.th32OwnerProcessID == targetProcessId) {
						HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						if (thread != NULL) {
							if (suspend) SuspendThread(thread);
							else ResumeThread(thread);
							CloseHandle(thread);
						}
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}
DWORD thread_id = 0;
void routine() {
	HANDLE handle = GetCurrentProcess();
	PROCESS_MEMORY_COUNTERS mem = { 0 };

	//Suspend all threads so we can make sure we are the only thread that can cause a page fault.
	DoSuspendThread(GetCurrentProcessId(), thread_id, 1);

	//Empty all loaded pages in memory. Some pages will directly be loaded into memory again like .text section but the important 
	//part is that we dont access any variable inside .data section. Like thread_id.
	K32EmptyWorkingSet(GetCurrentProcess());

	for (int i = 0; i < 100000000000000; i++) {//xd

		//store the base address the loaded Module
		char* dllImageBase = (char*)GetModuleHandleA(NULL); //suppose hModule is the handle to the loaded Module (.exe or .dll)

		//get the address of NT Header
		auto dos = (PIMAGE_DOS_HEADER)dllImageBase;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
		auto nt = (PIMAGE_NT_HEADERS)((BYTE*)dllImageBase + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return;

		auto section_header = (PIMAGE_SECTION_HEADER)((BYTE*)(&nt->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

		for (auto j = 0; j < nt->FileHeader.NumberOfSections; j++, section_header++) {
			if ((section_header->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) continue;
			//if (execute_only) {
			//	if (!(section_header->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
			//}
			if (!strcmp((const char*)section_header->Name, ".data")) {
				PSAPI_WORKING_SET_EX_INFORMATION working = { 0 };
				working.VirtualAddress = (PVOID)((ULONGLONG)dllImageBase + section_header->VirtualAddress);
				K32QueryWorkingSetEx(GetCurrentProcess(), &working, sizeof(working));
				if (working.VirtualAttributes.Valid) {
					std::cout << "Someone acceseed the page that was not the current process :D" << std::endl;
				}
				//std::cout << working.VirtualAttributes.Valid << std::endl;
			}

		}


	}
	DoSuspendThread(GetCurrentProcessId(), thread_id, 0);


}

//https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex could be used instead. To check valid bit. Much more relaible.
// But i started with this approch i might update this with queryworkingsetex intead.
// 
//How to detect all cs2 anti cheats 101
void main() {

	//Start a thread to isolate the execution.
	std::thread s(&routine);
	std::stringstream ss;
	ss << s.get_id();
	thread_id = std::stoi(ss.str());
	s.join();

}