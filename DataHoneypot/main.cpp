#include <Windows.h>
#include <iostream>
#include <thread>	
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#include <libloaderapi.h>
#pragma comment(lib,"ntdll.lib")

#define PAGE_SIZE  0x1000
#define PAGE_MASK  0xFFF
#define PAGE_SHIFT 12
#define SIZE_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + (((Size) & PAGE_MASK) ? 1 : 0))
#define PAGES_TO_SIZE(Pages) ((Pages) << PAGE_SIZE)

DWORD thread_id = 0;

void suspendThread(DWORD targetProcessId, DWORD targetThreadId, bool suspend) {
	
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
					if (te.th32ThreadID != targetThreadId && te.th32OwnerProcessID == targetProcessId) {
						HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						if (thread) {
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

bool isVAReadable(PVOID virtualAddress) {
	PSAPI_WORKING_SET_EX_INFORMATION w = { 0 };
	w.VirtualAddress = virtualAddress;
	K32QueryWorkingSetEx(GetCurrentProcess(), &w, sizeof(w));

	return w.VirtualAttributes.Valid;
}


void routine() {

	//Suspend all threads so we can make sure we are the only thread that can cause a page fault.
	suspendThread(GetCurrentProcessId(), thread_id, 1);

	//Empty all loaded pages in memory. Some pages will directly be loaded into memory again like .text section but the important 
	//part is that we dont access any variable inside .data section. Like thread_id.
	K32EmptyWorkingSet(GetCurrentProcess());

	//Dont touch any .data varibalbe here
	while (1) {

		char* base = (char*)GetModuleHandleA(NULL);

		auto dos = (PIMAGE_DOS_HEADER)base;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
		auto nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return;

		auto section_header = (PIMAGE_SECTION_HEADER)((BYTE*)(&nt->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

		for (auto j = 0; j < nt->FileHeader.NumberOfSections; j++, section_header++) {
			if (!strcmp((const char*)section_header->Name, ".data")) {
				for (int k = 0; k < SIZE_TO_PAGES(section_header->SizeOfRawData); k++) {
					if (isVAReadable((PVOID)((ULONGLONG)base + section_header->VirtualAddress + k*PAGE_SIZE))) {
						std::cout << "Someone acceseed the page" << std::endl;
						goto End;
					}
				}
	
			}
		}
	}

End:
	suspendThread(GetCurrentProcessId(), thread_id, 0);

}

//How to detect all cs2 cheats 101
void main() {
	//Start a thread to isolate the execution.
	std::thread s(&routine);
	std::stringstream ss;
	ss << s.get_id();
	thread_id = std::stoi(ss.str());
	s.join();
	while (1) {}

}
