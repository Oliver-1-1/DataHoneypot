#include <Windows.h>
#include <iostream>
#include <thread>	
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>

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
	K32EmptyWorkingSet(handle);

	for (int i = 0; i < 10000; i++) {

		K32GetProcessMemoryInfo(handle, &mem, sizeof(PROCESS_MEMORY_COUNTERS));

		//The page faults will instantly settle and be kept at the same count. If no other thread in the process(which is impossible
		//Since we suspended them all. If a process tries to read from the data section with ReadProcessMemory it will be noticed :D.
		//Attaching via cheat engine explodes the page fault count
		std::cout << mem.PageFaultCount << std::endl;
		Sleep(500);
	}
	

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

	while(1){}
}