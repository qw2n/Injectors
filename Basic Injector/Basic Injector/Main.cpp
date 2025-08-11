#include <Windows.h>
#include <iostream>

int main() {
	const char* dll = "dll.dll"; // here ur path to dll
	const char* ProcessName = "notepad"; // here ur process name

	HWND hwnd = FindWindowA(ProcessName, 0);
	if (!hwnd) {
		std::cout << "[-] Failed to find process!\n";

		return 1;
	}

	DWORD ProcessId = 0;

	GetWindowThreadProcessId(hwnd, &ProcessId);

	if (!ProcessId) {
		std::cout << "[-] Failed to get ProcessId!\n";

		return 1;
	}

	std::cout << "[+] ProcessId: " << ProcessId << std::endl;

	HANDLE qProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (!qProcess) {
		std::cout << "[-] Failed to open process!\n";

		return 1;
	}

	{
		LPVOID Alloc = VirtualAllocEx(
			qProcess,
			0,
			MAX_PATH,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!Alloc) {
			std::cout << "[-] Failed to allocate memory!\n";

			CloseHandle(qProcess);

			return 1;
		}

		std::cout << "[+] Allocated memory: 0x" << std::hex << Alloc << std::endl;

		if (!WriteProcessMemory(qProcess, Alloc, dll, strlen(dll) + 1, 0)) {
			std::cout << "[-] Failed to write dll into process!\n";

			VirtualFreeEx(qProcess, Alloc, 0, MEM_RELEASE);
			CloseHandle(qProcess);

			return 1;
		}

		HANDLE Thread = CreateRemoteThread(
			qProcess,
			0,
			0,
			(LPTHREAD_START_ROUTINE)LoadLibraryA,
			Alloc,
			0,
			0
		);

		if (!Thread) {
			std::cout << "[-] Failed to create remote thread!\n";

			VirtualFreeEx(qProcess, Alloc, 0, MEM_RELEASE);
			CloseHandle(qProcess);

			return 1;
		}

		std::cout << "[+] Thread: 0x" << std::hex << Thread << std::endl;

		WaitForSingleObject(Thread, INFINITE);

		VirtualFreeEx(qProcess, Alloc, 0, MEM_RELEASE);

		CloseHandle(Thread);
		CloseHandle(qProcess);
	}

	std::cout << "[+] Injected!\n";

	std::system("pause");

	return EXIT_SUCCESS;
}