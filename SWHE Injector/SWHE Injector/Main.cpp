#include <Windows.h>
#include <iostream>

int main()
{
    const char* Dll_path = "DllWithHook.dll";
    const char* ProcessName = "notepad";

	HWND hwnd = FindWindowA(ProcessName, 0);
	if (!hwnd) {
		std::cout << "[-] Failed to find window!\n";

		return 1;
	}

	DWORD ProcessId = 0;
	DWORD ThreadId = GetWindowThreadProcessId(hwnd, &ProcessId);
	if (!ProcessId || !ThreadId) {
		std::cout << "[-] Failed to find process id or thread id!\n";

		return 1;
	}

	std::cout << "[+] ThreadId: " << ThreadId << std::endl;
	std::cout << "[+] ProcessId: " << ProcessId << std::endl;

	HMODULE Dll = LoadLibraryEx(Dll_path, 0, DONT_RESOLVE_DLL_REFERENCES);
	if (!Dll) {
		std::cout << "[-] Failed to load dll: '" << Dll_path << "' | " << GetLastError();

		return 1;
	}

	HOOKPROC HookAddress = (HOOKPROC)GetProcAddress(Dll, "NextHook");
	if (!HookAddress) {
		std::cout << "[-] Failed to find 'NextHook' in dll: '" << Dll_path << "' | " << GetLastError();

		return 1;
	}

	std::cout << "[+] HookAddress: 0x" << std::hex << HookAddress << std::endl;

	HHOOK HandleHook = SetWindowsHookEx(
		WH_GETMESSAGE,
		HookAddress,
		Dll,
		ThreadId
	);

	if (!HandleHook) {
		std::cout << "[-] Failed to SetWindowsHookEx!\n";

		return 1;
	}

	std::cout << "[+] Hook: 0x" << std::hex << HandleHook << std::endl;

	PostThreadMessage(
		ThreadId,
		WM_NULL,
		0,
		0
	);

	std::cout << "[+] Injected!\n";

    return EXIT_SUCCESS;
}