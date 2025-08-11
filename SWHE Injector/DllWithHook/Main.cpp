#include <Windows.h>
#include <thread>

extern "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, code, wParam, lParam);
}

void MainThread() {
    MessageBoxA(
        0,
        "Injected!",
        "SetWindowsHookEx",
        MB_OK
    );
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        std::thread(MainThread).detach();
    }

    return TRUE;
}