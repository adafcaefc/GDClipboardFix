#include <Windows.h>
#include <string>

namespace memory {

	template <typename T> void write(DWORD address, T value) {
		*reinterpret_cast<T*>(address) = value;
	}

	BOOL place_jump(DWORD address, DWORD destination_address, DWORD length) {

		DWORD oldProtect, newProtect, relativeAddress;

		if (VirtualProtect((LPVOID)address, length, PAGE_EXECUTE_READWRITE, &oldProtect)) {

			relativeAddress = (DWORD)(destination_address - address) - 5;
			write(address, (BYTE)0xE9);
			write(address + 0x1, relativeAddress);

			for (DWORD i = 0x5; i < length; i++) {
				write(address, (BYTE)0x90);
			}

			return VirtualProtect((LPVOID)address, length, oldProtect, &newProtect);
		}

		return FALSE;

	}

}

DWORD base = (DWORD)GetModuleHandle(0);

DWORD start_clipboard_hook = base + 0x1513A8;
DWORD ret_clipboard_hook = base + 0x1513AE;
DWORD jb_clipboard_hook = base + 0x1513BA;
DWORD clipboard_string_length = 0;
DWORD clipboard_string_position = 0;

char copy_to_clipboard_stored[1024];
DWORD copy_to_clipboard_stored_location = (DWORD)copy_to_clipboard_stored;

void to_clipboard(HWND hwnd, const std::string& s) {

	OpenClipboard(hwnd);
	EmptyClipboard();

	HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, s.size() + 1);

	if (!hg) {
		CloseClipboard();
		return;
	}

	auto dest = GlobalLock(hg);

	if (!dest) {
		CloseClipboard();
		return;
	}

	memcpy(dest, s.c_str(), s.size() + 1);

	GlobalUnlock(hg);

	SetClipboardData(CF_TEXT, hg);
	CloseClipboard();

	GlobalFree(hg);


}

void copy_to_clipboard() {

	__asm {

		pushad
		push ebp
		mov ebp, esp
		mov esi, [copy_to_clipboard_stored_location]
		mov edi, [clipboard_string_position]
		mov ecx, [clipboard_string_length]
		xor ebx, ebx
		start_loop :
		mov al, [edi]
			mov[esi], al
			inc esi
			inc edi
			inc ebx
			cmp ebx, ecx
			jl start_loop
			mov esp, ebp
			pop ebp
			popad

	}

	std::string string_to_copy(copy_to_clipboard_stored, clipboard_string_length);

	to_clipboard(GetDesktopWindow(), string_to_copy);

}

DWORD copy_to_clipboard_location = (DWORD)copy_to_clipboard;

__declspec(naked) void clipboard_hook() {

	__asm {
		pushad
		mov[clipboard_string_length], edx
		mov[clipboard_string_position], eax
		call copy_to_clipboard_location
		popad
		cmp dword ptr[ebp - 0x10], 0x10
		jb jump_point_below
		jmp[ret_clipboard_hook]
		jump_point_below:
		jmp[jb_clipboard_hook]
	}

}

DWORD WINAPI main_hook(LPVOID lpParam) {
	memory::place_jump(start_clipboard_hook, (DWORD)clipboard_hook, 5);
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

	switch (ul_reason_for_call) {

	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0x1000, &main_hook, 0, 0, NULL);

	case DLL_PROCESS_DETACH:
		break;

	}

	return TRUE;

}
