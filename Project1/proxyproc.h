#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <winternl.h>

namespace proxyproc
{
#define SystemHandleInformation 16 
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

#define MAX_DATA_SIZE 0x1000

#define STATUS_WAITING 0
#define STATUS_FINISHED 1
#define STATUS_ERROR 2

	std::string proxy_proc = "lsass.exe";

	using f_OpenProcess = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
	using f_ReadProcessMemory = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
	using f_WriteProcessMemory = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

	using f_RtlAdjustPrivilege = NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
	using f_NtQuerySystemInformation = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

	DWORD proxy_pid, target_pid;

	typedef struct _SYSTEM_HANDLE {
		ULONG ProcessId;
		BYTE ObjectTypeNumber;
		BYTE Flags;
		USHORT Handle;
		PVOID Object;
		ACCESS_MASK GrantedAccess;
	} SYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION {
		ULONG HandleCount;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION;

	HANDLE proxy_handle;
	HANDLE target_handle;
	HMODULE ntdll;

	struct CREATE_HANDLE_DATA
	{
		DWORD pid;
		DWORD status;
		HANDLE out;
		f_OpenProcess pOpenProcess;
	};

	namespace read
	{
		// base for the data that is read from proxy process
		uintptr_t data_base;
	}
	namespace write
	{
		// base for the data that is written from proxy process
		uintptr_t data_base;
	}

	// base for the shellcode that will read data from proxy process
	uintptr_t shellcode_base;
	// base for struct that tells shellcode what to do
	uintptr_t readwrite_data_base;

	HANDLE thread;

	struct READWRITE_DATA
	{
		bool updated;
		bool write;
		HANDLE handle;
		DWORD status;
		size_t size;
		uintptr_t address;
		uintptr_t proxy_data_base;
		f_WriteProcessMemory pWriteProcessMemory;
		f_ReadProcessMemory pReadProcessMemory;
	};

	void __stdcall shellcode_create_handle(CREATE_HANDLE_DATA* data)
	{
		data->out = data->pOpenProcess(PROCESS_ALL_ACCESS, FALSE, data->pid);
		data->status = STATUS_FINISHED;
	}

	void __stdcall shellcode_readwrite_data(READWRITE_DATA* data)
	{
		// no bueno for the cpu :sadbob:
		while (true)
		{
			if (!data->updated)
			{
				continue;
			}

			if (data->write)
			{
				data->status = STATUS_WAITING;
				data->pWriteProcessMemory(data->handle, (LPVOID)data->address, (LPCVOID)data->proxy_data_base, data->size, NULL);
				data->status = STATUS_FINISHED;
			}
			else
			{
				data->status = STATUS_WAITING;
				data->pReadProcessMemory(data->handle, (LPCVOID)data->address, (LPVOID)data->proxy_data_base, data->size, NULL);
				data->status = STATUS_FINISHED;
			}

			data->updated = false;
		}
	}

	DWORD get_process_id(const char* image_name)
	{
		HANDLE hsnap;
		PROCESSENTRY32 pt;
		DWORD PiD;
		hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		do {
			if (!strcmp(pt.szExeFile, image_name)) {
				CloseHandle(hsnap);
				PiD = pt.th32ProcessID;
				return PiD;
			}
		} while (Process32Next(hsnap, &pt));
		return 0;
	}

	void init_readwrite_shellcode()
	{
		if (!readwrite_data_base)
		{
			readwrite_data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, sizeof(READWRITE_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!readwrite_data_base)
				exit(50);

			std::cout << "readwrite data base at 0x" << readwrite_data_base << std::endl;
		}

		if (!shellcode_base)
		{
			shellcode_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (!shellcode_base)
				exit(60);

			std::cout << "shellcode data base at 0x" << shellcode_base << std::endl;

			WriteProcessMemory(proxy_handle, (LPVOID)shellcode_base, shellcode_readwrite_data, 0x1000, NULL);
		}
	}

	bool find_existing_handle()
	{
		ULONG handle_info_size = 0x10000;
		SYSTEM_HANDLE_INFORMATION* handle_info = (SYSTEM_HANDLE_INFORMATION*)malloc(handle_info_size);

		f_NtQuerySystemInformation NtQuerySystemInformation = (f_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

		while (NtQuerySystemInformation(SystemHandleInformation, handle_info, handle_info_size, NULL) == STATUS_INFO_LENGTH_MISMATCH)
		{
			handle_info_size *= 2;
			handle_info = (SYSTEM_HANDLE_INFORMATION*)realloc(handle_info, handle_info_size);
		}

		for (int i = 0; i < handle_info->HandleCount; i++)
		{
			SYSTEM_HANDLE handle = handle_info->Handles[i];
			if (handle.ProcessId == proxy_pid)
			{
				if (handle.ObjectTypeNumber != 7)
					continue;

				HANDLE duplicated_handle = NULL;
				DuplicateHandle(proxy_handle, (HANDLE)handle.Handle, GetCurrentProcess(), &duplicated_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);

				if (GetProcessId(duplicated_handle) != target_pid)
					continue;

				if (handle.GrantedAccess == PROCESS_ALL_ACCESS)
				{
					target_handle = (HANDLE)handle.Handle;
					CloseHandle(duplicated_handle);

					std::cout << "found existing handle: " << target_handle << std::endl;

					break;
				}

				CloseHandle(duplicated_handle);
			}
		}

		free(handle_info);
		return target_handle != 0;
	}

	// creates a handle from "explorer.exe" can also be changed
	void create_handle_in_proxy(const char* image_name)
	{
		ntdll = GetModuleHandleA("ntdll");
		f_RtlAdjustPrivilege RtlAdjustPrivilege = (f_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
		boolean old_priv;
		RtlAdjustPrivilege(20, TRUE, FALSE, &old_priv);

		proxy_pid = get_process_id(proxy_proc.c_str());
		target_pid = get_process_id(image_name);

		std::cout << "proxy_pid: " << proxy_pid << " target_pid: " << target_pid << std::endl;

		proxy_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proxy_pid);

		if (!find_existing_handle())
		{
			std::cout << "no existing handle found, creating new one...\n";

			CREATE_HANDLE_DATA data{ 0 };
			data.pOpenProcess = OpenProcess;
			data.pid = target_pid;
			data.status = STATUS_WAITING;
			data.out = 0;

			uintptr_t create_handle_data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, sizeof(CREATE_HANDLE_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!create_handle_data_base)
				exit(10);
			WriteProcessMemory(proxy_handle, (LPVOID)create_handle_data_base, &data, sizeof(CREATE_HANDLE_DATA), NULL);

			uintptr_t create_handle_shellcode_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (!create_handle_shellcode_base)
				exit(20);
			WriteProcessMemory(proxy_handle, (LPVOID)create_handle_shellcode_base, shellcode_create_handle, 0x1000, NULL);

			HANDLE h = CreateRemoteThread(proxy_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)create_handle_shellcode_base, (LPVOID)create_handle_data_base, NULL, NULL);
			if (h)
				CloseHandle(h);

			DWORD status = STATUS_WAITING;
			while (status == STATUS_WAITING)
			{
				CREATE_HANDLE_DATA data_checked{ 0 };
				ReadProcessMemory(proxy_handle, (LPCVOID)create_handle_data_base, &data_checked, sizeof(CREATE_HANDLE_DATA), NULL);
				status = data_checked.status;
				target_handle = data_checked.out;

				Sleep(30);
			}
		}

		std::cout << std::hex << "proxy_handle: " << proxy_handle << " target_handle: " << target_handle << std::endl;

		init_readwrite_shellcode();
	}

	void cleanup()
	{
		TerminateThread(thread, 0);
	}

	void read_virtual_memory(uintptr_t address, void* buf, size_t size)
	{
		if (!read::data_base)
		{
			read::data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, MAX_DATA_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!read::data_base)
				exit(40);

			std::cout << "proxy data base at 0x" << read::data_base << std::endl;
		}

		READWRITE_DATA data{ 0 };
		data.address = address;
		data.handle = target_handle;
		data.size = size;
		data.status = STATUS_WAITING;
		data.proxy_data_base = read::data_base;
		data.updated = true;
		data.write = false;
		data.pReadProcessMemory = ReadProcessMemory;
		data.pWriteProcessMemory = WriteProcessMemory;

		WriteProcessMemory(proxy_handle, (LPVOID)readwrite_data_base, &data, sizeof(READWRITE_DATA), NULL);

		if (!thread)
		{
			thread = CreateRemoteThread(proxy_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)shellcode_base, (LPVOID)readwrite_data_base, NULL, NULL);
			if (!thread)
				exit(70);
		}

		DWORD status = STATUS_WAITING;
		while (status != STATUS_FINISHED)
		{
			READWRITE_DATA data_checked{ 0 };
			ReadProcessMemory(proxy_handle, (LPCVOID)readwrite_data_base, &data_checked, sizeof(READWRITE_DATA), NULL);
			status = data_checked.status;
			if (status == STATUS_ERROR)
			{
				std::cerr << "error during read_virtual_memory operation!\n";
				exit(100);
			}
		}

		ReadProcessMemory(proxy_handle, (LPCVOID)read::data_base, buf, size, NULL);
	}

	template<typename T>
	T read_virtual_memory(uintptr_t address)
	{
		T out{ 0 };

		if (!address)
			return out;

		read_virtual_memory(address, &out, sizeof(T));

		return out;
	}

	void write_virtual_memory(uintptr_t address, void* buf, size_t size)
	{
		if (!write::data_base)
		{
			write::data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, MAX_DATA_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!write::data_base)
				exit(40);

			std::cout << "proxy data base at 0x" << std::hex << write::data_base << std::endl;
		}

		WriteProcessMemory(proxy_handle, (LPVOID)write::data_base, buf, size, NULL);

		READWRITE_DATA data{ 0 };
		data.address = address;
		data.handle = target_handle;
		data.size = size;
		data.status = STATUS_WAITING;
		data.proxy_data_base = write::data_base;
		data.updated = true;
		data.write = true;
		data.pReadProcessMemory = ReadProcessMemory;
		data.pWriteProcessMemory = WriteProcessMemory;

		WriteProcessMemory(proxy_handle, (LPVOID)readwrite_data_base, &data, sizeof(READWRITE_DATA), NULL);

		if (!thread)
		{
			thread = CreateRemoteThread(proxy_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)shellcode_base, (LPVOID)readwrite_data_base, NULL, NULL);
			if (!thread)
				exit(70);
		}

		DWORD status = STATUS_WAITING;
		while (status != STATUS_FINISHED)
		{
			READWRITE_DATA data_checked{ 0 };
			ReadProcessMemory(proxy_handle, (LPCVOID)readwrite_data_base, &data_checked, sizeof(READWRITE_DATA), NULL);
			status = data_checked.status;
			if (status == STATUS_ERROR)
			{
				std::cerr << "error during read_virtual_memory operation!\n";
				exit(100);
			}
		}
	}

	template<typename T>
	void write_virtual_memory(uintptr_t address, T* buf)
	{
		if (!address)
			return;

		write_virtual_memory(address, buf, sizeof(T));
	}
}