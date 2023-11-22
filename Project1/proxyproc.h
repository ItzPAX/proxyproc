#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <thread>

namespace proxyproc
{
#define MAX_DATA_SIZE 0x1000

#define STATUS_WAITING 0
#define STATUS_FINISHED 1
#define STATUS_ERROR 2

	std::string proxy_proc = "explorer.exe";

	using f_OpenProcess = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
	using f_ReadProcessMemory = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
	using f_WriteProcessMemory = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

	HANDLE proxy_handle;
	HANDLE target_handle;

	HANDLE read_thread;
	HANDLE write_thread;

	// base for the shellcode that will read data from proxy process
	uintptr_t read_read_shellcode_base;
	// base for the READ_DATA struct in proxy process
	uintptr_t read_read_data_base;
	// base for the data that is read from proxy process
	uintptr_t read_data_base;

	// base for the shellcode that will write data from proxy process
	uintptr_t write_write_shellcode_base;
	// base for the WRITE_DATA struct in proxy process
	uintptr_t write_write_data_base;
	// base for the data that is written from proxy process
	uintptr_t write_data_base;

	struct CREATE_HANDLE_DATA
	{
		DWORD pid;
		DWORD status;
		HANDLE out;
		f_OpenProcess pOpenProcess;
	};

	struct READ_DATA
	{
		bool updated;
		HANDLE handle;
		DWORD status;
		size_t size;
		uintptr_t address;
		uintptr_t proxy_data_base;
		f_ReadProcessMemory pReadProcessMemory;
	};

	struct WRITE_DATA
	{
		bool updated;
		HANDLE handle;
		DWORD status;
		size_t size;
		uintptr_t address;
		uintptr_t proxy_data_base;
		f_WriteProcessMemory pWriteProcessMemory;
	};

	void __stdcall shellcode_create_handle(CREATE_HANDLE_DATA* data)
	{
		data->out = data->pOpenProcess(PROCESS_ALL_ACCESS, FALSE, data->pid);
		data->status = STATUS_FINISHED;
	}

	void __stdcall shellcode_read_data(READ_DATA* data)
	{
		// no bueno for the cpu :sadbob:
		while (true)
		{
			if (!data->updated)
			{
				continue;
			}

			data->status = STATUS_WAITING;
			data->pReadProcessMemory(data->handle, (LPCVOID)data->address, (LPVOID)data->proxy_data_base, data->size, NULL);
			data->status = STATUS_FINISHED;

			data->updated = false;
		}
	}

	void __stdcall shellcode_write_data(WRITE_DATA* data)
	{
		while (true)
		{
			if (!data->updated)
			{
				continue;
			}

			data->status = STATUS_WAITING;
			data->pWriteProcessMemory(data->handle, (LPVOID)data->address, (LPCVOID)data->proxy_data_base, data->size, NULL);
			data->status = STATUS_FINISHED;

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

	// creates a handle from "explorer.exe" can also be changed
	void create_handle_in_proxy(const char* image_name)
	{
		DWORD proxy_pid = get_process_id(proxy_proc.c_str());
		DWORD target_pid = get_process_id(image_name);

		std::cout << "proxy_pid: " << proxy_pid << " target_pid: " << target_pid << std::endl;

		proxy_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proxy_pid);

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
		
		std::cout << std::hex << "proxy_handle: " << proxy_handle << " target_handle: " << target_handle << std::endl;
	}

	void cleanup()
	{
		TerminateThread(write_thread, 0);
		TerminateThread(read_thread, 0);
	}

	void read_virtual_memory(uintptr_t address, void* buf, size_t size)
	{
		if (!read_data_base)
		{
			read_data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, MAX_DATA_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!read_data_base)
				exit(40);

			std::cout << "proxy data base at 0x" << read_data_base << std::endl;
		}

		READ_DATA data{ 0 };
		data.address = address;
		data.handle = target_handle;
		data.size = size;
		data.status = STATUS_WAITING;
		data.proxy_data_base = read_data_base;
		data.updated = true;
		data.pReadProcessMemory = ReadProcessMemory;

		if (!read_read_data_base)
		{
			read_read_data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, sizeof(READ_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!read_read_data_base)
				exit(50);

			std::cout << "read data base at 0x" << read_read_data_base << std::endl;
		}

		WriteProcessMemory(proxy_handle, (LPVOID)read_read_data_base, &data, sizeof(READ_DATA), NULL);

		if (!read_read_shellcode_base)
		{
			read_read_shellcode_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (!read_read_shellcode_base)
				exit(60);

			std::cout << "shellcode data base at 0x" << read_read_shellcode_base << std::endl;

			WriteProcessMemory(proxy_handle, (LPVOID)read_read_shellcode_base, shellcode_read_data, 0x1000, NULL);
		}

		if (!read_thread)
		{
			read_thread = CreateRemoteThread(proxy_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)read_read_shellcode_base, (LPVOID)read_read_data_base, NULL, NULL);
			if (!read_thread)
				exit(70);
		}

		DWORD status = STATUS_WAITING;
		while (status != STATUS_FINISHED)
		{
			READ_DATA data_checked{ 0 };
			ReadProcessMemory(proxy_handle, (LPCVOID)read_read_data_base, &data_checked, sizeof(READ_DATA), NULL);
			status = data_checked.status;
			if (status == STATUS_ERROR)
			{
				std::cerr << "error during read_virtual_memory operation!\n";
				exit(100);
			}
		}

		ReadProcessMemory(proxy_handle, (LPCVOID)read_data_base, buf, size, NULL);
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
		if (!write_data_base)
		{
			write_data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, MAX_DATA_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!write_data_base)
				exit(40);

			std::cout << "proxy data base at 0x" << std::hex << write_data_base << std::endl;
		}

		WriteProcessMemory(proxy_handle, (LPVOID)write_data_base, buf, size, NULL);

		WRITE_DATA data{ 0 };
		data.address = address;
		data.handle = target_handle;
		data.size = size;
		data.status = STATUS_WAITING;
		data.proxy_data_base = write_data_base;
		data.updated = true;
		data.pWriteProcessMemory = WriteProcessMemory;

		if (!write_write_data_base)
		{
			write_write_data_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, sizeof(WRITE_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			if (!write_write_data_base)
				exit(50);

			std::cout << "write data base at 0x" << write_write_data_base << std::endl;
		}

		WriteProcessMemory(proxy_handle, (LPVOID)write_write_data_base, &data, sizeof(WRITE_DATA), NULL);

		if (!write_write_shellcode_base)
		{
			write_write_shellcode_base = reinterpret_cast<uintptr_t>(VirtualAllocEx(proxy_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (!write_write_shellcode_base)
				exit(60);

			std::cout << "shellcode data base at 0x" << write_write_shellcode_base << std::endl;

			WriteProcessMemory(proxy_handle, (LPVOID)write_write_shellcode_base, shellcode_write_data, 0x1000, NULL);
		}

		if (!write_thread)
		{
			write_thread = CreateRemoteThread(proxy_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)write_write_shellcode_base, (LPVOID)write_write_data_base, NULL, NULL);
			if (!write_thread)
				exit(70);
		}

		DWORD status = STATUS_WAITING;
		while (status != STATUS_FINISHED)
		{
			WRITE_DATA data_checked{ 0 };
			ReadProcessMemory(proxy_handle, (LPCVOID)write_write_data_base, &data_checked, sizeof(WRITE_DATA), NULL);
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