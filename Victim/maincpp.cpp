#include <Windows.h>
#include <iostream>

void loop_thread()
{
	static int integer = 10;
	static float floateger = 4.20f;
	while (true)
	{
		std::cout << "Integer value: " << std::dec << integer << " at address: 0x" << std::hex << &integer << std::endl;
		std::cout << "Float value: " << std::dec << floateger << " at address: 0x" << std::hex << &floateger << std::endl;
		Sleep(1000);
	}
}

int main()
{
	HANDLE h = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)loop_thread, NULL, NULL, NULL);
	if (h)
		CloseHandle(h);

	_fgetchar();

	return 0;
}