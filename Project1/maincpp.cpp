#include "proxyproc.h"

int main()
{
	// setup our proxy process and open a handle to our target from it
	proxyproc::create_handle_in_proxy("Victim.exe");

	// read memory from this address
	float f = proxyproc::read_virtual_memory<float>(0x00007FF665AD5038);
	std::cout << f << std::endl;
	f += 10;
	// write new value
	proxyproc::write_virtual_memory<float>(0x00007FF665AD5038, &f);

	// terminate both threads
	proxyproc::cleanup();

	system("pause");

	return 0;
}