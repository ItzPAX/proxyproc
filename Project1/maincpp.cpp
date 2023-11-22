#include "proxyproc.h"

int main()
{
	proxyproc::create_handle_in_proxy("Victim.exe");

	for (int i = 0; i < 10000; i++)
	{
		float f = proxyproc::read_virtual_memory<float>(0x00007FF654005038);
		f += 10;
		proxyproc::write_virtual_memory<float>(0x00007FF654005038, &f);
	}

	proxyproc::cleanup();

	system("pause");

	return 0;
}