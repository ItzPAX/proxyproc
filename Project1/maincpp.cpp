#include "proxyproc.h"

int main()
{
	proxyproc::create_handle_in_proxy("Victim.exe");
	int t = proxyproc::read_virtual_memory<int>(0x00007FF7D8A05034);
	std::cout << std::dec << t << std::endl;
	
	float f = proxyproc::read_virtual_memory<float>(0x00007FF7D8A05038);
	std::cout << std::dec << f << std::endl;

	proxyproc::cleanup();

	system("pause");

	return 0;
}