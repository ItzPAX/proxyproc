# Header only UM AC "Bypass"

This works by creating a handle from a "proxy" process that will do all the reading for you


## Limitations

You will still need to be able to open a handle to the game making this ineffective against KM ACs

Extremely inefficient, I haven't yet figured out how to properly tell the thread to "idle" when there is no update
## Usage

```cpp
#include "proxyproc.h"

int main()
{
	// setup our proxy process and open a handle to our target from it
	proxyproc::create_handle_in_proxy("Victim.exe");

	// read memory from this address
	float f = proxyproc::read_virtual_memory<float>(0x00007FF654005038);
	f += 10;
	// write new value
	proxyproc::write_virtual_memory<float>(0x00007FF654005038, &f);

	// terminate both threads
	proxyproc::cleanup();

	system("pause");

	return 0;
}
```
