# Header only UM AC "Bypass"

This works by creating a handle from a "proxy" process that will do all the reading for you


## Limitations

You will still need to be able to open a handle to the game making this ineffective against KM ACs

Extremely inefficient, I haven't yet figured out how to properly tell the thread to "idle" when there is no update
## Usage

```cpp
int main()
{
	proxyproc::create_handle_in_proxy("YOURPROCESS.exe");
	int t = proxyproc::read_virtual_memory<int>(ADDRESS);
	std::cout << std::dec << t << std::endl;

        // call this before you exit the program to terminate the thread
	proxyproc::cleanup();

	system("pause");

	return 0;
}
```
