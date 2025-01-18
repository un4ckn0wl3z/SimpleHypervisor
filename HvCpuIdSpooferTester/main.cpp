#include <stdio.h>
#include <tchar.h>
#include <intrin.h>


int main()
{
	int CPUinfo[4];

	__cpuidex(CPUinfo, 0x13371337, 0x12345678);

	printf("EAX = 0x%X EBX = 0x%X ECX = 0x%X EDX = 0x%X\r\n", CPUinfo[0], CPUinfo[1], CPUinfo[2], CPUinfo[3]);

	getchar();

	return 0;
}