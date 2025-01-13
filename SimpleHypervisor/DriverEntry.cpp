#include <ntifs.h>
#include "SimpleHypervisor.h"

SimpleHypervisor* VT_CPU[128];

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(unsigned __int64 size)
{
	PHYSICAL_ADDRESS highest;
	highest.QuadPart = 0xFFFFFFFFFFFFFFFF;
	return MmAllocateContiguousMemory(size, highest);
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* p, size_t size)
{
	UNREFERENCED_PARAMETER(size);
	if (p)
	{
		MmFreeContiguousMemory(p);
		p = NULL;
	}
}


EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);


EXTERN_C
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);


VOID VTLoadProc(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	ULONG uCPU = KeGetCurrentProcessorNumber();
	DbgPrintEx(77, 0, "Debug:CPU Number:------>: %d\r\n", uCPU);

	VT_CPU[uCPU] = new SimpleHypervisor(uCPU); // beware leak

	if (VT_CPU[uCPU]->Initialize())
	{
		VT_CPU[uCPU]->Install();
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

VOID VTUnLoadProc(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	ULONG uCPU = KeGetCurrentProcessorNumber();
	DbgPrintEx(77, 0, "Debug:CPU Number:------>: %d\r\n", uCPU);

	VT_CPU[uCPU]->UnInstall();

	VT_CPU[uCPU]->UnInitialize();

	if (VT_CPU[uCPU])
	{
		delete VT_CPU[uCPU];
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}


VOID VTLoad()
{
	KeGenericCallDpc(VTLoadProc, NULL);
}


#ifdef __cplusplus
EXTERN_C
#endif // __cplusplus
VOID VTUnload(PDRIVER_OBJECT DriverObject)
{
	KeGenericCallDpc(VTUnLoadProc, NULL);
	DbgPrintEx(77, 0, "Debug:VTUnload\r\n");
}

#ifdef __cplusplus
EXTERN_C
#endif // __cplusplus
 NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = VTUnload;
	VTLoad();

	DbgPrintEx(77,0,"Debug:VTLoad\r\n");


	return STATUS_SUCCESS;
}