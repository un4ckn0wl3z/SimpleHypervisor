#include <ntifs.h>
#include <intrin.h>

#include "SimpleHypervisor.h"
#include "Asm.h"

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
	if (p) {
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
//------------------------------------------

VOID HvLoadProc(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	ULONG uCPU = KeGetCurrentProcessorNumber();
	DbgPrintEx(77,0,"Debug: Current CPU----->%d\n", uCPU);

	VT_CPU[uCPU] = new SimpleHypervisor(uCPU);   // Beware memory leak


	if (VT_CPU[uCPU]->InstallVT())
	{
		DbgPrintEx(77,0,"VT startup completed\n");
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

VOID HvUnLoadProc(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	ULONG uCPU = KeGetCurrentProcessorNumber();
	DbgPrintEx(77,0,"Debug: Current CPU----->%d\n", uCPU);

	VT_CPU[uCPU]->UnInstallVT();

	if (VT_CPU[uCPU])
	{
		delete VT_CPU[uCPU];
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

VOID HvLoad()
{
	KeGenericCallDpc(HvLoadProc, NULL);
}

#ifdef __cplusplus
extern "C"
#endif
VOID HvUnLoad(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	KeGenericCallDpc(HvUnLoadProc, NULL);

	DbgPrintEx(77,0,"Debug: Driver uninstall!\n");
}

#ifdef __cplusplus
extern "C"
#endif
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	UNREFERENCED_PARAMETER(RegisterPath);
	DbgPrintEx(77,0,"Debug: Driver installation!\n");

	DriverObject->DriverUnload = HvUnLoad;

	HvLoad();

	return STATUS_SUCCESS;
}

