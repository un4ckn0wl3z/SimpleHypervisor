#include <ntifs.h>


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
	DbgPrintEx(77, 0, "Debug:CPU Number:------>: %d\r\n", KeGetCurrentProcessorNumber());

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
	DbgPrintEx(77, 0, "VTUnload\r\n");
}

#ifdef __cplusplus
EXTERN_C
#endif // __cplusplus
 NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = VTUnload;
	VTLoad();

	DbgPrintEx(77,0,"VTLoad\r\n");


	return STATUS_SUCCESS;
}