#include <ntifs.h>
#include <intrin.h>
#include "SimpleHypervisor.h"

SimpleHypervisor::SimpleHypervisor()
{
}

BOOLEAN SimpleHypervisor::Install()
{
	if (!CheckVTSupported())
	{
		return FALSE;
	}

	if (!CheckVTEnable())
	{
		return FALSE;
	}

	DbgPrintEx(77, 0, "Debug:CPU Support virtualization\r\n");

	// Init VMCS

	return TRUE;

}

BOOLEAN SimpleHypervisor::CheckVTSupported()
{
	int ctx[4] = { 0 };
 
	// Check CPU Capacity
	__cpuidex(ctx, 1, 0);

	if ((ctx[2] && CPUID_1_ECX_VMX) == 0)
	{
		// Not support VT
		return FALSE;
	}

	return TRUE;


}


BOOLEAN SimpleHypervisor::CheckVTEnable()
{
	ULONG_PTR msr;
	msr = __readmsr(IA32_FEATURE_CONTROL_CODE);
	if ((msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX) == 0)
	{
		return FALSE;
	}


	return TRUE;

}