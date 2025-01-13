#include <ntifs.h>
#include <intrin.h>
#include "SimpleHypervisor.h"
#include "Asm.h"

EXTERN_C
BOOLEAN VMExitHandler(ULONG_PTR* Registers)
{
	// 
	UNREFERENCED_PARAMETER(Registers);
	return TRUE;
}


BOOLEAN SimpleHypervisor::Initialize()
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

	// Init VMX region mem

	m_VMXRegion = (ULONG_PTR*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_VMXRegion)
	{
		RtlSecureZeroMemory(m_VMXRegion, PAGE_SIZE);
	}

	// Init VMCS

	m_VMCSRegion = (ULONG_PTR*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_VMCSRegion)
	{
		RtlSecureZeroMemory(m_VMCSRegion, PAGE_SIZE);
	}

	// Init MSR BIT MAP

	m_MsrBitmapRegion = (UINT8*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_MsrBitmapRegion)
	{
		RtlSecureZeroMemory(m_MsrBitmapRegion, PAGE_SIZE);
	}

	// Init VM MEM
	m_VMXRootStackRegion = (ULONG_PTR)MmAllocateNonCachedMemory(3 * PAGE_SIZE);

	if (m_VMXRootStackRegion)
	{
		SetVMExitHandler((ULONG_PTR)VMExitHandler, m_VMXRootStackRegion + 0x2000);
	}

	m_VMXon = FALSE;

	InitVMCS();

	return TRUE;

}

BOOLEAN SimpleHypervisor::Install()
{
	return TRUE;
}

BOOLEAN SimpleHypervisor::UnInstall()
{
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


VOID SimpleHypervisor::SetVMExitHandler(ULONG_PTR HandlerEntryPoint, ULONG_PTR HandlerStack)
{
	m_HostState.rip = HandlerEntryPoint;
	m_HostState.rsp = ROUNDUP(HandlerStack, PAGE_SIZE);

	return VOID();

}

BOOLEAN SimpleHypervisor::InitVMCS()
{
	// Get physical address
	m_VMXRegionPhysAddr = MmGetPhysicalAddress(m_VMXRegion).QuadPart;
	m_VMCSRegionPhysAddr = MmGetPhysicalAddress(m_VMCSRegion).QuadPart;
	m_MsrBitmapRegionPhysAddr = MmGetPhysicalAddress(m_MsrBitmapRegion).QuadPart;

	StackPointer = (ULONG_PTR)Asm_StackPointer();

	return TRUE;
}