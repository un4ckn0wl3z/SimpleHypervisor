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

	m_VMXOn = FALSE;

	InitVMCS();

	return TRUE;

}

VOID SimpleHypervisor::UnInitialize()
{
	if (m_VMXRegion)
	{
		MmFreeNonCachedMemory(m_VMXRegion, PAGE_SIZE);

	}

	if (m_VMCSRegion)
	{
		MmFreeNonCachedMemory(m_VMCSRegion, PAGE_SIZE);

	}

	if (m_MsrBitmapRegion)
	{
		MmFreeNonCachedMemory(m_MsrBitmapRegion, PAGE_SIZE);

	}

	if (m_VMXRootStackRegion)
	{
		MmFreeNonCachedMemory((PVOID)m_VMXRootStackRegion, 3 * PAGE_SIZE);

	}

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
	// Guest status
	StackPointer = (ULONG_PTR)Asm_StackPointer();
	ReturnAddress = (ULONG_PTR)Asm_NextInstructionPointer();

	if (m_VMXOn)
	{
		DbgPrintEx(77, 0, "Debug:SimpleHypervisor is running: %d\r\n");
		return FALSE;
	}

	// Get physical address
	m_VMXRegionPhysAddr = MmGetPhysicalAddress(m_VMXRegion).QuadPart;
	m_VMCSRegionPhysAddr = MmGetPhysicalAddress(m_VMCSRegion).QuadPart;
	m_MsrBitmapRegionPhysAddr = MmGetPhysicalAddress(m_MsrBitmapRegion).QuadPart;

	DbgPrintEx(77, 
		0, "Debug:[CPU:%d] -- [VMX] --------- VA: %016llX! ------ phy: %016llX!\r\n",m_CPU , m_VMXRegion, m_VMXRegionPhysAddr);
	DbgPrintEx(77, 
		0, "Debug:[CPU:%d] -- [VMCS] -------- VA: %016llX! ------ phy: %016llX!\r\n", m_CPU, m_VMCSRegion, m_VMCSRegionPhysAddr);
	DbgPrintEx(77, 
		0, "Debug:[CPU:%d] -- [MsrBitmap] --- VA: %016llX! ------ phy: %016llX!\r\n", m_CPU, m_MsrBitmapRegion, m_MsrBitmapRegionPhysAddr);



	// Check features
	m_VmxBasic = __readmsr(IA32_VMX_BASIC_MSR_CODE);
	m_VmxFeatureControl = __readmsr(IA32_FEATURE_CONTROL_CODE);

	// Fill in version number

	*(PULONG32)m_VMXRegion = (ULONG32)m_VmxBasic;
	*(PULONG32)m_VMCSRegion = (ULONG32)m_VmxBasic;

	// Enable VMX Config
	// 
	// { Init guest state
	m_GuestState.cs = __readcs();
	m_GuestState.ds = __readds();
	m_GuestState.ss = __readss();
	m_GuestState.es = __reades();
	m_GuestState.fs = __readfs();
	m_GuestState.gs = __readgs();

	m_GuestState.ldtr = __sldt();
	m_GuestState.tr = __str();
	m_GuestState.rflags = __readeflags();

	m_GuestState.rip = ReturnAddress;
	m_GuestState.rsp = StackPointer;

	__sgdt(&(m_GuestState.gdt));

	__sidt(&(m_GuestState.idt));

	m_GuestState.cr3 = __readcr3();
	m_GuestState.cr0 = ((__readcr0() & __readmsr(IA32_VMX_CR0_FIXED1)) | __readmsr(IA32_VMX_CR0_FIXED0));

	m_GuestState.cr4 = ((__readcr4() & __readmsr(IA32_VMX_CR4_FIXED1)) | __readmsr(IA32_VMX_CR4_FIXED0));
	m_GuestState.dr7 = __readdr(7);

	m_GuestState.msr_debugctl = __readmsr(IA32_DEBUGCTL);
	m_GuestState.msr_sysenter_cs = __readmsr(IA32_SYSENTER_CS);
	m_GuestState.msr_sysenter_eip = __readmsr(IA32_SYSENTER_EIP);
	m_GuestState.msr_sysenter_esp = __readmsr(IA32_SYSENTER_ESP);
	// }
	
	__writecr0(m_GuestState.cr0);
	__writecr4(m_GuestState.cr4);

	// Init host state

	// {

	m_HostState.cr0 = __readcr0();
	m_HostState.cr3 = __readcr3();
	m_HostState.cr4 = __readcr4();

	m_HostState.cs = __readcs() & 0xF8;
	m_HostState.ds = __readds() & 0xF8;
	m_HostState.ss = __readss() & 0xF8;
	m_HostState.es = __reades() & 0xF8;
	m_HostState.fs = __readfs() & 0xF8;
	m_HostState.gs = __readgs() & 0xF8;

	m_HostState.tr = __str();
	m_HostState.msr_sysenter_cs = __readmsr(IA32_SYSENTER_CS);
	m_HostState.msr_sysenter_eip = __readmsr(IA32_SYSENTER_EIP);
	m_HostState.msr_sysenter_esp = __readmsr(IA32_SYSENTER_ESP);


	__sgdt(&(m_HostState.gdt));

	__sidt(&(m_HostState.idt));

	// }


	// Init EPT

	InitializeEPT();




	return TRUE;
}

VOID SimpleHypervisor::InitializeEPT()
{
	PHYSICAL_ADDRESS highest;
	MTRR_CAPABILITIES mtrrCapabilities;
	MTRR_VARIABLE_BASE mtrrBase;
	MTRR_VARIABLE_MASK mtrrMask;
	SHV_MTRR_RANGE mtrrData[16];

	int i = 0;
	int j = 0;

	unsigned long bit = 0;
	ULONG_PTR LargePageAddress = 0;
	ULONG CandidateMemoryType = 0;

	highest.QuadPart = 0xFFFFFFFFFFFFFFFF;

	m_EPT = (PVMX_EPT)MmAllocateContiguousMemory(sizeof(VMX_EPT), highest);

	if (!m_EPT)
	{
		return;
	}

	RtlSecureZeroMemory(m_EPT, sizeof(VMX_EPT));
	DbgPrintEx(77, 0, "Debug:[%d]EPT Memory:------->%p\r\n", m_CPU, m_EPT);


	// Reading the mtrr addressing range
	mtrrCapabilities.AsUlonglong = __readmsr(MTRR_MSR_CAPABILITIES);
	DbgPrintEx(77, 0, "Debug:[%d]mtrrCapabilities:------->0x%016llX\r\n", m_CPU, mtrrCapabilities.AsUlonglong);
	DbgPrintEx(77, 0, "Debug:[%d]mtrrCapabilities.u.VarCnt:------->0x%X\r\n", m_CPU, mtrrCapabilities.u.VarCnt);


	for (i = 0; i < mtrrCapabilities.u.VarCnt; i++)
	{
		mtrrBase.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_BASE + i * 2);
		mtrrMask.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_MASK + i * 2);

		mtrrData[i].Type = mtrrBase.u.Type;
		mtrrData[i].Enabled = mtrrMask.u.Enabled;
		if (mtrrData[i].Enabled != FALSE)
		{
			// Set Base Address
			mtrrData[i].PhysicalAddressMin = mtrrBase.u.PhysBase * MTRR_PAGE_SIZE;

			_BitScanForward64(&bit, mtrrMask.u.PhysMask * MTRR_PAGE_SIZE);
			mtrrData[i].PhysicalAddressMax = mtrrData[i].PhysicalAddressMin + (1ULL << bit) - 1;

		}
	}

	// Prepare item to fill in EPT content

	m_EPT->PML4T[0].u.Read = 1;
	m_EPT->PML4T[0].u.Write = 1;
	m_EPT->PML4T[0].u.Execute = 1;
	m_EPT->PML4T[0].u.PageFrameNumber = (MmGetPhysicalAddress(m_EPT->PDPT)).QuadPart / PAGE_SIZE;

	DbgPrintEx(77, 0, "Debug:[%d]PML4E[0].u.PageFrameNumber:------->0x%016llX\r\n", m_CPU, m_EPT->PML4T[0].u.PageFrameNumber);


	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		// Fill-in page count for PDPT
		m_EPT->PDPT[i].u.Read = 1;
		m_EPT->PDPT[i].u.Write = 1;
		m_EPT->PDPT[i].u.Execute = 1;
		m_EPT->PDPT[i].u.PageFrameNumber = (MmGetPhysicalAddress(&m_EPT->PDT[i][0])).QuadPart / PAGE_SIZE;
	}

	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		// Build every 2M of EPT as one page
		for (j = 0; j < PDE_ENTRY_COUNT; j++) 
		{
			m_EPT->PDT[i][j].u.Read = 1;
			m_EPT->PDT[i][j].u.Write = 1;
			m_EPT->PDT[i][j].u.Execute = 1;
			m_EPT->PDT[i][j].u.Large = 1;
			m_EPT->PDT[i][j].u.PageFrameNumber = (i * 512) + j;

			LargePageAddress = m_EPT->PDT[i][j].u.PageFrameNumber * _2MB;

			CandidateMemoryType = MTRR_TYPE_WB;

			for (int k = 0; k < sizeof(mtrrData) / sizeof(mtrrData[0]); k++)
			{
				// check memory enabled
				if (mtrrData[k].Enabled != FALSE)
				{
					// Check boundary
					if ( ((LargePageAddress + _2MB) >= mtrrData[k].PhysicalAddressMin) &&
						   (LargePageAddress <= mtrrData[k].PhysicalAddressMax)
						)
					{
						// Change type
						CandidateMemoryType = mtrrData[k].Type;

					}

				}

			}

			m_EPT->PDT[i][j].u.Type = CandidateMemoryType;

		}
	}





}