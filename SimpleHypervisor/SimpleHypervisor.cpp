#include <ntifs.h>
#include <intrin.h>

#include "SimpleHypervisor.h"
#include "Asm.h"

#define ENABLE_EPT

//#define ENABLE_OUTPUT

#define VMERR_RET(x, s)\
	if( (x) != 0 )\
	{\
		DbgPrintEx(77,0,"Debug:%s call [failed]!\n", s);\
		return;\
	}

#ifdef  ENABLE_OUTPUT
#define VMWRITE_ERR_RET(e,v)\
	DbgPrintEx(77,0,"Debug:%s------>0x%016llX\n", #e, v); \
	VMERR_RET(vmxwrite(e,v),"vmwrite - " #e);

#define VMREAD_ERR_RET(e,v)\
	DbgPrintEx(77,0,"Debug:%s------>0x%016llX\n", #e, v);\
    VMERR_RET(vmxread(e,v),"vmread - " #e);
#else
#define VMWRITE_ERR_RET(e,v)\
	VMERR_RET(vmxwrite(e,v),"vmwrite - " #e);

#define VMREAD_ERR_RET(e,v)\
    VMERR_RET(vmxread(e,v),"vmread - " #e);
#endif





__forceinline unsigned char vmxon(ULONG_PTR* VmxRegion)
{
	return __vmx_on(VmxRegion);
}

__forceinline unsigned char vmxclear(ULONG_PTR* VmcsRegion)
{
	return __vmx_vmclear(VmcsRegion);
}

__forceinline unsigned char vmxptrld(ULONG_PTR* VmcsRegion)
{
	return __vmx_vmptrld(VmcsRegion);
}

__forceinline unsigned char vmxwrite(VMCSFIELD Encoding, ULONG_PTR Value)
{
	return __vmx_vmwrite(Encoding, Value);
}

__forceinline unsigned char vmxread(VMCSFIELD Encoding, ULONG_PTR* Value)
{
	return __vmx_vmread(Encoding, Value);
}

__forceinline unsigned char vmxlaunch(void)
{
	return __vmx_vmlaunch();
}

__forceinline ULONG_PTR VmxAdjustMsr(ULONG_PTR MsrValue, ULONG_PTR DesiredValue)
{
	DesiredValue &= (MsrValue >> 32);
	DesiredValue |= (MsrValue & 0xFFFFFFFF);
	return DesiredValue;
}

void ShowGuestRegister(ULONG_PTR* Registers)
{
	ULONG_PTR Rip = 0, Rsp = 0;
	ULONG_PTR Cr0 = 0, Cr3 = 0, Cr4 = 0;
	ULONG_PTR Cs = 0, Ss = 0, Ds = 0, Es = 0, Fs = 0, Gs = 0, Tr = 0, Ldtr = 0;
	ULONG_PTR GsBase = 0, DebugCtl = 0, Dr7 = 0, RFlags = 0;
	ULONG_PTR IdtBase = 0, GdtBase = 0, IdtLimit = 0, GdtLimit = 0;

	DbgPrintEx(77,0,"Debug:RAX = 0x%016llX RCX = 0x%016llX RDX = 0x%016llX RBX = 0x%016llX\n",
		Registers[R_RAX], Registers[R_RCX], Registers[R_RDX], Registers[R_RBX]);
	DbgPrintEx(77,0,"Debug:RSP = 0x%016llX RBP = 0x%016llX RSI = 0x%016llX RDI = 0x%016llX\n",
		Registers[R_RSP], Registers[R_RBP], Registers[R_RSI], Registers[R_RDI]);
	DbgPrintEx(77,0,"Debug:R8 = 0x%016llX R9 = 0x%016llX R10 = 0x%016llX R11 = 0x%016llX\n",
		Registers[R_R8], Registers[R_R9], Registers[R_R10], Registers[R_R11]);
	DbgPrintEx(77,0,"Debug:R12 = 0x%016llX R13 = 0x%016llX R14 = 0x%016llX R15 = 0x%016llX\n",
		Registers[R_R12], Registers[R_R13], Registers[R_R14], Registers[R_R15]);

	__vmx_vmread(GUEST_RSP, &Rsp);
	__vmx_vmread(GUEST_RIP, &Rip);
	DbgPrintEx(77,0,"Debug:RSP = 0x%016llX RIP = 0x%016llX\n", Rsp, Rip);

	__vmx_vmread(GUEST_CR0, &Cr0);
	__vmx_vmread(GUEST_CR3, &Cr3);
	__vmx_vmread(GUEST_CR4, &Cr4);
	DbgPrintEx(77,0,"Debug:CR0 = 0x%016llX CR3 = 0x%016llX CR4 = 0x%016llX\n", Cr0, Cr3, Cr4);

	__vmx_vmread(GUEST_CS_SELECTOR, &Cs);
	__vmx_vmread(GUEST_SS_SELECTOR, &Ss);
	__vmx_vmread(GUEST_DS_SELECTOR, &Ds);
	__vmx_vmread(GUEST_ES_SELECTOR, &Es);
	__vmx_vmread(GUEST_FS_SELECTOR, &Fs);
	__vmx_vmread(GUEST_GS_SELECTOR, &Gs);
	__vmx_vmread(GUEST_TR_SELECTOR, &Tr);
	__vmx_vmread(GUEST_LDTR_SELECTOR, &Ldtr);
	DbgPrintEx(77,0,"Debug:CS = 0x%016llX SS = 0x%016llX DS = 0x%016llX ES = 0x%016llX FS = 0x%016llX GS = 0x%016llX TR = 0x%016llX LDTR = 0x%016llX\n",
		Cs, Ss, Ds, Es, Fs, Gs, Tr, Ldtr);

	__vmx_vmread(GUEST_GS_BASE, &GsBase);
	__vmx_vmread(GUEST_IA32_DEBUGCTL, &DebugCtl);
	__vmx_vmread(GUEST_DR7, &Dr7);
	__vmx_vmread(GUEST_RFLAGS, &RFlags);
	DbgPrintEx(77,0,"Debug:GsBase = 0x%016llX DebugCtl = 0x%016llX Dr7 = 0x%016llX RFlags = 0x%016llX\n",
		GsBase, DebugCtl, Dr7, RFlags);

	__vmx_vmread(GUEST_IDTR_BASE, &IdtBase);
	__vmx_vmread(GUEST_IDTR_LIMIT, &IdtLimit);
	DbgPrintEx(77,0,"Debug:IdtBase = 0x%016llX IdtLimit = 0x%016llX\n", IdtBase, IdtLimit);

	__vmx_vmread(GUEST_GDTR_BASE, &GdtBase);
	__vmx_vmread(GUEST_GDTR_LIMIT, &GdtLimit);
	DbgPrintEx(77,0,"Debug:GdtBase = 0x%016llX GdtLimit = 0x%016llX\n", GdtBase, GdtLimit);

	return VOID();
}

EXTERN_C VOID VMExitHandler(ULONG_PTR* Registers)
{
	ULONG_PTR GuestRIP = 0;
	ULONG_PTR GuestRSP = 0;
	ULONG_PTR ExitInstructionLength = 0;
	ULONG_PTR ExitReason = 0;
	ULONG_PTR GuestRFLAGS = 0;
	ULONGLONG MsrValue = 0;
	ULONG_PTR ExitQualification = 0;
	ULONG_PTR numCR = 0, opType = 0, accType = 0, reg = 0, cr3 = 0;
	ULONG_PTR GuestVirt, GuestPhys;
	ULONG_PTR IdtVector, IdtVectorErrCode;
	ULONG_PTR InstructionInfo;
	int CPUInfo[4];

	VMREAD_ERR_RET(GUEST_RIP, &GuestRIP);
	VMREAD_ERR_RET(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);
	VMREAD_ERR_RET(VM_EXIT_REASON, &ExitReason);
	VMREAD_ERR_RET(GUEST_RFLAGS, &GuestRFLAGS);
	VMREAD_ERR_RET(EXIT_QUALIFICATION, &ExitQualification);

	VMREAD_ERR_RET(GUEST_RFLAGS, &GuestRFLAGS);
	VMREAD_ERR_RET(GUEST_RSP, &GuestRSP);
	VMREAD_ERR_RET(GUEST_CR3, &cr3);
	VMREAD_ERR_RET(GUEST_GS_BASE, &reg);
	VMREAD_ERR_RET(GUEST_LINEAR_ADDRESS, &GuestVirt);
	VMREAD_ERR_RET(GUEST_PHYSICAL_ADDRESS, &GuestPhys);
	VMREAD_ERR_RET(IDT_VECTORING_INFO, &IdtVector);
	VMREAD_ERR_RET(IDT_VECTORING_ERROR_CODE, &IdtVectorErrCode);
	VMREAD_ERR_RET(VMX_INSTRUCTION_INFO, &InstructionInfo);

	switch (ExitReason)
	{
	case VMX_EXIT_CPUID:
		if (Registers[R_RAX] == 0x13371337)
		{
			ShowGuestRegister(Registers);
			Registers[R_RBX] = 0xBAADF00D;
			Registers[R_RCX] = 0xFEEDC0DE;
			Registers[R_RDX] = 0xDEADBEEF;
		}
		else
		{
			__cpuidex(CPUInfo, Registers[R_RAX], Registers[R_RCX]);
			Registers[R_RAX] = (ULONG_PTR)CPUInfo[0];
			Registers[R_RBX] = (ULONG_PTR)CPUInfo[1];
			Registers[R_RCX] = (ULONG_PTR)CPUInfo[2];
			Registers[R_RDX] = (ULONG_PTR)CPUInfo[3];
		}
		break;
	case VMX_EXIT_VMCALL:
	{
		ULONG64 JmpEIP;
		if (Registers[R_RAX] == 'BYE')
		{
			// DbgPrintEx(77,0,"Debug: (VMCALL is called) \n");
			JmpEIP = GuestRIP + ExitInstructionLength;
			__vmx_off();
			Asm_AfterVMXOff(GuestRSP, JmpEIP);
		}
	}
	break;
	case VMX_EXIT_VMCLEAR:   // Deny running nested VM instructions
	case VMX_EXIT_VMLAUNCH:
	case VMX_EXIT_VMPTRLD:
	case VMX_EXIT_VMPTRST:
	case VMX_EXIT_VMREAD:
	case VMX_EXIT_VMWRITE:
	case VMX_EXIT_VMRESUME:
	case VMX_EXIT_VMXON:
	case VMX_EXIT_VMXOFF:
		VMWRITE_ERR_RET(GUEST_RFLAGS, GuestRFLAGS | 0x1);
		break;
	case VMX_EXIT_RDMSR:
		MsrValue = __readmsr(Registers[R_RCX]);
		Registers[R_RAX] = LODWORD(MsrValue);
		Registers[R_RDX] = HIDWORD(MsrValue);
		break;
	case VMX_EXIT_WRMSR:
		MsrValue = MAKEQWORD(Registers[R_RAX], Registers[R_RDX]);
		__writemsr(Registers[R_RCX], MsrValue);
		break;
	case VMX_EXIT_MOV_CRX:
		numCR = ExitQualification & 0b1111;
		opType = (ExitQualification >> 6) & 1;
		accType = (ExitQualification & 0b110000) >> 4;
		reg = (ExitQualification >> 8) & 0b1111;
		if (numCR == 3 && opType == 0)
		{
			if (accType == 1)  //mov reg,cr3
			{
				VMREAD_ERR_RET(GUEST_CR3, &cr3);
				Registers[reg] = cr3;
			}
			else if (accType == 0) //mov cr3,reg
			{
				cr3 = Registers[reg];
				VMWRITE_ERR_RET(GUEST_CR3, cr3);
			}
		}
		break;
	case VMX_EXIT_XSETBV:
		_xsetbv(Registers[R_RCX], MAKEQWORD(Registers[R_RAX], Registers[R_RDX]));
		break;
	case VMX_EXIT_INVD:
		__wbinvd();
		break;
	case VMX_EXIT_XCPT_OR_NMI:
		break;
	default:
		DbgPrintEx(77,0,"Debug: Unknown VM_EIXT reason: 0x%X\n", ExitReason);
		break;
	}

	__vmx_vmwrite(GUEST_RIP, GuestRIP + ExitInstructionLength);

	return VOID();
}

BOOLEAN SimpleHypervisor::InstallVT()
{
	if (!CheakVTSupported())
	{
		return FALSE;
	}

	if (!CheakVTEnable())
	{
		return FALSE;
	}

	DbgPrintEx(77,0,"Debug:[%d]CPU supports virtualization\n", m_CPU);
	//Initialize VMX region memory

	m_VMXRegion = (ULONG_PTR*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_VMXRegion) {
		RtlSecureZeroMemory(m_VMXRegion, PAGE_SIZE);
	}

	//Initialize VMCS
	m_VMCSRegion = (ULONG_PTR*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_VMCSRegion) {
		RtlSecureZeroMemory(m_VMCSRegion, PAGE_SIZE);
	}

	m_MsrBitmapRegion = (UINT8*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_MsrBitmapRegion) {
		RtlSecureZeroMemory(m_MsrBitmapRegion, PAGE_SIZE);
	}

	//Initialize virtualized stack memory

	m_VMXRootStackRegion = (ULONG_PTR)MmAllocateNonCachedMemory(3 * PAGE_SIZE);

	if (m_VMXRootStackRegion) {
		SetVMExitHandler((ULONG_PTR)Asm_VMExitHandler, m_VMXRootStackRegion + 0x2000);
	}

	SetupVMCS();

	__writeds(0x28 | 0x3);
	__writees(0x28 | 0x3);
	__writefs(0x50 | 0x3);

	return TRUE;
}

VOID SimpleHypervisor::UnInstallVT()
{
	if (m_VMXOn)
	{
		// Missing one to exit VMCALL
		Asm_VmxCall('BYE');

		m_VMXOn = FALSE;
	}

	if (m_EPT)
	{
		MmFreeContiguousMemory(m_EPT);
	}

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

BOOLEAN SimpleHypervisor::CheakVTSupported()
{
	int ctx[4] = { 0 };

	//Check CPU Capability

	__cpuidex(ctx, 1, 0);

	if ((ctx[2] & CPUID_1_ECX_VMX) == 0)
	{
		//No support for virtualization

		return FALSE;
	}

	return TRUE;
}

BOOLEAN SimpleHypervisor::CheakVTEnable()
{
	ULONG_PTR msr;
	msr = __readmsr(IA32_FEATURE_CONTROL_CODE);

	if ((msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX) == 0)
		return FALSE;

	return TRUE;
}

VOID SimpleHypervisor::SetVMExitHandler(ULONG_PTR HandlerEntryPoint, ULONG_PTR HandlerStack)
{
	m_HostState.rip = HandlerEntryPoint;
	m_HostState.rsp = ROUNDUP(HandlerStack, PAGE_SIZE);

	return VOID();
}


VOID SimpleHypervisor::InitializeEPT()
{
	PHYSICAL_ADDRESS highest;
	MTRR_CAPABILITIES mtrrCapabilities;
	MTRR_VARIABLE_BASE mtrrBase;
	MTRR_VARIABLE_MASK mtrrMask;

	SHV_MTRR_RANGE   mtrrData[16];
	int i = 0;
	int j = 0;
	unsigned long bit = 0;

	ULONG_PTR LargePageAddress = 0;
	ULONG_PTR CandidateMemoryType = 0;

	highest.QuadPart = 0xFFFFFFFFFFFFFFFF;
	m_EPT = (PVMX_EPT)MmAllocateContiguousMemory(sizeof(VMX_EPT), highest);
	if (!m_EPT)
	{
		DbgPrintEx(77,0,"Debug:[%d] Allocating EPT memory [failed]!\n", m_CPU);
		return;
	}

	RtlSecureZeroMemory(m_EPT, sizeof(VMX_EPT));
	DbgPrintEx(77,0,"Debug:[%d]EPT memory------>%p\n", m_CPU, m_EPT);

	//Read range
	mtrrCapabilities.AsUlonglong = __readmsr(MTRR_MSR_CAPABILITIES);
	DbgPrintEx(77,0,"Debug:[%d]mtrrCapabilities------>0x%016llX\n", m_CPU, mtrrCapabilities.AsUlonglong);
	DbgPrintEx(77,0,"Debug:[%d]mtrrCapabilities.u.VarCnt------>0x%X\n", m_CPU, mtrrCapabilities.u.VarCnt);
	for (i = 0; i < mtrrCapabilities.u.VarCnt; i++)
	{
		mtrrBase.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_BASE + i * 2);
		mtrrMask.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_MASK + i * 2);

		mtrrData[i].Type = (UINT32)mtrrBase.u.Type;
		mtrrData[i].Enabled = (UINT32)mtrrMask.u.Enabled;
		//Check whether it is enabled

		if (mtrrData[i].Enabled != FALSE)
		{
			//Set the base address
			mtrrData[i].PhysicalAddressMin = mtrrBase.u.PhysBase * MTRR_PAGE_SIZE;

			_BitScanForward64(&bit, mtrrMask.u.PhysMask * MTRR_PAGE_SIZE);
			mtrrData[i].PhysicalAddressMax = mtrrData[i].PhysicalAddressMin + (1ULL << bit) - 1;
		}
	}

	//Prepare to fill EPT content
	m_EPT->PML4T[0].u.Read = 1;
	m_EPT->PML4T[0].u.Write = 1;
	m_EPT->PML4T[0].u.Execute = 1;
	m_EPT->PML4T[0].u.PDPTAddress = MmGetPhysicalAddress(&m_EPT->PDPT).QuadPart / PAGE_SIZE;
 
	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		// Set the number of pages for PDPT

		m_EPT->PDPT[i].u.Read = 1;
		m_EPT->PDPT[i].u.Write = 1;
		m_EPT->PDPT[i].u.Execute = 1;
		m_EPT->PDPT[i].u.PDTAddress = MmGetPhysicalAddress(&m_EPT->PDT[i][0]).QuadPart / PAGE_SIZE;
	}

	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		//Build a PDT with 2 MB of memory as one page

		for (j = 0; j < PDE_ENTRY_COUNT; j++)
		{
			m_EPT->PDT[i][j].u.Read = 1;
			m_EPT->PDT[i][j].u.Write = 1;
			m_EPT->PDT[i][j].u.Execute = 1;
			m_EPT->PDT[i][j].u.Large = 1;
			m_EPT->PDT[i][j].u.PTAddress = (i * 512) + j;

			LargePageAddress = m_EPT->PDT[i][j].u.PTAddress * _2MB;

			CandidateMemoryType = MTRR_TYPE_WB;

			for (int k = 0; k < sizeof(mtrrData) / sizeof(mtrrData[0]); k++)
			{
				// Check if memory is enabled

				if (mtrrData[k].Enabled != FALSE)
				{
					// Check the physical address boundary of the large page. If the single physical page is 4KB, rewrite the entry to 2MB.
					if (((LargePageAddress + _2MB) >= mtrrData[k].PhysicalAddressMin) &&
						(LargePageAddress <= mtrrData[k].PhysicalAddressMax))
					{
						//Override the alternative memory type
						CandidateMemoryType = mtrrData[k].Type;
					}
				}
			}

			m_EPT->PDT[i][j].u.Type = CandidateMemoryType;
		}
	}

	DbgPrintEx(77,0,"Debug:[%d] Initialized EPT successfully!\n", m_CPU);
}

VOID SimpleHypervisor::GdtEntryToVmcsFormat(ULONG selector, ULONG_PTR* base, ULONG_PTR* limit, ULONG_PTR* rights)
{
	GDT gdtr;
	PKGDTENTRY64 gdtEntry;

	//Initialize to 0

	*base = *limit = *rights = 0;

	if (selector == 0 || (selector & SELECTOR_TABLE_INDEX) != 0) {
		*rights = 0x10000;	// unusable
		return;
	}

	__sgdt(&gdtr);
	gdtEntry = (PKGDTENTRY64)(gdtr.ulBase + (selector & ~(0x3)));

	*limit = __segmentlimit(selector);
	*base = ((gdtEntry->Bytes.BaseHigh << 24) | (gdtEntry->Bytes.BaseMiddle << 16) | (gdtEntry->BaseLow)) & 0xFFFFFFFF;
	*base |= ((gdtEntry->Bits.Type & 0x10) == 0) ? ((uintptr_t)gdtEntry->BaseUpper << 32) : 0;
	*rights = (gdtEntry->Bytes.Flags1) | (gdtEntry->Bytes.Flags2 << 8);
	*rights |= (gdtEntry->Bits.Present) ? 0 : 0x10000;

	return VOID();
}

VOID SimpleHypervisor::SetupVMCS()
{
	ULONG_PTR base, limit, rights;
	//Guest Status
	StackPointer = (ULONG_PTR)Asm_StackPointer();
	ReturnAddress = (ULONG_PTR)Asm_NextInstructionPointer();

	if (m_VMXOn)
	{
		DbgPrintEx(77,0,"Debug:[%d]Virtualization [Running]!\n", m_CPU);
		return;
	}

	// Get physical memory address

	m_VMXRegionPhysAddr = MmGetPhysicalAddress(m_VMXRegion).QuadPart;
	m_VMCSRegionPhysAddr = MmGetPhysicalAddress(m_VMCSRegion).QuadPart;
	m_MsrBitmapRegionPhysAddr = MmGetPhysicalAddress(m_MsrBitmapRegion).QuadPart;

	DbgPrintEx(77,0,"Debug:[%d]VMX------>Virtual address:0x%016llX Physical address:0x%016llX\n", m_CPU, m_VMXRegion, m_VMXRegionPhysAddr);
	DbgPrintEx(77,0,"Debug:[%d]VMCS------>Virtual address:0x%016llX Physical address:0x%016llX\n", m_CPU, m_VMCSRegion, m_VMCSRegionPhysAddr);
	DbgPrintEx(77,0,"Debug:[%d]MsrBitmap------>Virtual address:0x%016llX Physical address:0x%016llX\n", m_CPU, m_MsrBitmapRegion, m_MsrBitmapRegionPhysAddr);

	//Check Features
	m_VmxBasic = __readmsr(IA32_VMX_BASIC_MSR_CODE);
	m_VmxFeatureControl = __readmsr(IA32_FEATURE_CONTROL_CODE);

	//Fill in the version number

	*(PULONG32)m_VMXRegion = (ULONG32)m_VmxBasic;
	*(PULONG32)m_VMCSRegion = (ULONG32)m_VmxBasic;

	//Enable VMX configuration
	//Initialize Guest state
	//{
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
	//}

	__writecr0(m_GuestState.cr0);
	__writecr4(m_GuestState.cr4);

	//Initialize Host status
	//{
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
	//}


#ifdef ENABLE_EPT
	//Initialize EPT

	InitializeEPT();
#endif //ENABLE_EPT


	//Setup VMX
	VMERR_RET(vmxon(&m_VMXRegionPhysAddr), "vmxon");  // The VMM is on
	DbgPrintEx(77,0,"Debug:[%d] vmxon started successfully\n", m_CPU);
	m_VMXOn = TRUE;

	VMERR_RET(vmxclear(&m_VMCSRegionPhysAddr), "vmxclear");
	VMERR_RET(vmxptrld(&m_VMCSRegionPhysAddr), "vmxptrld");
	DbgPrintEx(77,0,"Debug:[%d]VMCS loaded successfully\n", m_CPU);

	//Setup VMCS
	VMWRITE_ERR_RET(VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFL);

#ifdef ENABLE_EPT
	m_EPTP.AsUlonglong = 0;
	m_EPTP.u.PageWalkLength = 3;
	m_EPTP.u.Type = MTRR_TYPE_WB;
	m_EPTP.u.PageFrameNumber = ((MmGetPhysicalAddress(&(m_EPT->PML4T)).QuadPart)) / PAGE_SIZE;

	VMWRITE_ERR_RET(EPT_POINTER, m_EPTP.AsUlonglong);
	VMWRITE_ERR_RET(VIRTUAL_PROCESSOR_ID, 1);
#endif //ENABLE_EPT

	//VM Execution Control Field

	VMWRITE_ERR_RET(MSR_BITMAP, m_MsrBitmapRegionPhysAddr);    // Bitmap

#ifdef ENABLE_EPT
	VMWRITE_ERR_RET(SECONDARY_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(IA32_VMX_PROCBASED_CTLS2),
			SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID
		));
#else
	// The following code enables RDTSC events

	VMWRITE_ERR_RET(SECONDARY_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(IA32_VMX_PROCBASED_CTLS2),
			SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_ENABLE_RDTSCP));
#endif //ENABLE_EPT

	VMWRITE_ERR_RET(PIN_BASED_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS), 0));  // Do not monitor virtual machines

	VMWRITE_ERR_RET(CPU_BASED_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP));  // Do not monitor virtual machines

	// VM Exit and VM Entry control fields

	VMWRITE_ERR_RET(VM_EXIT_CONTROLS,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS),
			VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT));

	VMWRITE_ERR_RET(VM_ENTRY_CONTROLS,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS),
			VM_ENTRY_IA32E_MODE));

	// Guest status
	GdtEntryToVmcsFormat(m_GuestState.cs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_CS_SELECTOR, m_GuestState.cs);
	VMWRITE_ERR_RET(GUEST_CS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_CS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_CS_BASE, base);


	GdtEntryToVmcsFormat(m_GuestState.ss, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_SS_SELECTOR, m_GuestState.ss);
	VMWRITE_ERR_RET(GUEST_SS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_SS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_SS_BASE, base);


	GdtEntryToVmcsFormat(m_GuestState.ds, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_DS_SELECTOR, m_GuestState.ds);
	VMWRITE_ERR_RET(GUEST_DS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_DS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_DS_BASE, base);


	GdtEntryToVmcsFormat(m_GuestState.es, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_ES_SELECTOR, m_GuestState.es);
	VMWRITE_ERR_RET(GUEST_ES_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_ES_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_ES_BASE, base);
	VMWRITE_ERR_RET(HOST_ES_SELECTOR, m_HostState.es);


	GdtEntryToVmcsFormat(m_GuestState.fs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_FS_SELECTOR, m_GuestState.fs);
	VMWRITE_ERR_RET(GUEST_FS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_FS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_FS_BASE, base);
	m_HostState.fsbase = base;


	GdtEntryToVmcsFormat(m_GuestState.gs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_GS_SELECTOR, m_GuestState.gs);
	base = __readmsr(MSR_GS_BASE);
	VMWRITE_ERR_RET(GUEST_GS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_GS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_GS_BASE, base);
	m_HostState.gsbase = base;


	GdtEntryToVmcsFormat(m_GuestState.tr, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_TR_SELECTOR, m_GuestState.tr);
	VMWRITE_ERR_RET(GUEST_TR_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_TR_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_TR_BASE, base);
	m_HostState.trbase = base;


	GdtEntryToVmcsFormat(m_GuestState.ldtr, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_LDTR_SELECTOR, m_GuestState.ldtr);
	VMWRITE_ERR_RET(GUEST_LDTR_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_LDTR_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_LDTR_BASE, base);


	VMWRITE_ERR_RET(GUEST_GDTR_BASE, m_GuestState.gdt.ulBase);
	VMWRITE_ERR_RET(GUEST_GDTR_LIMIT, m_GuestState.gdt.wLimit);


	VMWRITE_ERR_RET(GUEST_IDTR_BASE, m_GuestState.idt.ulBase);
	VMWRITE_ERR_RET(GUEST_IDTR_LIMIT, m_GuestState.idt.wLimit);


	VMWRITE_ERR_RET(CR0_READ_SHADOW, m_GuestState.cr0);
	VMWRITE_ERR_RET(GUEST_CR0, m_GuestState.cr0);
	VMWRITE_ERR_RET(GUEST_CR3, m_GuestState.cr3);


	VMWRITE_ERR_RET(GUEST_CR4, m_GuestState.cr4);
	VMWRITE_ERR_RET(CR4_READ_SHADOW, m_GuestState.cr4);


	VMWRITE_ERR_RET(GUEST_IA32_DEBUGCTL, m_GuestState.msr_debugctl);
	VMWRITE_ERR_RET(GUEST_DR7, m_GuestState.dr7);
	VMWRITE_ERR_RET(GUEST_RSP, m_GuestState.rsp);
	VMWRITE_ERR_RET(GUEST_RIP, m_GuestState.rip);
	VMWRITE_ERR_RET(GUEST_RFLAGS, m_GuestState.rflags);


	//Host status
	VMWRITE_ERR_RET(HOST_CS_SELECTOR, m_HostState.cs);   //*
	VMWRITE_ERR_RET(HOST_SS_SELECTOR, m_HostState.ss);   //*
	VMWRITE_ERR_RET(HOST_DS_SELECTOR, m_HostState.ds);   //*

	VMWRITE_ERR_RET(HOST_FS_BASE, m_HostState.fsbase);  //*
	VMWRITE_ERR_RET(HOST_FS_SELECTOR, m_HostState.fs);  //*

	VMWRITE_ERR_RET(HOST_GS_BASE, m_HostState.gsbase);  //*
	VMWRITE_ERR_RET(HOST_GS_SELECTOR, m_HostState.gs);  //*

	VMWRITE_ERR_RET(HOST_TR_BASE, m_HostState.trbase);   //*
	VMWRITE_ERR_RET(HOST_TR_SELECTOR, m_HostState.tr);   //*

	VMWRITE_ERR_RET(HOST_GDTR_BASE, m_HostState.gdt.ulBase);                 //*
	VMWRITE_ERR_RET(HOST_IDTR_BASE, m_HostState.idt.ulBase);                 //*

	VMWRITE_ERR_RET(HOST_CR0, m_HostState.cr0);                 //*
	VMWRITE_ERR_RET(HOST_CR4, m_HostState.cr4);                 //*
	VMWRITE_ERR_RET(HOST_CR3, m_HostState.cr3);                 //*

	VMWRITE_ERR_RET(HOST_RIP, m_HostState.rip);
	VMWRITE_ERR_RET(HOST_RSP, m_HostState.rsp);

	// Initialization of VMCS completed
	DbgPrintEx(77,0,"Debug:[%d]Preparing to start virtualization\n", m_CPU);
	vmxlaunch(); //If this statement is executed successfully, it will not return

	// Only come here if the startup fails
	DbgPrintEx(77,0,"Debug:[%d] [Should not execute here]\n", m_CPU);
	/*
	*/
	if (m_VMXOn)
	{
		__vmx_off();
		m_VMXOn = FALSE;
	}
	return;
}