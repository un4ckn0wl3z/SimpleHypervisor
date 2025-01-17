#include <ntifs.h>
#include <intrin.h>

#include "SimpleHypervisor.h"
#include "Asm.h"

#define ENABLE_EPT

#define VMERR_RET(x, s)\
	if( (x) != 0 )\
	{\
		DbgPrint("Debug:%s Call [failed]!\n", s);\
		return;\
	}

#define VMWRITE_ERR_RET(e,v)\
	DbgPrintEx(77,0,"Debug:[%d]%s:0x%016llX\n",m_CPU, #e, v);\
	VMERR_RET(vmxwrite(e,v),"vmwrite - " #e);

#define VMREAD_ERR_RET(e,v)\
	DbgPrint("Debug:%s------>0x%016llX\n", #e, v);\
    VMERR_RET(vmxread(e,v),"vmread - " #e);

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

__forceinline unsigned char vmxlaunch()
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

	DbgPrint("Debug:RAX = 0x%016llX RCX = 0x%016llX RDX = 0x%016llX RBX = 0x%016llX\n",
		Registers[R_RAX], Registers[R_RCX], Registers[R_RDX], Registers[R_RBX]);
	DbgPrint("Debug:RSP = 0x%016llX RBP = 0x%016llX RSI = 0x%016llX RDI = 0x%016llX\n",
		Registers[R_RSP], Registers[R_RBP], Registers[R_RSI], Registers[R_RDI]);
	DbgPrint("Debug:R8 = 0x%016llX R9 = 0x%016llX R10 = 0x%016llX R11 = 0x%016llX\n",
		Registers[R_R8], Registers[R_R9], Registers[R_R10], Registers[R_R11]);
	DbgPrint("Debug:R12 = 0x%016llX R13 = 0x%016llX R14 = 0x%016llX R15 = 0x%016llX\n",
		Registers[R_R12], Registers[R_R13], Registers[R_R14], Registers[R_R15]);

	__vmx_vmread(GUEST_RSP, &Rsp);
	__vmx_vmread(GUEST_RIP, &Rip);
	DbgPrint("Debug:RSP = 0x%016llX RIP = 0x%016llX\n", Rsp, Rip);

	__vmx_vmread(GUEST_CR0, &Cr0);
	__vmx_vmread(GUEST_CR3, &Cr3);
	__vmx_vmread(GUEST_CR4, &Cr4);
	DbgPrint("Debug:CR0 = 0x%016llX CR3 = 0x%016llX CR4 = 0x%016llX\n", Cr0, Cr3, Cr4);

	__vmx_vmread(GUEST_CS_SELECTOR, &Cs);
	__vmx_vmread(GUEST_DS_SELECTOR, &Ds);
	__vmx_vmread(GUEST_ES_SELECTOR, &Es);
	__vmx_vmread(GUEST_FS_SELECTOR, &Fs);
	__vmx_vmread(GUEST_GS_SELECTOR, &Gs);
	__vmx_vmread(GUEST_TR_SELECTOR, &Tr);
	__vmx_vmread(GUEST_LDTR_SELECTOR, &Ldtr);
	DbgPrint("Debug:CS = 0x%016llX DS = 0x%016llX ES = 0x%016llX FS = 0x%016llX GS = 0x%016llX TR = 0x%016llX LDTR = 0x%016llX\n",
		Cs, Ds, Es, Fs, Gs, Tr, Ldtr);

	__vmx_vmread(GUEST_GS_BASE, &GsBase);
	__vmx_vmread(GUEST_IA32_DEBUGCTL, &DebugCtl);
	__vmx_vmread(GUEST_DR7, &Dr7);
	__vmx_vmread(GUEST_RFLAGS, &RFlags);
	DbgPrint("Debug:GsBase = 0x%016llX DebugCtl = 0x%016llX Dr7 = 0x%016llX RFlags = 0x%016llX\n",
		GsBase, DebugCtl, Dr7, RFlags);

	__vmx_vmread(GUEST_IDTR_BASE, &IdtBase);
	__vmx_vmread(GUEST_IDTR_LIMIT, &IdtLimit);
	DbgPrint("Debug:IdtBase = 0x%016llX IdtLimit = 0x%016llX\n", IdtBase, IdtLimit);

	__vmx_vmread(GUEST_GDTR_BASE, &GdtBase);
	__vmx_vmread(GUEST_GDTR_LIMIT, &GdtLimit);
	DbgPrint("Debug:GdtBase = 0x%016llX GdtLimit = 0x%016llX\n", GdtBase, GdtLimit);

	return VOID();
}

EXTERN_C VOID VMExitHandler(ULONG_PTR* Registers)
{
	ULONG_PTR GuestRIP = 0;
	ULONG_PTR ExitInstructionLength = 0;
	//ShowGuestRegister(Registers);
	VMREAD_ERR_RET(GUEST_RIP, &GuestRIP);
	VMREAD_ERR_RET(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

	// more blah blah

	__vmx_vmwrite(GUEST_RIP, GuestRIP + ExitInstructionLength);

	return VOID();
}

BOOLEAN SimpleHypervisor::Initialize()
{
	if (!CheakVTSupported())
	{
		return FALSE;
	}

	if (!CheakVTEnable())
	{
		return FALSE;
	}

	DbgPrintEx(77,0,"Debug:[%d]CPU DPC Init\n", m_CPU);
 	m_VMXRegion = (ULONG_PTR*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_VMXRegion) {
		RtlSecureZeroMemory(m_VMXRegion, PAGE_SIZE);
	}

 	m_VMCSRegion = (ULONG_PTR*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_VMCSRegion) {
		RtlSecureZeroMemory(m_VMCSRegion, PAGE_SIZE);
	}

	m_MsrBitmapRegion = (UINT8*)MmAllocateNonCachedMemory(PAGE_SIZE);
	if (m_MsrBitmapRegion) {
		RtlSecureZeroMemory(m_MsrBitmapRegion, PAGE_SIZE);
	}

 	m_VMXRootStackRegion = (ULONG_PTR)MmAllocateNonCachedMemory(3 * PAGE_SIZE);

	if (m_VMXRootStackRegion) {
		SetVMExitHandler((ULONG_PTR)Asm_VMExitHandler, m_VMXRootStackRegion + 0x2000);
	}

	m_VMXOn = FALSE;

	InitVMCS();

	return TRUE;
}

VOID SimpleHypervisor::UnInitialize()
{
	if (m_VMXOn)
	{
		// Missing one to exit VMCALL
		__vmx_off();
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

BOOLEAN SimpleHypervisor::Install()
{

	return TRUE;
}

BOOLEAN SimpleHypervisor::UnInstall()
{

	return TRUE;
}

BOOLEAN SimpleHypervisor::CheakVTSupported()
{
	int ctx[4] = { 0 };

 	__cpuidex(ctx, 1, 0);

	if ((ctx[2] & CPUID_1_ECX_VMX) == 0)
	{
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

VOID SimpleHypervisor::GdtEntryToVmcsFormat(ULONG selector, ULONG_PTR* base, ULONG_PTR* limit, ULONG_PTR* rights)
{
	GDT gdtr;
	PKGDTENTRY64 gdtEntry;

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


VOID SimpleHypervisor::InitVMCS()
{
	//VMX_EPTP EPTP;
	ULONG_PTR base, limit, rights;
	//Guest
	StackPointer = (ULONG_PTR)Asm_StackPointer();
	ReturnAddress = (ULONG_PTR)Asm_NextInstructionPointer();

	if (m_VMXOn)
	{
		DbgPrintEx(77,0,"Debug:[%d] !\n", m_CPU);
		return;
	}

 	m_VMXRegionPhysAddr = MmGetPhysicalAddress(m_VMXRegion).QuadPart;
	m_VMCSRegionPhysAddr = MmGetPhysicalAddress(m_VMCSRegion).QuadPart;
	m_MsrBitmapRegionPhysAddr = MmGetPhysicalAddress(m_MsrBitmapRegion).QuadPart;

	DbgPrintEx(77,0,"Debug:[%d]VMX------>va:0x%016llX     pa:0x%016llX!\n", m_CPU, m_VMXRegion, m_VMXRegionPhysAddr);
	DbgPrintEx(77,0,"Debug:[%d]VMCS------>va:0x%016llX     pa:0x%016llX!\n", m_CPU, m_VMCSRegion, m_VMCSRegionPhysAddr);
	DbgPrintEx(77,0,"Debug:[%d]MsrBitmap------>va:0x%016llX     pa:0x%016llX!\n", m_CPU, m_MsrBitmapRegion, m_MsrBitmapRegionPhysAddr);

	//Check Features
	m_VmxBasic = __readmsr(IA32_VMX_BASIC_MSR_CODE);
	m_VmxFeatureControl = __readmsr(IA32_FEATURE_CONTROL_CODE);

 	*(PULONG32)m_VMXRegion = (ULONG32)m_VmxBasic;
	*(PULONG32)m_VMCSRegion = (ULONG32)m_VmxBasic;

 
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
 	InitializeEPT();
#endif //ENABLE_EPT

	//Setup VMX
	VMERR_RET(vmxon(&m_VMXRegionPhysAddr), "vmxon");
	DbgPrintEx(77,0,"Debug:[%d]vmxon done\n", m_CPU);
	m_VMXOn = TRUE;

	VMERR_RET(vmxclear(&m_VMCSRegionPhysAddr), "vmxclear");
	VMERR_RET(vmxptrld(&m_VMCSRegionPhysAddr), "vmxptrld");
	DbgPrintEx(77,0,"Debug:[%d]VMCS done\n", m_CPU);

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

 	VMWRITE_ERR_RET(MSR_BITMAP, m_MsrBitmapRegionPhysAddr);

#ifdef ENABLE_EPT
	VMWRITE_ERR_RET(SECONDARY_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(IA32_VMX_PROCBASED_CTLS2),
			SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_VPID
		));
#else
 	VMWRITE_ERR_RET(SECONDARY_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(IA32_VMX_PROCBASED_CTLS2),
			SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_ENABLE_RDTSCP));
#endif //ENABLE_EPT

	VMWRITE_ERR_RET(PIN_BASED_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS), 0));   

	VMWRITE_ERR_RET(CPU_BASED_VM_EXEC_CONTROL,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP));  

	//VM Exit && VM Entry Control Fields

	VMWRITE_ERR_RET(VM_EXIT_CONTROLS,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS),
			VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT));

	VMWRITE_ERR_RET(VM_ENTRY_CONTROLS,
		VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS),
			VM_ENTRY_IA32E_MODE));

	// Guest Status

	GdtEntryToVmcsFormat(m_GuestState.cs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_CS_SELECTOR, m_GuestState.cs);
	VMWRITE_ERR_RET(GUEST_CS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_CS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_CS_BASE, base);

	GdtEntryToVmcsFormat(m_GuestState.ds, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_DS_SELECTOR, m_GuestState.ds);
	VMWRITE_ERR_RET(GUEST_DS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_DS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_DS_BASE, base);

	GdtEntryToVmcsFormat(m_GuestState.ss, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_SS_SELECTOR, m_GuestState.ss);
	VMWRITE_ERR_RET(GUEST_SS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_SS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_SS_BASE, base);

	GdtEntryToVmcsFormat(m_GuestState.es, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_ES_SELECTOR, m_GuestState.es);
	VMWRITE_ERR_RET(GUEST_ES_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_ES_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_ES_BASE, base);

	GdtEntryToVmcsFormat(m_GuestState.fs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_FS_SELECTOR, m_GuestState.fs);
	VMWRITE_ERR_RET(GUEST_FS_LIMIT, limit);
	VMWRITE_ERR_RET(GUEST_FS_AR_BYTES, rights);
	VMWRITE_ERR_RET(GUEST_FS_BASE, base);
	m_HostState.fsbase = base;

	GdtEntryToVmcsFormat(m_GuestState.gs, &base, &limit, &rights);
	base = __readmsr(MSR_GS_BASE);
	VMWRITE_ERR_RET(GUEST_GS_SELECTOR, m_GuestState.gs);
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

	VMWRITE_ERR_RET(GUEST_CR0, m_GuestState.cr0);
	VMWRITE_ERR_RET(GUEST_CR3, m_GuestState.cr3);
	VMWRITE_ERR_RET(GUEST_CR4, m_GuestState.cr4);
	VMWRITE_ERR_RET(CR0_READ_SHADOW, m_GuestState.cr0);
	VMWRITE_ERR_RET(CR4_READ_SHADOW, m_GuestState.cr4);

	VMWRITE_ERR_RET(GUEST_DR7, m_GuestState.dr7);
	VMWRITE_ERR_RET(GUEST_IA32_DEBUGCTL, m_GuestState.msr_debugctl);

	VMWRITE_ERR_RET(GUEST_RSP, m_GuestState.rsp);
	VMWRITE_ERR_RET(GUEST_RIP, m_GuestState.rip);
	VMWRITE_ERR_RET(GUEST_RFLAGS, m_GuestState.rflags);

	// Host status

	VMWRITE_ERR_RET(HOST_CS_SELECTOR, m_HostState.cs);
	VMWRITE_ERR_RET(HOST_DS_SELECTOR, m_HostState.ds);
	VMWRITE_ERR_RET(HOST_SS_SELECTOR, m_HostState.ss);
	VMWRITE_ERR_RET(HOST_ES_SELECTOR, m_HostState.es);

	VMWRITE_ERR_RET(HOST_FS_BASE, m_HostState.fsbase);
	VMWRITE_ERR_RET(HOST_FS_SELECTOR, m_HostState.fs);

	VMWRITE_ERR_RET(HOST_GS_BASE, m_HostState.gsbase);
	VMWRITE_ERR_RET(HOST_GS_SELECTOR, m_HostState.gs);

	VMWRITE_ERR_RET(HOST_TR_BASE, m_HostState.trbase);
	VMWRITE_ERR_RET(HOST_TR_SELECTOR, m_HostState.tr);

	VMWRITE_ERR_RET(GUEST_GDTR_BASE, m_HostState.gdt.ulBase);
	VMWRITE_ERR_RET(GUEST_IDTR_BASE, m_HostState.idt.ulBase);

	VMWRITE_ERR_RET(HOST_CR0, m_HostState.cr0);
	VMWRITE_ERR_RET(HOST_CR3, m_HostState.cr3);
	VMWRITE_ERR_RET(HOST_CR4, m_HostState.cr4);

	VMWRITE_ERR_RET(HOST_RSP, m_HostState.rsp);
	VMWRITE_ERR_RET(HOST_RIP, m_HostState.rip);

	// Initialization of VMCS completed
	DbgPrint("Debug:[%d] Prepare to start virtualization\n", m_CPU);
	m_VMXOn = TRUE;
	vmxlaunch();  // If this statement is executed successfully, it will not return

	DbgPrint("Debug:[%d] It shouldn't be executed here \n", m_CPU);
	__vmx_off();
	m_VMXOn = FALSE;
	return;
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
		DbgPrintEx(77,0,"Debug:[%d] EPT !\n", m_CPU);
		return;
	}

	RtlSecureZeroMemory(m_EPT, sizeof(VMX_EPT));
	DbgPrintEx(77,0,"Debug:[%d]EPT ------>%p\n", m_CPU, m_EPT);

 	mtrrCapabilities.AsUlonglong = __readmsr(MTRR_MSR_CAPABILITIES);
	DbgPrintEx(77,0,"Debug:[%d]mtrrCapabilities------>0x%016llX\n", m_CPU, mtrrCapabilities.AsUlonglong);
	DbgPrintEx(77,0,"Debug:[%d]mtrrCapabilities.u.VarCnt------>0x%X\n", m_CPU, mtrrCapabilities.u.VarCnt);
	for (i = 0; i < mtrrCapabilities.u.VarCnt; i++)
	{
		mtrrBase.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_BASE + i * 2);
		mtrrMask.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_MASK + i * 2);

		mtrrData[i].Type = (UINT32)mtrrBase.u.Type;
		mtrrData[i].Enabled = (UINT32)mtrrMask.u.Enabled;
 		if (mtrrData[i].Enabled != FALSE)
		{
 			mtrrData[i].PhysicalAddressMin = mtrrBase.u.PhysBase * MTRR_PAGE_SIZE;

			_BitScanForward64(&bit, mtrrMask.u.PhysMask * MTRR_PAGE_SIZE);
			mtrrData[i].PhysicalAddressMax = mtrrData[i].PhysicalAddressMin + (1ULL << bit) - 1;
		}
	}

 	m_EPT->PML4T[0].u.Read = 1;
	m_EPT->PML4T[0].u.Write = 1;
	m_EPT->PML4T[0].u.Execute = 1;
	m_EPT->PML4T[0].u.PDPTAddress = MmGetPhysicalAddress(&m_EPT->PDPT).QuadPart / PAGE_SIZE;
 
	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
 		m_EPT->PDPT[i].u.Read = 1;
		m_EPT->PDPT[i].u.Write = 1;
		m_EPT->PDPT[i].u.Execute = 1;
		m_EPT->PDPT[i].u.PDTAddress = MmGetPhysicalAddress(&m_EPT->PDT[i][0]).QuadPart / PAGE_SIZE;
	}

	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
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
 				if (mtrrData[k].Enabled != FALSE)
				{
 					if (((LargePageAddress + _2MB) >= mtrrData[k].PhysicalAddressMin) &&
						(LargePageAddress <= mtrrData[k].PhysicalAddressMax))
					{
 						CandidateMemoryType = mtrrData[k].Type;
					}
				}
			}

			m_EPT->PDT[i][j].u.Type = CandidateMemoryType;
		}
	}

	DbgPrintEx(77,0,"Debug:[%d] EPT !\n", m_CPU);
}