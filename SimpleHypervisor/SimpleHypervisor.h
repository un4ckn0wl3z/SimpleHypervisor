#pragma once

typedef struct _CPUID_ECX
{
	unsigned SSE3 : 1;
	unsigned PCLMULQDQ : 1;
	unsigned DTES64 : 1;
	unsigned MONITOR : 1;
	unsigned DS_CPL : 1;
	unsigned VMX : 1;
	unsigned SMX : 1;
	unsigned EIST : 1;
	unsigned TM2 : 1;
	unsigned SSSE3 : 1;
	unsigned Reserved : 22;
	unsigned Reserved_64 : 32;
}CPUID_ECX;

/* CPUID */
// {
#define CPUID_1_ECX_VMX (1<<5)
// }

/* MSRs */
#define IA32_FEATURE_CONTROL_CODE		        0x03A
#define IA32_SYSENTER_CS                        0x174
#define IA32_SYSENTER_ESP                       0x175
#define IA32_SYSENTER_EIP                       0x176
#define IA32_DEBUGCTL                           0x1D9
#define IA32_VMX_BASIC_MSR_CODE			        0x480
#define IA32_VMX_PINBASED_CTLS                  0x481
#define IA32_VMX_PROCBASED_CTLS                 0x482
#define IA32_VMX_EXIT_CTLS                      0x483
#define IA32_VMX_ENTRY_CTLS                     0x484
#define IA32_VMX_MISC                           0x485
#define IA32_VMX_CR0_FIXED0                     0x486
#define IA32_VMX_CR0_FIXED1                     0x487
#define IA32_VMX_CR4_FIXED0                     0x488
#define IA32_VMX_CR4_FIXED1                     0x489
#define	IA32_FS_BASE    						0xc0000100
#define	IA32_GS_BASE							0xc0000101
#define IA32_VMX_PROCBASED_CTLS2				0x0000048B

#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_VMCS_ENUM                  0x48a
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490

#define MSR_IA32_MTRRCAP				0xfe
#define MSR_IA32_MTRR_DEF_TYPE			0x2ff
#define MSR_IA32_MTRR_PHYSBASE(n)		(0x200 + 2*(n))
#define MSR_IA32_MTRR_PHYSMASK(n)		(0x200 + 2*(n) + 1)
#define MSR_IA32_MTRR_FIX64K_00000		0x250
#define MSR_IA32_MTRR_FIX16K_80000		0x258
#define MSR_IA32_MTRR_FIX16K_A0000		0x259
#define MSR_IA32_MTRR_FIX4K_C0000		0x268
#define MSR_IA32_MTRR_FIX4K_C8000		0x269
#define MSR_IA32_MTRR_FIX4K_D0000		0x26a
#define MSR_IA32_MTRR_FIX4K_D8000		0x26b
#define MSR_IA32_MTRR_FIX4K_E0000		0x26c
#define MSR_IA32_MTRR_FIX4K_E8000		0x26d
#define MSR_IA32_MTRR_FIX4K_F0000		0x26e
#define MSR_IA32_MTRR_FIX4K_F8000		0x26f
#define MSR_GS_BASE						0xC0000101


//------------------------------------------
#define FEATURE_CONTROL_LOCKED	(1 << 0)
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1 << 1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1 << 2)
//------------------------------------------

#define ROUNDUP(x,align) ((x + align - 1) & ~(align - 1))

//------------------------------------------
/* GDT */
typedef struct _GDT {
	USHORT wLimit;
	ULONG_PTR ulBase;
} GDT, * PGDT;

/* IDT */
typedef struct _IDT {
	USHORT wLimit;
	ULONG_PTR ulBase;
} IDT, * PIDT;

typedef struct _HOST_STATE {
	ULONG_PTR cr0;
	ULONG_PTR cr3;
	ULONG_PTR cr4;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	ULONG_PTR tr;
	ULONG_PTR fsbase;
	ULONG_PTR gsbase;
	ULONG_PTR trbase;
	GDT gdt;
	IDT idt;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_esp;
	ULONG_PTR msr_sysenter_eip;
} HOST_STATE, * PHOST_STATE;
//---------------------------------------

typedef struct _GUEST_STATE {
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	GDT gdt;
	IDT idt;
	ULONG_PTR ldtr;
	ULONG_PTR tr;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR rflags;
	ULONG_PTR cr0;
	ULONG_PTR cr4;
	ULONG_PTR cr3;
	ULONG_PTR dr7;
	ULONG_PTR msr_debugctl;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_eip;
	ULONG_PTR msr_sysenter_esp;

	ULONG_PTR msr_perf_global_ctrl;
	ULONG_PTR msr_pat;
	ULONG_PTR msr_efer;
	ULONG_PTR msr_bndcfgs;
} GUEST_STATE, * PGUEST_STATE;

//---------------------------------------

#define PML4E_ENTRY_COUNT	512
#define PDPTE_ENTRY_COUNT	512
#define PDE_ENTRY_COUNT		512

// EPTP struct
typedef struct _VMX_EPTP
{
	union 
	{
		struct
		{
			UINT64 Type : 3;
			UINT64 PageWalkLen : 3;
			UINT64 EnableAccessAndDirtyFlags : 1;
			UINT64 Reserved : 5;
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 15;
		};
	};

	UINT64 AsUlonglong;
} VMX_EPTP, * PVMX_EPTP;


// PML4E struct

typedef struct _VMX_PML4E
{

	union
	{
		struct
		{
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Reserved : 5;
			UINT64 Accessed : 1;
			UINT64 SoftwareUse : 1;
			UINT64 UserModeExecute : 1;
			UINT64 SoftwareUse2 : 1;
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 4;
			UINT64 SoftwareUseHigh : 12;
		};
	};

	UINT64 AsUlonglong;

}VMX_PML4E, * PVMX_PML4E;


// PDPTE struct

typedef struct _VMX_PDPTE
{

	union
	{
		struct
		{
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Type : 3;
			UINT64 IgnorePat : 1;
			UINT64 Large : 1;
			UINT64 Accessed : 1;
			UINT64 Dirty : 1;
			UINT64 UserModeExecute : 1;
			UINT64 SoftwareUse : 1;
			UINT64 Reserved : 18;
			UINT64 PageFrameNumber : 18;
			UINT64 ReservedHigh : 4;
			UINT64 SoftwareUseHigh : 11;
			UINT64 SuppressVme : 1;

		};
	};

	UINT64 AsUlonglong;

}VMX_PDPTE, * PVMX_PDPTE;

// 00:29:42

typedef struct _VMX_EPT
{

	DECLSPEC_ALIGN(PAGE_SIZE) VMX_PML4E Pml4[PML4E_ENTRY_COUNT];


}VMX_EPT;

//---------------------------------------

class SimpleHypervisor
{
public:
	SimpleHypervisor(ULONG uCPU)
		: m_CPU(uCPU)
		, m_VMXRegion(NULL)
		, m_VMCSRegion(NULL)
		, m_MsrBitmapRegion(NULL)
		, m_VMXOn(FALSE)
		, m_VMXRegionPhysAddr(0)
		, m_VMCSRegionPhysAddr(0)
		, m_MsrBitmapRegionPhysAddr(0)
	{

	}

public:
	BOOLEAN Initialize();
	BOOLEAN Install();
	BOOLEAN UnInstall();
	VOID UnInitialize();

protected:
	BOOLEAN CheckVTSupported();
	BOOLEAN CheckVTEnable();
	VOID SetVMExitHandler(ULONG_PTR HandlerEntryPoint, ULONG_PTR HandlerStack);
	BOOLEAN InitVMCS();

private:
	ULONG m_CPU;
	ULONG_PTR* m_VMXRegion;
	ULONG_PTR* m_VMCSRegion;
	UINT8* m_MsrBitmapRegion;

	ULONG_PTR m_VMXRootStackRegion;
	BOOLEAN m_VMXOn;

	HOST_STATE m_HostState;
	GUEST_STATE m_GuestState;

	ULONG_PTR m_VMXRegionPhysAddr;
	ULONG_PTR m_VMCSRegionPhysAddr;
	ULONG_PTR m_MsrBitmapRegionPhysAddr;

	ULONG_PTR StackPointer;
	ULONG_PTR ReturnAddress;

	ULONG_PTR m_VmxBasic;
	ULONG_PTR m_VmxFeatureControl;


};