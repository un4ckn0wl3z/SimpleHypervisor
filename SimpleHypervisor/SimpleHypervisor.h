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

#define MSR_IA32_MTRRCAP			0xfe
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
#define MSR_GS_BASE 0xC0000101

//------------------------------------------
#define FEATURE_CONTROL_LOCKED	(1 << 0)
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1 << 1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1 << 2)


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
#pragma pack(push,1)
// EPTP Struct
typedef struct _VMX_EPTP
{
	union
	{
		struct
		{
			UINT64 Type : 3;
			UINT64 PageWalkLength : 3;
			UINT64 EnableAccessAndDirtyFlags : 1;
			UINT64 Reserved : 5;
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 16;
		}u;

		UINT64 AsUlonglong;
	};


}VMX_EPTP, * PVMX_EPTP;
static_assert(sizeof(VMX_EPTP) == sizeof(UINT64), "EPTP Size Mismatch");

// PML4E Struct
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
			UINT64 SofewareUse : 1;
			UINT64 UserModeExecute : 1;
			UINT64 SofewareUse2 : 1;
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 4;
			UINT64 SofewareUseHigh : 12;
		}u;

		UINT64 AsUlonglong;
	};

}VMX_PML4E, * PVMX_PML4E;
static_assert(sizeof(VMX_PML4E) == sizeof(UINT64), "PML4E Size Mismatch");

// HUGE_PDPTE Struct
typedef struct _VMX_HUGE_PDPTE
{
	union
	{
		struct
		{
			UINT64 Read : 1;  //0
			UINT64 Write : 1; //1
			UINT64 Execute : 1;  //2
			UINT64 Type : 3;     //5:3
			UINT64 IgnorePat : 1;//6
			UINT64 Large : 1;    //7
			UINT64 Accessed : 1; //8
			UINT64 Dirty : 1;    //9
			UINT64 UserModeExecute : 1;//10
			UINT64 SofewareUse : 1;    //11
			UINT64 Reserved : 18;   //29:12
			UINT64 PageFrameNumber : 18; //(N-1):30
			UINT64 ReservedHigh : 4;
			UINT64 SoftworeUseHigh : 11;
			UINT64 SuppressVme : 1;
		}u;

		UINT64 AsUlonglong;
	};

}VMX_HUGE_PDPTE, * PVMX_HUGE_PDPTE;
static_assert(sizeof(VMX_HUGE_PDPTE) == sizeof(UINT64), "HUGE_PDPTE Size Mismatch");

// PDPTE Struct
typedef struct _VMX_PDPTE
{
	union
	{
		struct
		{
			UINT64 Read : 1;  //0
			UINT64 Write : 1; //1
			UINT64 Execute : 1;  //2
			UINT64 Reserved : 5; //7:3
			UINT64 Accessed : 1; //8
			UINT64 SoftwareUse : 1; //9
			UINT64 UserModeExecute : 1;//10
			UINT64 SofewareUse2 : 1;    //11
			UINT64 PageFrameNumber : 36;
			UINT64 ReservedHigh : 4;
			UINT64 SoftworeUseHigh : 12; //63:52
		}u;

		UINT64 AsUlonglong;
	};

}VMX_PDPTE, * PVMX_PDPTE;
static_assert(sizeof(VMX_PDPTE) == sizeof(UINT64), "PDPTE Size Mismatch");

// LARGE_PDE Struct
typedef struct _VMX_LARGE_PDE
{
	union
	{
		struct
		{
			UINT64 Read : 1;  //0
			UINT64 Write : 1; //1
			UINT64 Execute : 1;  //2
			UINT64 Type : 3;     //5:3
			UINT64 IgnorePat : 1;//6
			UINT64 Large : 1;    //7
			UINT64 Accessed : 1; //8
			UINT64 Dirty : 1;    //9
			UINT64 UserModeExecute : 1;//10
			UINT64 SofewareUse : 1;    //11
			UINT64 Reserved : 9;   //20:12
			UINT64 PageFrameNumber : 27; //(N-1):21
			UINT64 ReservedHigh : 4;
			UINT64 SoftworeUseHigh : 11; //62:52
			UINT64 SuppressVme : 1;
		}u;

		UINT64 AsUlonglong;
	};

}VMX_LARGE_PDE, * PVMX_LARGE_PDE;
static_assert(sizeof(VMX_LARGE_PDE) == sizeof(UINT64), "LARGE_PDE Size Mismatch");

// PDE Struct
typedef struct _VMX_PDE
{
	union
	{
		struct
		{
			UINT64 Read : 1;  //0
			UINT64 Write : 1; //1
			UINT64 Execute : 1;  //2
			UINT64 Reserved : 4;     //6:3
			UINT64 Small : 1;    //7
			UINT64 Accessed : 1; //8
			UINT64 SofewareUse : 1;    //9
			UINT64 UserModeExecute : 1;//10
			UINT64 SofewareUse2 : 1;   //11
			UINT64 PageFrameNumber : 36; //(N-1):12
			UINT64 ReservedHigh : 4;
			UINT64 SoftworeUseHigh : 12; //63:52
		}u;

		UINT64 AsUlonglong;
	};

}VMX_PDE, * PVMX_PDE;
static_assert(sizeof(VMX_PDE) == sizeof(UINT64), "PDE Size Mismatch");


#define PML4E_ENTRY_COUNT 512
#define PDPTE_ENTRY_COUNT 512
#define PDE_ENTRY_COUNT   512

typedef struct _VMX_EPT
{
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_PML4E PML4T[PML4E_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_PDPTE PDPT[PDPTE_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_LARGE_PDE PDT[PDPTE_ENTRY_COUNT][PDE_ENTRY_COUNT];
}VMX_EPT, * PVMX_EPT;

typedef struct _MTRR_CAPABILITIES
{
	union
	{
		struct
		{
			UINT64 VarCnt : 8;
			UINT64 FixedSupported : 1;
			UINT64 Reserved : 1;
			UINT64 WcSupported : 1;
			UINT64 SmrrSupported : 1;
			UINT64 Reserved2 : 52;
		}u;

		UINT64 AsUlonglong;
	};
}MTRR_CAPABILITIES, * PMTRR_CAPABILITIES;
static_assert(sizeof(MTRR_CAPABILITIES) == sizeof(UINT64), "MTRR_CAPABILITIES Size Mismatch");

typedef struct _MTRR_VARIABLE_BASE
{
	union
	{
		struct
		{
			UINT64 Type : 8;
			UINT64 Reserved : 4;
			UINT64 PhysBase : 36;
			UINT64 Reserved2 : 16;
		}u;

		UINT64 AsUlonglong;
	};
}MTRR_VARIABLE_BASE, * PMTRR_VARIABLE_BASE;
static_assert(sizeof(MTRR_VARIABLE_BASE) == sizeof(UINT64), "MTRR_VARIABLE_BASE Size Mismatch");

typedef struct _MTRR_VARIABLE_MASK
{
	union
	{
		struct
		{
			UINT64 Reserved : 11;
			UINT64 Enabled : 1;
			UINT64 PhysMask : 36;
			UINT64 Reserved2 : 16;
		}u;

		UINT64 AsUlonglong;
	};
}MTRR_VARIABLE_MASK, * PMTRR_VARIABLE_MASK;
C_ASSERT(sizeof(MTRR_VARIABLE_MASK) == sizeof(UINT64));
//static_assert(sizeof(MTRR_VARIABLE_MASK) == sizeof(UINT64), "MTRR_VARIABLE_MASK Size Mismatch");

#pragma pack(pop)


typedef struct _SHV_MTRR_RANGE
{
	UINT32 Enabled;
	UINT32 Type;
	UINT64 PhysicalAddressMin;
	UINT64 PhysicalAddressMax;
}SHV_MTRR_RANGE, * PSHV_MTRR_RANGE;

#define MTRR_MSR_CAPABILITIES   0x0fe
#define MTRR_MSR_DEFAULT        0x2ff
#define MTRR_MSR_VARIABLE_BASE  0x200
#define MTRR_MSR_VARIABLE_MASK  (MTRR_MSR_VARIABLE_BASE+1)
#define MTRR_PAGE_SIZE          4096
#define MTRR_PAGE_MASK          (~(MTRR_PAGE_SIZE-1))
//---------------------------------------

#define _1GB (1 * 1024 * 1024 * 1024)
#define _2MB (2 * 1024 * 1024)
#define MTRR_TYPE_UC  0
#define MTRR_TYPE_WC  1
#define MTRR_TYPE_WT  4
#define MTRR_TYPE_WP  5
#define MTRR_TYPE_WB  6
#define MTRR_TYPE_MAX 7

// --------------------------------------

enum VMCSFIELD {
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
	EPTP_INDEX = 0x00000004,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	GUEST_PML_INDEX = 0x00000812,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_B = 0x00002002,
	MSR_BITMAP = 0x00002004,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	PML_ADDRESS = 0x0000200e,
	TSC_OFFSET = 0x00002010,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	APIC_ACCESS_ADDR = 0x00002014,
	PI_DESC_ADDR = 0x00002016,
	VM_FUNCTION_CONTROL = 0x00002018,
	EPT_POINTER = 0x0000201a,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EPTP_LIST_ADDR = 0x00002024,
	VMREAD_BITMAP = 0x00002026,
	VMWRITE_BITMAP = 0x00002028,
	VIRT_EXCEPTION_INFO = 0x0000202a,
	XSS_EXIT_BITMAP = 0x0000202c,
	TSC_MULTIPLIER = 0x00002032,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	VMCS_LINK_POINTER = 0x00002800,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_PAT = 0x00002804,
	GUEST_EFER = 0x00002806,
	GUEST_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_PDPTE0 = 0x0000280a,
	GUEST_BNDCFGS = 0x00002812,
	HOST_PAT = 0x00002c00,
	HOST_EFER = 0x00002c02,
	HOST_PERF_GLOBAL_CTRL = 0x00002c04,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	IDT_VECTORING_INFO = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0x00004826,
	GUEST_SMBASE = 0x00004828,
	GUEST_SYSENTER_CS = 0x0000482a,
	GUEST_PREEMPTION_TIMER = 0x0000482e,
	HOST_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	EXIT_QUALIFICATION = 0x00006400,
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_SYSENTER_ESP = 0x00006c10,
	HOST_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};

// -------------------------------------------------

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
		, m_EPT(NULL)
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
	VOID InitializeEPT();

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

	VMX_EPT* m_EPT;

};