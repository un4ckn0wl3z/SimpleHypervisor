#pragma once

EXTERN_C ULONG_PTR Asm_StackPointer();
EXTERN_C ULONG_PTR Asm_NextInstructionPointer();

EXTERN_C ULONG_PTR __readcs(void);
EXTERN_C ULONG_PTR __readds(void);
EXTERN_C ULONG_PTR __readss(void);
EXTERN_C ULONG_PTR __reades(void);
EXTERN_C ULONG_PTR __readfs(void);
EXTERN_C ULONG_PTR __readgs(void);
EXTERN_C ULONG_PTR __sldt(void);
EXTERN_C ULONG_PTR __str(void);
EXTERN_C ULONG_PTR __sgdt(PGDT gdtr);
EXTERN_C void __invd(void);
EXTERN_C void __writeds(ULONG_PTR DS);
EXTERN_C void __writees(ULONG_PTR ES);
EXTERN_C void __writefs(ULONG_PTR FS);

EXTERN_C void Asm_VMExitHandler(void);
EXTERN_C void Asm_VmxCall(ULONG64 uCallNumber);
EXTERN_C void Asm_AfterVMXOff(ULONG64 JmpESP, ULONG64 JmpEIP);