#pragma once

EXTERN_C
ULONG_PTR Asm_StackPointer();

EXTERN_C
ULONG_PTR Asm_NextInstructionPointer();


EXTERN_C ULONG_PTR __readcs();

EXTERN_C ULONG_PTR __readds();

EXTERN_C ULONG_PTR __readss();

EXTERN_C ULONG_PTR __reades();

EXTERN_C ULONG_PTR __readfs();

EXTERN_C ULONG_PTR __readgs();

EXTERN_C ULONG_PTR __sldt();

EXTERN_C ULONG_PTR __str();

EXTERN_C ULONG_PTR __sgdt(PGDT gdtr);