_ASM segment para 'CODE'

ALIGN 16

Asm_StackPointer PROC

	mov rax, rsp
	sub rax, sizeof(QWORD)
	ret

Asm_StackPointer ENDP

Asm_NextInstructionPointer PROC

	mov rax, [rsp]
	ret

Asm_NextInstructionPointer ENDP

__readcs PROC 

	mov rax, cs
	ret

__readcs ENDP


__readds PROC 

	mov rax, ds
	ret

__readds ENDP

__readss PROC 

	mov rax, ss
	ret

__readss ENDP


__reades PROC 

	mov rax, es
	ret

__reades ENDP


__readfs PROC 

	mov rax, fs
	ret

__readfs ENDP

__readgs PROC 

	mov rax, gs
	ret

__readgs ENDP

__sldt PROC 

	sldt rax
	ret

__sldt ENDP

__str PROC 

	str rax
	ret

__str ENDP


__sgdt PROC 

	mov rax, rcx
	sgdt [rax]
	ret

__sgdt ENDP

END