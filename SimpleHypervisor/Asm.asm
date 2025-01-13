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

END