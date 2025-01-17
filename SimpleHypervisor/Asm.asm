
_ASM segment para 'CODE'

extern VMExitHandler :PROC

SAVESTATE MACRO
	push r15
	mov r15,rsp  ;First save the original stack top (RSP before entering the takeover function)
	add r15,8
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push r15    ;rsp
	push rbx
	push rdx
	push rcx
	push rax
ENDM

LOADSTATE MACRO
	pop rax
	pop rcx
	pop rdx
	pop rbx
	add rsp, 8
	pop rbp
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
ENDM

ALIGN 16

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

__invd PROC ; what if we just "mov eax,cr3;mov cr3, eax"
 invd
 ret
__invd ENDP

__writeds PROC
 mov ds, cx
 ret
__writeds ENDP

__writees PROC
 mov es, cx
 ret
__writees ENDP

__writefs PROC
 mov fs, cx
 ret
__writefs ENDP

Asm_StackPointer PROC
 mov rax, rsp
 sub rax, sizeof(QWORD)		; 
 ret
Asm_StackPointer ENDP

Asm_NextInstructionPointer PROC
 mov rax, [rsp]
 ret
Asm_NextInstructionPointer ENDP


Asm_VMExitHandler PROC
	cli
	SAVESTATE   ;Save state
	mov   rcx,rsp   ;Put the top of the stack to rcx

	sub   rsp,0100h
	call  VMExitHandler ;Call VMExitHandler(__fastcall)
	add   rsp,0100h


	LOADSTATE   ;Restoration register
	sti
__do_resume:
	vmresume;   Return to VM non-root (return to the Guest environment to continue execution)



Asm_VMExitHandler ENDP

_ASM ENDS
END