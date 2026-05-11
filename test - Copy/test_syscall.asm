; Test NtQuerySystemTime syscall directly
; ml64 /c test_syscall.asm
; link test_syscall.obj /entry:main /subsystem:console

.code

main proc
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    sub rsp, 28h        ; shadow space + alignment

    ; Allocate output buffer on stack
    sub rsp, 10h
    mov qword ptr [rsp], 0   ; zero-init

    ; r10 = pointer to output
    lea r10, [rsp]

    ; eax = SSN for NtQuerySystemTime (0x5B)
    mov eax, 5Bh

    ; syscall
    syscall

    ; Check output
    mov rax, [rsp]
    test rax, rax
    jnz good

    ; Bad - output is zero
    mov ecx, 1
    jmp done

good:
    xor ecx, ecx

done:
    add rsp, 10h
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    mov eax, ecx
    ret
main endp

end
