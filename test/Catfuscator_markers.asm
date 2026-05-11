;
; Catfuscator SDK - Marker functions for x64
; Assemble: ml64 /c Catfuscator_markers.asm
; Link the resulting .obj into your project
;
; Each marker is a stub: mov eax, MAGIC; ret (6 bytes)
; The protector scans for CALLs whose target starts with B8 XX XX CA A1 C3
; At runtime these are harmless no-ops (clobber eax + return)
;

.code

CatfuscatorVirtualizeBegin PROC
    mov eax, 0A1CA0001h
    ret
CatfuscatorVirtualizeBegin ENDP

CatfuscatorVirtualizeEnd PROC
    mov eax, 0A1CA0002h
    ret
CatfuscatorVirtualizeEnd ENDP

CatfuscatorMutateBegin PROC
    mov eax, 0A1CA0003h
    ret
CatfuscatorMutateBegin ENDP

CatfuscatorMutateEnd PROC
    mov eax, 0A1CA0004h
    ret
CatfuscatorMutateEnd ENDP

CatfuscatorUltraBegin PROC
    mov eax, 0A1CA0005h
    ret
CatfuscatorUltraBegin ENDP

CatfuscatorUltraEnd PROC
    mov eax, 0A1CA0006h
    ret
CatfuscatorUltraEnd ENDP

END
