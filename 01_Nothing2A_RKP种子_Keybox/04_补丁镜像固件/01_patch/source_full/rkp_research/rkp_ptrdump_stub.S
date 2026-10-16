.text
.global _start
_start:
    mov x0, x20
    ldr x1, [sp, #216]
    mov x2, #2048
    bl 0x50f0
    mov w0, #2048
    stur w0, [x27, #25]
    ldp x25, x26, [sp, #80]
    stur w21, [x27, #17]
    b 0x21c9c
