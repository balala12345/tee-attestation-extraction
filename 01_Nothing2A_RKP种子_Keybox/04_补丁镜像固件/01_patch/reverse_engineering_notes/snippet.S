.text
.global _start
_start:
  ldp x0, x1, [sp, #72]
  mov x2, x1
  mov x1, x0
  mov x0, x20
  .word 0x97ff0fcd
  ldp x0, x1, [sp, #72]
  .word 0x97ff71fd
  .word 0x17ff735f
  mov w19, w0
  cbnz w0, skip
  ldr x1, [sp, #48]
  mov x0, x22
  mov x2, x21
  .word 0x97ff0fc4
skip:
  .word 0x17ff74bd
