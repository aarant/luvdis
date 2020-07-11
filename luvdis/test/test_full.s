.syntax unified
.text
.thumb
  @ THUMB.1
  lsls r0,r1,#2
  lsrs r2,r3,#32
  @ THUMB.2
  adds r0,r1,r2
  subs r0,r1,#7
  @ THUMB.3
  movs r0,#0xff
  cmp r1,#0x80
  @ THUMB.4
  ands r0, r1
  eors r0, r2
  lsls r0, r3
  lsrs r0, r4
  asrs r0, r5
  adcs r0, r6
  sbcs r0, r7
  rors r1, r1
  tst r2, r1
  negs r3, r1
  cmp r4, r1
  cmn r5, r1
  orrs r6, r1
  muls r7, r1
  bics r0, r1
  mvns r0, r1
  @ THUMB.5
  add r0, r8
  cmp r1, r9
  mov r2, sp
  nop
  mov lr, r0
  mov pc, r1
  bx lr
  @ THUMB.6
  ldr r0, [pc,#4]
  @ THUMB.7
  str r0, [r1, r2]
  strb r3, [r4, r5]
  ldr r6, [r7, r0]
  ldrb r1, [r2, r3]
  @ THUMB.8
  strh r0, [r1, r2]
  ldsb r3, [r4, r5]
  ldrh r6, [r7, r0]
  ldsh r1, [r2, r3]
  @ THUMB 9
  str r0, [r1, #124]
  ldr r2, [r3, #4]
  strb r4, [r5, #6]
  ldrb r6, [r7, #31]
  @ THUMB.10
  strh r0, [r1, #2]
  ldrh r2, [r3, #62]
  @ THUMB.11
  str r0, [sp,#1020]
  ldr r1, [sp,#4]
  @ THUMB.12
  add r0, pc, #4
  add r1, sp, #1020
  @ THUMB.13
  add sp, #508
  add sp, #-508
  @ THUMB.14
  push {r0, r2, r4, r6, lr}
  pop {r1, r3, r5, r7, pc}
  @ THUMB.15
  stmia r0!, {r2, r4, r6}
  ldmia r1!, {r3, r5, r7}
  @ THUMB.16
  beq label
  bne label
  beq label
  bcs label
  bcc label
  bmi label
  bpl label
  bvs label
  bvc label
  bhi label
  bls label
  bge label
  blt label
  bgt label
  ble label
label:
  @ THUMB.18
  b label
  @ THUMB.19
  bl label
  bl label2
  @ Partial BL
  .2byte 0xF801 @ BL lr+2
label2:
  swi #5
