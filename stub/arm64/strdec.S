.section .text
.balign 4
// Keep a non-zero symbol entry offset so the Go injector must use the actual
// strdec_entry symbol offset instead of accidentally jumping to payload base.
.space 0x50, 0
.global strdec_entry
.type strdec_entry, %function

strdec_entry:
    sub sp, sp, #1584
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]

    // Disable core dumps early. This is best-effort and intentionally
    // ignores errors on kernels/builds which restrict prctl.
    mov x0, #4
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #167
    svc #0

    // Best-effort anti-attach: if PTRACE_TRACEME is accepted, late debugger
    // attaches are blocked by the kernel. Failure is non-fatal for Android
    // builds which restrict ptrace/syscalls in app contexts.
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x8, #117
    svc #0
    mov x27, x0

    // Best-effort anti-Frida probe: decode "/proc/self/maps" only on the
    // stack, read a few small maps windows, and trap if common Frida/Gum/Gadget
    // markers are present. Probe strings are not stored as contiguous plaintext.
    adr x0, strdec_maps_path_xor
    add x1, sp, #272
    mov w2, #16
91:
    ldrb w3, [x0], #1
    mov w5, #0x5a
    eor w3, w3, w5
    strb w3, [x1], #1
    subs w2, w2, #1
    b.ne 91b
    mov x0, #-100
    add x1, sp, #272
    mov x2, #0
    mov x3, #0
    mov x8, #56
    svc #0
    cmp x0, #0
    b.lt 98f
    mov x6, x0
    mov w18, #0
.Lmaps_read_loop:
    mov x0, x6
    add x1, sp, #320
    mov x2, #512
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le 97f
    mov x4, x0
    mov x2, #0
92:
    cmp x2, x4
    b.hs .Lmaps_after_scan
    add x3, x1, x2
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x66
    b.ne 93f
    add x7, x2, #4
    cmp x7, x4
    b.hs 93f
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x72
    b.ne 93f
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x69
    b.ne 93f
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne 93f
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.eq 99f
93:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne 96f
    add x7, x2, #2
    cmp x7, x4
    b.hs 96f
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x75
    b.ne 96f
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x6d
    b.eq 99f
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne 96f
    add x7, x2, #5
    cmp x7, x4
    b.hs 96f
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.ne 96f
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne 96f
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne 96f
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x65
    b.ne 96f
    ldrb w5, [x3, #5]
    orr w5, w5, #0x20
    cmp w5, #0x74
    b.eq 99f
96:
    add x2, x2, #1
    b 92b
.Lmaps_after_scan:
    add w18, w18, #1
    cmp w18, #4
    b.lo .Lmaps_read_loop
97:
    mov x0, x6
    mov x8, #57
    svc #0
98:
    b 100f
99:
    brk #0xf1d
100:

    // Best-effort smaps probe: same marker scan as maps, but smaps can expose
    // injected anonymous/memfd regions which some maps sanitizers hide.
    adr x0, strdec_smaps_path_xor
    add x1, sp, #272
    mov w2, #17
.Lsmaps_decode_loop:
    ldrb w3, [x0], #1
    mov w5, #0x5a
    eor w3, w3, w5
    strb w3, [x1], #1
    subs w2, w2, #1
    b.ne .Lsmaps_decode_loop
    mov x0, #-100
    add x1, sp, #272
    mov x2, #0
    mov x3, #0
    mov x8, #56
    svc #0
    cmp x0, #0
    b.lt .Lsmaps_done
    mov x6, x0
    mov w18, #0
.Lsmaps_read_loop:
    mov x0, x6
    add x1, sp, #320
    mov x2, #512
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le .Lsmaps_close
    mov x4, x0
    mov x2, #0
.Lsmaps_scan_loop:
    cmp x2, x4
    b.hs .Lsmaps_after_scan
    add x3, x1, x2
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x66
    b.ne .Lsmaps_check_gum
    add x7, x2, #4
    cmp x7, x4
    b.hs .Lsmaps_check_gum
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x72
    b.ne .Lsmaps_check_gum
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x69
    b.ne .Lsmaps_check_gum
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Lsmaps_check_gum
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.eq .Lsmaps_trap
.Lsmaps_check_gum:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lsmaps_check_gadget
    add x7, x2, #2
    cmp x7, x4
    b.hs .Lsmaps_check_gadget
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x75
    b.ne .Lsmaps_check_gadget
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x6d
    b.eq .Lsmaps_trap
.Lsmaps_check_gadget:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lsmaps_next
    add x7, x2, #5
    cmp x7, x4
    b.hs .Lsmaps_next
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.ne .Lsmaps_next
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Lsmaps_next
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lsmaps_next
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x65
    b.ne .Lsmaps_next
    ldrb w5, [x3, #5]
    orr w5, w5, #0x20
    cmp w5, #0x74
    b.eq .Lsmaps_trap
.Lsmaps_next:
    add x2, x2, #1
    b .Lsmaps_scan_loop
.Lsmaps_after_scan:
    add w18, w18, #1
    cmp w18, #3
    b.lo .Lsmaps_read_loop
.Lsmaps_close:
    mov x0, x6
    mov x8, #57
    svc #0
.Lsmaps_done:
    b .Lsmaps_after_trap
.Lsmaps_trap:
    brk #0x5aa
.Lsmaps_after_trap:

    // Best-effort anti-debugger status probe: decode "/proc/self/status" on
    // stack and trap when TracerPid reports a non-zero tracer. Plaintext path
    // and marker are not stored as contiguous data bytes in the binary.
    adr x0, strdec_status_path_xor
    add x1, sp, #272
    mov w2, #18
.Lstatus_decode_loop:
    ldrb w3, [x0], #1
    mov w5, #0x5a
    eor w3, w3, w5
    strb w3, [x1], #1
    subs w2, w2, #1
    b.ne .Lstatus_decode_loop
    mov x0, #-100
    add x1, sp, #272
    mov x2, #0
    mov x3, #0
    mov x8, #56
    svc #0
    cmp x0, #0
    b.lt .Lstatus_done
    mov x6, x0
    mov x0, x6
    add x1, sp, #320
    mov x2, #512
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le .Lstatus_close
    mov x4, x0
    add x4, x1, x4
    mov x2, #0
.Lstatus_scan_loop:
    add x7, x2, #9
    cmp x7, x0
    b.hs .Lstatus_close
    add x3, x1, x2
    ldrb w5, [x3]
    cmp w5, #0x54
    b.ne .Lstatus_next
    ldrb w5, [x3, #1]
    cmp w5, #0x72
    b.ne .Lstatus_next
    ldrb w5, [x3, #2]
    cmp w5, #0x61
    b.ne .Lstatus_next
    ldrb w5, [x3, #3]
    cmp w5, #0x63
    b.ne .Lstatus_next
    ldrb w5, [x3, #4]
    cmp w5, #0x65
    b.ne .Lstatus_next
    ldrb w5, [x3, #5]
    cmp w5, #0x72
    b.ne .Lstatus_next
    ldrb w5, [x3, #6]
    cmp w5, #0x50
    b.ne .Lstatus_next
    ldrb w5, [x3, #7]
    cmp w5, #0x69
    b.ne .Lstatus_next
    ldrb w5, [x3, #8]
    cmp w5, #0x64
    b.ne .Lstatus_next
    ldrb w5, [x3, #9]
    cmp w5, #0x3a
    b.ne .Lstatus_next
    add x3, x3, #10
.Lstatus_skip_ws:
    cmp x3, x4
    b.hs .Lstatus_close
    ldrb w5, [x3]
    cmp w5, #0x20
    b.eq .Lstatus_ws_advance
    cmp w5, #0x09
    b.ne .Lstatus_digit_loop
.Lstatus_ws_advance:
    add x3, x3, #1
    b .Lstatus_skip_ws
.Lstatus_digit_loop:
    ldrb w5, [x3], #1
    cmp w5, #0x31
    b.lo .Lstatus_close
    cmp w5, #0x39
    b.ls .Lstatus_trap
    cmp w5, #0x30
    b.eq .Lstatus_digit_loop
    b .Lstatus_close
.Lstatus_next:
    add x2, x2, #1
    b .Lstatus_scan_loop
.Lstatus_close:
    mov x0, x6
    mov x8, #57
    svc #0
.Lstatus_done:
    b .Lstatus_after_trap
.Lstatus_trap:
    cmp x27, #0
    b.ne .Lstatus_after_trap
    brk #0x7d1
.Lstatus_after_trap:

    // Best-effort anti-Frida fd-link probe: read a small fixed fd range and
    // inspect symlink targets for Frida/Gum/Gadget artifacts. This catches common
    // gadget/server pipes or memfd handles without relying only on maps names.
    adr x0, strdec_fd_path_xor
    add x1, sp, #272
    mov w2, #15
.Lfd_path_decode_loop:
    ldrb w3, [x0], #1
    mov w5, #0x5a
    eor w3, w3, w5
    strb w3, [x1], #1
    subs w2, w2, #1
    b.ne .Lfd_path_decode_loop
    mov w10, #0
.Lfd_loop:
    cmp w10, #32
    b.hs .Lfd_done
    add x1, sp, #272
    mov w11, #10
    cmp w10, #10
    b.hs .Lfd_two_digits
    add w12, w10, #0x30
    strb w12, [x1, #14]
    strb wzr, [x1, #15]
    b .Lfd_readlink
.Lfd_two_digits:
    udiv w12, w10, w11
    msub w13, w12, w11, w10
    add w12, w12, #0x30
    add w13, w13, #0x30
    strb w12, [x1, #14]
    strb w13, [x1, #15]
    strb wzr, [x1, #16]
.Lfd_readlink:
    mov x0, #-100
    add x1, sp, #272
    add x2, sp, #832
    mov x3, #512
    mov x8, #78
    svc #0
    cmp x0, #0
    b.le .Lfd_next_fd
    mov x4, x0
    add x1, sp, #832
    mov x2, #0
.Lfd_scan_loop:
    cmp x2, x4
    b.hs .Lfd_next_fd
    add x3, x1, x2
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x66
    b.ne .Lfd_check_gum
    add x7, x2, #4
    cmp x7, x4
    b.hs .Lfd_check_gum
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x72
    b.ne .Lfd_check_gum
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x69
    b.ne .Lfd_check_gum
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Lfd_check_gum
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.eq .Lfd_trap
.Lfd_check_gum:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lfd_scan_next
    add x7, x2, #2
    cmp x7, x4
    b.hs .Lfd_scan_next
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x75
    b.ne .Lfd_scan_next
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x6d
    b.eq .Lfd_trap
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lfd_scan_next
    add x7, x2, #5
    cmp x7, x4
    b.hs .Lfd_scan_next
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.ne .Lfd_scan_next
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Lfd_scan_next
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lfd_scan_next
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x65
    b.ne .Lfd_scan_next
    ldrb w5, [x3, #5]
    orr w5, w5, #0x20
    cmp w5, #0x74
    b.eq .Lfd_trap
.Lfd_scan_next:
    add x2, x2, #1
    b .Lfd_scan_loop
.Lfd_next_fd:
    add w10, w10, #1
    b .Lfd_loop
.Lfd_trap:
    brk #0xf2d
.Lfd_done:

    // Best-effort Frida socket probe: scan /proc/net/unix for common server
    // or gadget socket names. Open/read failures are ignored for compatibility.
    adr x0, strdec_net_unix_path_xor
    add x1, sp, #272
    mov w2, #15
.Lunix_path_decode_loop:
    ldrb w3, [x0], #1
    mov w5, #0x5a
    eor w3, w3, w5
    strb w3, [x1], #1
    subs w2, w2, #1
    b.ne .Lunix_path_decode_loop
    mov x0, #-100
    add x1, sp, #272
    mov x2, #0
    mov x3, #0
    mov x8, #56
    svc #0
    cmp x0, #0
    b.lt .Lunix_done
    mov x6, x0
    mov w18, #0
.Lunix_read_loop:
    mov x0, x6
    add x1, sp, #320
    mov x2, #512
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le .Lunix_close
    mov x4, x0
    mov x2, #0
.Lunix_scan_loop:
    cmp x2, x4
    b.hs .Lunix_after_scan
    add x3, x1, x2
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x66
    b.ne .Lunix_check_gum
    add x7, x2, #4
    cmp x7, x4
    b.hs .Lunix_check_gum
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x72
    b.ne .Lunix_check_gum
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x69
    b.ne .Lunix_check_gum
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Lunix_check_gum
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.eq .Lunix_trap
.Lunix_check_gum:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lunix_check_gadget
    add x7, x2, #2
    cmp x7, x4
    b.hs .Lunix_check_gadget
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x75
    b.ne .Lunix_check_gadget
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x6d
    b.eq .Lunix_trap
.Lunix_check_gadget:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lunix_next
    add x7, x2, #5
    cmp x7, x4
    b.hs .Lunix_next
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.ne .Lunix_next
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Lunix_next
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Lunix_next
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x65
    b.ne .Lunix_next
    ldrb w5, [x3, #5]
    orr w5, w5, #0x20
    cmp w5, #0x74
    b.eq .Lunix_trap
.Lunix_next:
    add x2, x2, #1
    b .Lunix_scan_loop
.Lunix_after_scan:
    add w18, w18, #1
    cmp w18, #4
    b.lo .Lunix_read_loop
.Lunix_close:
    mov x0, x6
    mov x8, #57
    svc #0
.Lunix_done:
    b .Lunix_after_trap
.Lunix_trap:
    brk #0xf57
.Lunix_after_trap:

    // Best-effort thread-name probe: scan a small tid range under
    // /proc/self/task/<tid>/comm for Frida/Gum/Gadget worker names. This is
    // intentionally bounded to avoid expensive procfs walks on older devices.
    adr x0, strdec_task_comm_path_xor
    add x1, sp, #272
    mov w2, #25
.Ltask_tpl_decode_loop:
    ldrb w3, [x0], #1
    mov w5, #0x5a
    eor w3, w3, w5
    strb w3, [x1], #1
    subs w2, w2, #1
    b.ne .Ltask_tpl_decode_loop
    mov w10, #1
.Ltask_tid_loop:
    cmp w10, #96
    b.hs .Ltask_done
    add x1, sp, #272
    mov w11, #10
    mov w12, w10
    udiv w13, w12, w11
    msub w14, w13, w11, w12
    cbnz w13, .Ltask_two_digits
    add w14, w14, #0x30
    strb w14, [x1, #16]
    strb wzr, [x1, #17]
    b .Ltask_open
.Ltask_two_digits:
    add w13, w13, #0x30
    add w14, w14, #0x30
    strb w13, [x1, #16]
    strb w14, [x1, #17]
    mov w15, #0x2f
    strb w15, [x1, #18]
    mov w15, #0x63
    strb w15, [x1, #19]
    mov w15, #0x6f
    strb w15, [x1, #20]
    mov w15, #0x6d
    strb w15, [x1, #21]
    strb w15, [x1, #22]
    strb wzr, [x1, #23]
.Ltask_open:
    mov x0, #-100
    add x1, sp, #272
    mov x2, #0
    mov x3, #0
    mov x8, #56
    svc #0
    cmp x0, #0
    b.lt .Ltask_next_tid
    mov x6, x0
    mov x0, x6
    add x1, sp, #832
    mov x2, #128
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le .Ltask_close
    mov x4, x0
    add x1, sp, #832
    mov x2, #0
.Ltask_scan_loop:
    cmp x2, x4
    b.hs .Ltask_close
    add x3, x1, x2
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x66
    b.ne .Ltask_check_gum
    add x7, x2, #4
    cmp x7, x4
    b.hs .Ltask_check_gum
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x72
    b.ne .Ltask_check_gum
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x69
    b.ne .Ltask_check_gum
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Ltask_check_gum
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.eq .Ltask_trap
.Ltask_check_gum:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Ltask_check_gadget
    add x7, x2, #2
    cmp x7, x4
    b.hs .Ltask_check_gadget
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x75
    b.ne .Ltask_check_gadget
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x6d
    b.eq .Ltask_trap
.Ltask_check_gadget:
    ldrb w5, [x3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Ltask_scan_next
    add x7, x2, #5
    cmp x7, x4
    b.hs .Ltask_scan_next
    ldrb w5, [x3, #1]
    orr w5, w5, #0x20
    cmp w5, #0x61
    b.ne .Ltask_scan_next
    ldrb w5, [x3, #2]
    orr w5, w5, #0x20
    cmp w5, #0x64
    b.ne .Ltask_scan_next
    ldrb w5, [x3, #3]
    orr w5, w5, #0x20
    cmp w5, #0x67
    b.ne .Ltask_scan_next
    ldrb w5, [x3, #4]
    orr w5, w5, #0x20
    cmp w5, #0x65
    b.ne .Ltask_scan_next
    ldrb w5, [x3, #5]
    orr w5, w5, #0x20
    cmp w5, #0x74
    b.eq .Ltask_trap
.Ltask_scan_next:
    add x2, x2, #1
    b .Ltask_scan_loop
.Ltask_close:
    mov x0, x6
    mov x8, #57
    svc #0
.Ltask_next_tid:
    add w10, w10, #1
    b .Ltask_tid_loop
.Ltask_done:
    b .Ltask_after_trap
.Ltask_trap:
    brk #0x7aa
.Ltask_after_trap:

    adr x19, strdec_anchor
    adr x20, strdec_static_anchor_va
    ldr x21, [x20]
    sub x22, x19, x21

    // Self-check the executable stub body. The expected value is patched per
    // build, so static patching/hooking the decryptor poisons execution early.
    adr x0, strdec_entry
    adr x1, strdec_anchor
    adr x20, strdec_guard_seed
    ldr w9, [x20]
10:
    cmp x0, x1
    b.hs 11f
    ldrb w10, [x0], #1
    add w9, w9, w10
    eor w9, w9, w9, lsl #13
    eor w9, w9, w9, lsr #17
    eor w9, w9, w9, lsl #5
    b 10b
11:
    adr x20, strdec_guard_hash
    ldr w10, [x20]
    cmp w9, w10
    b.eq 12f
    brk #0x6d2
12:

    adr x20, strdec_page_va
    ldr x0, [x20]
    add x0, x0, x22
    adr x20, strdec_page_len
    ldr x1, [x20]
    cbz x1, 1f
    mov x2, #3
    mov x8, #226
    svc #0

    // Keep decrypted string pages out of core dumps where supported.
    adr x20, strdec_page_va
    ldr x0, [x20]
    add x0, x0, x22
    adr x20, strdec_page_len
    ldr x1, [x20]
    mov x2, #16
    mov x8, #233
    svc #0

1:
    adr x20, strdec_entry_count
    ldr w24, [x20]
    str wzr, [x20]
    adr x25, strdec_table

    adr x20, strdec_table_seed
    ldr w21, [x20]
    str wzr, [x20]
    mov w9, #0x5a7e
    movk w9, #0xa5c3, lsl #16
    eor w21, w21, w9

    adr x20, strdec_runtime_table_hash
    ldr w17, [x20]
    adr x20, strdec_runtime_table_hash_mask
    ldr w9, [x20]
    eor w17, w17, w9
    adr x20, strdec_runtime_table_hash_seed
    ldr w9, [x20]
    mov w27, w24
    eor w27, w27, w9
    str w9, [sp, #248]
    mov w3, #0
    mov w28, w24
    mov w9, #24
    mul w28, w28, w9
.Lruntime_table_hash_loop:
    cmp w3, w28
    b.hs .Lruntime_table_hash_done
    ldrb w4, [x25, x3]
    mov w5, #0x352d
    movk w5, #0x7feb, lsl #16
    madd w5, w3, w5, w4
    add w27, w27, w5
    eor w27, w27, w27, lsl #7
    eor w27, w27, w27, lsr #15
    eor w27, w27, w27, lsl #11
    add w3, w3, #1
    b .Lruntime_table_hash_loop
.Lruntime_table_hash_done:
    cbnz w27, .Lruntime_table_hash_nonzero
    ldr w27, [sp, #248]
.Lruntime_table_hash_nonzero:
    cmp w27, w17
    b.eq .Lruntime_table_hash_ok
    brk #0x7c3
.Lruntime_table_hash_ok:

    adr x20, strdec_key_seed
    ldr w23, [x20]
    str wzr, [x20]
    mov w9, #0x3b17
    movk w9, #0x6d9e, lsl #16
    eor w23, w23, w9

    adr x20, strdec_param_table_a
    ldr w10, [x20]
    str wzr, [x20]
    adr x20, strdec_param_table_b
    ldr w11, [x20]
    str wzr, [x20]
    adr x20, strdec_param_key_index
    ldr w12, [x20]
    str wzr, [x20]
    adr x20, strdec_param_string_pos
    ldr w13, [x20]
    str wzr, [x20]
    adr x20, strdec_param_string_index
    ldr w14, [x20]
    str wzr, [x20]

    mov w26, #0

2:
    cmp w26, w24
    b.hs 5f

    // Decrypt one 24-byte table entry. The loop shape intentionally avoids a
    // single canonical xorshift block that is easy to signature-match.
    eor w6, w21, w26
    eor w6, w6, w26, lsr #8
    mov w5, #0xa7
    eor w6, w6, w5
    add w20, w6, w10
    and w20, w20, #0xff
    mov w3, #0
6:
    cmp w3, #24
    b.hs 7f
    ldrb w4, [x25, x3]
    mov w19, w4
    add w27, w26, w26, lsl #1
    lsl w27, w27, #3
    add w27, w27, w3
    mul w5, w27, w10
    eor w5, w5, w21
    lsr w6, w27, #3
    mul w6, w6, w11
    eor w5, w5, w6
    mov w6, #0x79b9
    movk w6, #0x9e37, lsl #16
    eor w5, w5, w6
    eor w5, w5, w5, lsl #13
    eor w5, w5, w5, lsr #17
    eor w5, w5, w5, lsl #5
    lsr w6, w27, #8
    add w5, w5, w6
    eor w5, w5, w20
    eor w4, w4, w5
    strb w4, [x25, x3]
    eor w20, w20, w19
    eor w20, w20, w27
    and w20, w20, #0xff
    lsl w6, w20, #3
    lsr w20, w20, #5
    orr w20, w20, w6
    add w20, w20, #0x3d
    and w20, w20, #0xff
    add w3, w3, #1
    // Opaque control-flow edge: always falls through to the loop branch, but
    // breaks straight-line pattern matching in small decryptor signatures.
    eor w6, w3, w3
    cbnz w6, 7f
    b 6b

7:
    ldr x7, [x25, #0]
    ldr w6, [x25, #8]
    and w1, w6, #0xffff
    lsr w18, w6, #16
    and w18, w18, #0xff
    lsr w16, w6, #24
    and w16, w16, #0xf
    ldr w2, [x25, #12]
    ldr w15, [x25, #16]
    ldr w17, [x25, #20]
    lsr w19, w17, #16
    and w17, w17, #0xffff

    // Reconstruct the per-string key from split key material, VA, length,
    // table index, and per-entry salt/mixer/variant.
    mov w5, w23
    eor w5, w5, w7
    lsr x8, x7, #32
    eor w5, w5, w8
    eor w5, w5, w1
    mul w8, w26, w12
    eor w5, w5, w8
    eor w5, w5, w15
    eor w5, w5, w17
    eor w5, w5, w16
    mov w8, #0xca6b
    movk w8, #0x85eb, lsl #16
    eor w5, w5, w8
    eor w5, w5, w5, lsl #13
    eor w5, w5, w5, lsr #17
    eor w5, w5, w5, lsl #5
    lsr x8, x7, #7
    eor w5, w5, w8
    mov w8, #0x9f3b
    movk w8, #0x045d, lsl #16
    mul w8, w1, w8
    add w5, w5, w8
    eor w2, w2, w5

    // Verify row-level integrity tag packed into length bits 16..23.
    mov w5, w2
    eor w5, w5, w23
    eor w5, w5, w7
    lsr x8, x7, #32
    eor w5, w5, w8
    eor w5, w5, w1
    mul w8, w26, w12
    eor w5, w5, w8
    eor w5, w5, w15
    ror w8, w17, #27
    eor w5, w5, w8
    mov w8, #0x9f3b
    movk w8, #0x045d, lsl #16
    mul w8, w16, w8
    eor w5, w5, w8
    mov w8, #0x7c15
    movk w8, #0x7f4a, lsl #16
    eor w5, w5, w8
    eor w5, w5, w5, lsl #13
    eor w5, w5, w5, lsr #17
    eor w5, w5, w5, lsl #5
    eor w5, w5, w5, lsr #11
    mov w8, #0x79b9
    movk w8, #0x9e37, lsl #16
    add w5, w5, w8
    eor w8, w5, w5, lsr #8
    eor w8, w8, w5, lsr #16
    eor w8, w8, w5, lsr #24
    and w8, w8, #0xff
    cmp w8, w18
    b.eq .Lentry_tag_ok
    brk #0x7a9
.Lentry_tag_ok:

    // Decoy rows carry valid tags and non-zero lengths, but point outside the
    // real string page window. Keep their table rows plausible without touching
    // process memory.
    adr x20, strdec_page_va
    ldr x8, [x20]
    cmp x7, x8
    b.lo 4f
    adr x20, strdec_page_len
    ldr x27, [x20]
    add x27, x8, x27
    cmp x7, x27
    b.hs 4f

    mov w28, w2
    eor w28, w28, w7
    lsr x8, x7, #32
    eor w28, w28, w8
    eor w28, w28, w1
    mul w8, w26, w14
    eor w28, w28, w8
    eor w28, w28, w13
    eor w28, w28, w15
    eor w28, w28, w17
    eor w28, w28, w16
    mov x0, x7
    add x0, x0, x22
    mov w3, #0

3:
    cmp w3, w1
    b.hs 4f
    ldrb w4, [x0, x3]
    add w28, w28, w13
    add w28, w28, w17
    mul w5, w3, w14
    add w5, w5, w15
    eor w28, w28, w5
    eor w28, w28, w28, lsl #13
    eor w28, w28, w28, lsr #17
    eor w28, w28, w28, lsl #5
    mul w5, w3, w13
    add w5, w5, w28
    lsr x8, x7, #4
    add w5, w5, w8
    tbz w16, #0, 13f
    eor w5, w5, w28, lsr #8
13:
    tbz w16, #1, 14f
    eor w5, w5, w17
14:
    tbz w16, #2, 15f
    eor w5, w5, w28, lsl #7
15:
    tbz w16, #3, 16f
    eor w5, w5, w28, lsr #11
16:
    mov w6, #0xeb2d
    movk w6, #0x27d4, lsl #16
    mul w6, w3, w6
    add w6, w6, w15
    eor w6, w6, w28
    lsr x8, x7, #16
    eor w6, w6, w8
    eor w6, w6, w17
    mov w8, #0x67b1
    movk w8, #0x1656, lsl #16
    add w27, w3, #1
    mul w8, w27, w8
    eor w6, w6, w8
    eor w6, w6, w6, lsl #13
    eor w6, w6, w6, lsr #17
    eor w6, w6, w6, lsl #5
    eor w8, w6, w6, lsr #16
    add w6, w8, w28, lsl #3
    eor w5, w5, w6
    mov w6, w28
    eor w6, w6, w15
    ror w8, w17, #23
    eor w6, w6, w8
    eor w6, w6, w7
    lsr x8, x7, #32
    eor w6, w6, w8
    mov w8, #0x7c15
    movk w8, #0x7f4a, lsl #16
    mul w8, w3, w8
    add w6, w6, w8
    add w6, w6, w14
    eor w6, w6, w6, lsl #13
    eor w6, w6, w6, lsr #17
    eor w6, w6, w6, lsl #5
    mov w8, #0x79b9
    movk w8, #0x9e37, lsl #16
    mul w8, w16, w8
    add w8, w8, w6
    and w27, w3, #7
    add w27, w27, #5
    neg w27, w27
    ror w8, w8, w27
    eor w6, w6, w8
    eor w6, w6, w6, lsr #13
    eor w5, w5, w6
    add w6, w15, w3
    and w8, w3, #7
    add w8, w8, #3
    neg w8, w8
    ror w6, w6, w8
    eor w6, w6, w28
    lsr x8, x7, #32
    eor w8, w8, w17
    add w6, w6, w8
    mul w8, w3, w13
    add w8, w8, w13
    eor w6, w6, w8
    mov w8, #0x79f5
    movk w8, #0x6d2b, lsl #16
    mul w8, w16, w8
    add w6, w6, w8
    eor w6, w6, w6, lsl #13
    eor w6, w6, w6, lsr #17
    eor w6, w6, w6, lsl #5
    lsr x8, x7, #7
    add w8, w8, w14
    add w8, w8, w6
    and w27, w3, #3
    add w27, w27, #9
    neg w27, w27
    ror w8, w8, w27
    eor w6, w6, w8
    eor w6, w6, w6, lsl #13
    eor w6, w6, w6, lsr #17
    eor w6, w6, w6, lsl #5
    eor w5, w5, w6
    eor w4, w4, w5
    strb w4, [x0, x3]
    add w3, w3, #1
    b 3b

4:
    cbz w19, .Lmain_content_mac_ok
    mov w3, #0
    mov w5, w2
    eor w5, w5, w7
    lsr x8, x7, #32
    eor w5, w5, w8
    eor w5, w5, w1
    eor w5, w5, w15
    ror w8, w17, #21
    eor w5, w5, w8
    eor w5, w5, w16
    mov w8, #0x79b9
    movk w8, #0x9e37, lsl #16
    eor w5, w5, w8
.Lmain_content_mac:
    cmp w3, w1
    b.hs .Lmain_content_mac_done
    ldrb w4, [x0, x3]
    add w8, w4, w3
    eor w5, w5, w8
    eor w5, w5, w5, lsl #13
    eor w5, w5, w5, lsr #17
    eor w5, w5, w5, lsl #5
    add w3, w3, #1
    b .Lmain_content_mac
.Lmain_content_mac_done:
    eor w8, w5, w5, lsr #16
    and w8, w8, #0xffff
    cmp w8, w19
    b.eq .Lmain_content_mac_ok
    brk #0x7a8
.Lmain_content_mac_ok:
    // Re-seal only the runtime table entry; each row is readable for the
    // shortest possible window before the next entry is processed.
    eor w6, w21, w26
    eor w6, w6, w26, lsr #8
    mov w5, #0xa7
    eor w6, w6, w5
    add w20, w6, w10
    and w20, w20, #0xff
    mov w3, #0
8:
    cmp w3, #24
    b.hs 9f
    ldrb w4, [x25, x3]
    add w27, w26, w26, lsl #1
    lsl w27, w27, #3
    add w27, w27, w3
    mul w5, w27, w10
    eor w5, w5, w21
    lsr w6, w27, #3
    mul w6, w6, w11
    eor w5, w5, w6
    mov w6, #0x79b9
    movk w6, #0x9e37, lsl #16
    eor w5, w5, w6
    eor w5, w5, w5, lsl #13
    eor w5, w5, w5, lsr #17
    eor w5, w5, w5, lsl #5
    lsr w6, w27, #8
    add w5, w5, w6
    eor w5, w5, w20
    eor w4, w4, w5
    strb w4, [x25, x3]
    eor w20, w20, w4
    eor w20, w20, w27
    and w20, w20, #0xff
    lsl w6, w20, #3
    lsr w20, w20, #5
    orr w20, w20, w6
    add w20, w20, #0x3d
    and w20, w20, #0xff
    add w3, w3, #1
    b 8b

9:
    add x25, x25, #24
    add w26, w26, #1
    b 2b

5:
    adr x20, strdec_page_len
    ldr x1, [x20]
    cbz x1, restore_done
    adr x20, strdec_page_va
    ldr x0, [x20]
    add x0, x0, x22
    mov x2, #5
    mov x8, #226
    svc #0

restore_done:
    adr x20, strdec_orig_entry_va
    ldr x16, [x20]
    adr x20, strdec_orig_entry_key
    ldr x17, [x20]
    str xzr, [x20]
    eor x16, x16, x17
    add x16, x16, x22
    str x16, [sp, #248]

    // Reseal the injected runtime payload itself: its table has been
    // re-encrypted and seed fields were wiped, so keep the pages out of
    // core dumps and remove write permission before transferring control.
    adr x0, strdec_entry
    lsr x0, x0, #12
    lsl x0, x0, #12
    adr x20, strdec_payload_len
    ldr x1, [x20]
    add x1, x1, #4095
    lsr x1, x1, #12
    lsl x1, x1, #12
    mov x2, #16
    mov x8, #233
    svc #0

    adr x0, strdec_entry
    lsr x0, x0, #12
    lsl x0, x0, #12
    adr x20, strdec_payload_len
    ldr x1, [x20]
    add x1, x1, #4095
    lsr x1, x1, #12
    lsl x1, x1, #12
    mov x2, #5
    mov x8, #226
    svc #0

    // Wipe procfs path and scan buffers built on the stub stack before
    // returning to the protected program. Saved registers and the computed
    // original entry at sp+248 are below this range.
    add x0, sp, #272
    mov x1, #1072
.Lwipe_scratch:
    str xzr, [x0], #8
    subs x1, x1, #8
    b.ne .Lwipe_scratch

    ldr x16, [sp, #248]
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #1584
    br x16

.balign 4
.global strdec_lazy_entry
.type strdec_lazy_entry, %function
strdec_lazy_entry:
    // On-demand string decrypt trampoline: decrypts the string at x0,
    // calls the original BL target, then re-encrypts before returning.
    //
    // Called from patched BL instructions in .text. The original
    // ADR/ADRP+ADD sequence sets x0 to the runtime string VA.
    // x30 holds the return address (text_va + 4 of the patched BL).
    //
    // Register allocation (avoid callee-saved x21-x28):
    //   x5=table ptr, x6=count, x7=string_va, x8=len
    //   x9=variant, x10=orig_target
    //   x11=key_state, x12=pos_param, x13=idx_param
    //   x14=saltA, x15=saltB
    //   x19=ASLR (saved), x20=text_va (saved)
    //   x17, x6 scratch in loops
    stp x1,  x2,  [sp, #-320]!
    stp x3,  x4,  [sp, #16]
    stp x5,  x6,  [sp, #32]
    stp x7,  x8,  [sp, #48]
    stp x9,  x10, [sp, #64]
    stp x11, x12, [sp, #80]
    stp x13, x14, [sp, #96]
    stp x15, x16, [sp, #112]
    str x17,       [sp, #128]
    stp x18, x30, [sp, #144]
    str x0,        [sp, #160]
    str x0,        [sp, #168]
    stp x19, x20,  [sp, #176]
    str x30,       [sp, #216]
    
    // Derive ASLR offset
    adr x19, strdec_anchor
    adr x20, strdec_static_anchor_va
    ldr x20, [x20]
    sub x19, x19, x20
    
    // Compute link-time text_va from return address
    mov x20, x30
    sub x20, x20, #4
    sub x20, x20, x19
    
    // Load dispatch table: x5=ptr, x6=count
    adr x5, strdec_lazy_count
    ldr w6, [x5]
    adr x5, strdec_lazy_hash
    ldr w18, [x5]
    adr x5, strdec_lazy_hash_mask
    ldr w4, [x5]
    eor w18, w18, w4
    adr x5, strdec_lazy_table
    ldr x5, [x5]
    add x5, x5, x19
    mov w16, w6
    adr x17, strdec_lazy_hash_seed
    ldr w4, [x17]
    eor w16, w16, w4
    str w4, [sp, #208]
    mov w3, #0
    mov x17, x5
.Llazy_hash_loop:
    cmp w3, w6
    b.hs .Llazy_hash_done
    mov w4, #0
.Llazy_hash_entry:
    cmp w4, #56
    b.hs .Llazy_hash_next
    ldrb w7, [x17, x4]
    mov w12, #56
    madd w12, w3, w12, w4
    mov w11, #0x9f3b
    movk w11, #0x045d, lsl #16
    madd w11, w12, w11, w7
    add w16, w16, w11
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    add w4, w4, #1
    b .Llazy_hash_entry
.Llazy_hash_next:
    add x17, x17, #56
    add w3, w3, #1
    b .Llazy_hash_loop
.Llazy_hash_done:
    cbnz w16, .Llazy_hash_nonzero
    ldr w16, [sp, #208]
.Llazy_hash_nonzero:
    cmp w16, w18
    b.eq .Llazy_hash_ok
    brk #0x7b3
.Llazy_hash_ok:
    mov w12, #0
    
.Llazy_scan:
    cbz w6, .Llazy_return
    mov w18, w12
    adr x16, strdec_lazy_mask_base
    ldr w4, [x16]
    adr x16, strdec_lazy_hash_seed
    ldr w16, [x16]
    eor w4, w4, w16
    eor w4, w4, w18
    eor w4, w4, w4, lsr #8
    mov w16, #0xc3
    eor w4, w4, w16
    and w11, w4, #0xff
    mov w3, #0
.Llazy_decode_scan:
    cmp w3, #56
    b.hs .Llazy_scan_decoded
    ldrb w7, [x5, x3]
    bl .Llazy_mask
    eor w4, w4, w11
    eor w4, w4, w7
    add x17, sp, #224
    strb w4, [x17, x3]
    eor w11, w11, w7
    eor w11, w11, w18
    eor w11, w11, w3
    and w11, w11, #0xff
    lsl w16, w11, #3
    lsr w11, w11, #5
    orr w11, w11, w16
    add w11, w11, #0x5d
    and w11, w11, #0xff
    add w3, w3, #1
    b .Llazy_decode_scan
.Llazy_scan_decoded:
    ldr x7, [sp, #224]       // decoded entry.text_va
    cmp x7, x20
    b.eq .Llazy_found
    add x5, x5, #56
    sub w6, w6, #1
    add w12, w12, #1
    b .Llazy_scan
    
.Llazy_found:
    // x5 = encrypted dispatch entry base; decoded copy is at sp+224.
    // Entry: text_va(8) string_va(8) len(4) key_state(4) pos_param(4) idx_param(4) saltA(4) saltB(4) variant(1) tag(4) pad(3) orig_target(8) = 56
    ldr x16, [sp, #224]       // text_va
    ldr x7,  [sp, #232]       // string_va (link-time)
    ldr w8,  [sp, #240]       // len
    ldr w11, [sp, #244]       // key_state
    ldr w12, [sp, #248]       // pos_param
    ldr w13, [sp, #252]       // idx_param
    ldr w14, [sp, #256]       // saltA
    ldr w15, [sp, #260]       // saltB
    ldrb w9, [sp, #264]       // variant
    ldrb w17, [sp, #265]      // tag
    ldrb w6, [sp, #266]
    orr w17, w17, w6, lsl #8
    ldrb w6, [sp, #267]
    orr w17, w17, w6, lsl #16
    ldrb w6, [sp, #268]
    orr w17, w17, w6, lsl #24
    ldr x10, [sp, #272]       // orig_target
    lsr x6, x16, #32
    eor w18, w16, w6
    eor w18, w18, w7
    lsr x6, x7, #32
    eor w18, w18, w6
    eor w18, w18, w8
    eor w18, w18, w11
    eor w18, w18, w12
    ror w6, w13, #29
    eor w18, w18, w6
    eor w18, w18, w14
    ror w6, w15, #25
    eor w18, w18, w6
    mov w6, #0x79b9
    movk w6, #0x9e37, lsl #16
    mul w6, w9, w6
    eor w18, w18, w6
    eor w18, w18, w10
    lsr x6, x10, #32
    eor w18, w18, w6
    mov w6, #0xe667
    movk w6, #0x6a09, lsl #16
    eor w18, w18, w6
    eor w18, w18, w18, lsl #13
    eor w18, w18, w18, lsr #17
    eor w18, w18, w18, lsl #5
    mov w6, #0x9f3b
    movk w6, #0x045d, lsl #16
    mul w6, w8, w6
    add w6, w6, w12
    add w18, w18, w6
    eor w18, w18, w18, lsl #13
    eor w18, w18, w18, lsr #17
    eor w18, w18, w18, lsl #5
    cmp w18, w17
    b.eq .Llazy_tag_ok
    brk #0x7b1
.Llazy_tag_ok:
    lsr w18, w15, #16
    and w15, w15, #0xffff
    str w18, [sp, #200]
    str w11, [sp, #204]
    add x10, x10, x19         // runtime orig_target
    
    add x0, x7, x19           // runtime entry-base string VA

    // The main runtime restores string pages to RX before entering the program.
    // Lazy decrypt needs a short RW window for the exact page span it touches.
    str w8, [sp, #208]
    lsr x16, x0, #12
    lsl x16, x16, #12
    sub x17, x0, x16
    add x1, x17, x8
    add x1, x1, #4095
    lsr x1, x1, #12
    lsl x1, x1, #12
    mov x0, x16
    mov x2, #3
    mov x8, #226
    svc #0
    add x0, x7, x19
    ldr w8, [sp, #208]
    
    // Decrypt string: x8=len, x11=state, x12=pP, x13=iP, x14=sA, x15=sB, x9=v
    mov w3, #0
.Llazy_dec:
    cmp w3, w8
    b.hs .Llazy_call
    ldrb w4, [x0, x3]
    add w11, w11, w12         // state += pos_param
    add w11, w11, w15         // state += saltB
    mul w6, w3, w13           // pos * idx_param
    add w6, w6, w14           // + saltA
    eor w11, w11, w6          // state ^= ...
    eor w11, w11, w11, lsl #13
    eor w11, w11, w11, lsr #17
    eor w11, w11, w11, lsl #5
    mul w6, w3, w12           // pos * pos_param
    add w6, w6, w11           // + state
    lsr x17, x7, #4           // va>>4
    add w6, w6, w17           // mask
    tbz w9, #0, .Llazy_v0
    eor w6, w6, w11, lsr #8
.Llazy_v0:
    tbz w9, #1, .Llazy_v1
    eor w6, w6, w15
.Llazy_v1:
    tbz w9, #2, .Llazy_v2
    eor w6, w6, w11, lsl #7
.Llazy_v2:
    tbz w9, #3, .Llazy_v3
    eor w6, w6, w11, lsr #11
.Llazy_v3:
    mov w16, #0xeb2d
    movk w16, #0x27d4, lsl #16
    mul w16, w3, w16
    add w16, w16, w14
    eor w16, w16, w11
    lsr x17, x7, #16
    eor w16, w16, w17
    eor w16, w16, w15
    mov w17, #0x67b1
    movk w17, #0x1656, lsl #16
    add w18, w3, #1
    mul w17, w18, w17
    eor w16, w16, w17
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    eor w17, w16, w16, lsr #16
    add w16, w17, w11, lsl #3
    eor w6, w6, w16
    mov w16, w11
    eor w16, w16, w14
    ror w17, w15, #23
    eor w16, w16, w17
    eor w16, w16, w7
    lsr x17, x7, #32
    eor w16, w16, w17
    mov w17, #0x7c15
    movk w17, #0x7f4a, lsl #16
    mul w17, w3, w17
    add w16, w16, w17
    add w16, w16, w13
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    mov w17, #0x79b9
    movk w17, #0x9e37, lsl #16
    mul w17, w9, w17
    add w17, w17, w16
    and w18, w3, #7
    add w18, w18, #5
    neg w18, w18
    ror w17, w17, w18
    eor w16, w16, w17
    eor w16, w16, w16, lsr #13
    eor w6, w6, w16
    add w16, w14, w3
    and w17, w3, #7
    add w17, w17, #3
    neg w17, w17
    ror w16, w16, w17
    eor w16, w16, w11
    lsr x17, x7, #32
    eor w17, w17, w15
    add w16, w16, w17
    mul w17, w3, w12
    add w17, w17, w12
    eor w16, w16, w17
    mov w17, #0x79f5
    movk w17, #0x6d2b, lsl #16
    mul w17, w9, w17
    add w16, w16, w17
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    lsr x17, x7, #7
    add w17, w17, w13
    add w17, w17, w16
    and w18, w3, #3
    add w18, w18, #9
    neg w18, w18
    ror w17, w17, w18
    eor w16, w16, w17
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    eor w6, w6, w16
    eor w4, w4, w6
    strb w4, [x0, x3]
    add w3, w3, #1
    b .Llazy_dec
    
.Llazy_call:
    ldr w18, [sp, #200]
    cbz w18, .Llazy_mac_ok
    mov w3, #0
    ldr w16, [sp, #204]
    eor w16, w16, w7
    lsr x17, x7, #32
    eor w16, w16, w17
    eor w16, w16, w8
    eor w16, w16, w14
    ror w17, w15, #21
    eor w16, w16, w17
    eor w16, w16, w9
    mov w17, #0x79b9
    movk w17, #0x9e37, lsl #16
    eor w16, w16, w17
.Llazy_mac:
    cmp w3, w8
    b.hs .Llazy_mac_done
    ldrb w4, [x0, x3]
    add w17, w4, w3
    eor w16, w16, w17
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    add w3, w3, #1
    b .Llazy_mac
.Llazy_mac_done:
    eor w17, w16, w16, lsr #16
    and w17, w17, #0xffff
    cmp w17, w18
    b.eq .Llazy_mac_ok
    brk #0x7b2
.Llazy_mac_ok:
    // Save decoded parameters in this trampoline frame; blr may clobber caller-saved registers.
    str x10, [sp, #192]
    ldr w6,  [sp, #204]
    str w8,  [sp, #280]
    str w6,  [sp, #284]
    str w12, [sp, #288]
    str w13, [sp, #292]
    str w14, [sp, #296]
    str w15, [sp, #300]
    str w9,  [sp, #304]
    str x7,  [sp, #312]
    // Present the original call ABI to the protected function.
    ldr x0,        [sp, #160]
    ldp x1,  x2,  [sp, #0]
    ldp x3,  x4,  [sp, #16]
    ldp x5,  x6,  [sp, #32]
    ldp x7,  x8,  [sp, #48]
    ldp x9,  x10, [sp, #64]
    ldp x11, x12, [sp, #80]
    ldp x13, x14, [sp, #96]
    ldp x15, x16, [sp, #112]
    ldr x17,      [sp, #128]
    ldr x18,      [sp, #144]
    ldr x16,      [sp, #192]
    str x19,      [sp, #192]
    blr x16
    str x0, [sp, #168]
    // Restore original string pointer before re-encrypting. The callee may
    // legally clobber x0 with a return value.
    ldr x19,      [sp, #192]
    // Reload decoded params (caller-saved may be clobbered by callee).
    ldr w8,  [sp, #280]
    ldr w11, [sp, #284]
    ldr w12, [sp, #288]
    ldr w13, [sp, #292]
    ldr w14, [sp, #296]
    ldr w15, [sp, #300]
    ldr w9,  [sp, #304]
    ldr x7,  [sp, #312]
    add x0, x7, x19
    mov w3, #0
.Llazy_enc:
    cmp w3, w8
    b.hs .Llazy_reseal
    ldrb w4, [x0, x3]
    add w11, w11, w12
    add w11, w11, w15
    mul w6, w3, w13
    add w6, w6, w14
    eor w11, w11, w6
    eor w11, w11, w11, lsl #13
    eor w11, w11, w11, lsr #17
    eor w11, w11, w11, lsl #5
    mul w6, w3, w12
    add w6, w6, w11
    lsr x17, x7, #4
    add w6, w6, w17
    tbz w9, #0, .Llazy_e0
    eor w6, w6, w11, lsr #8
.Llazy_e0:
    tbz w9, #1, .Llazy_e1
    eor w6, w6, w15
.Llazy_e1:
    tbz w9, #2, .Llazy_e2
    eor w6, w6, w11, lsl #7
.Llazy_e2:
    tbz w9, #3, .Llazy_e3
    eor w6, w6, w11, lsr #11
.Llazy_e3:
    mov w16, #0xeb2d
    movk w16, #0x27d4, lsl #16
    mul w16, w3, w16
    add w16, w16, w14
    eor w16, w16, w11
    lsr x17, x7, #16
    eor w16, w16, w17
    eor w16, w16, w15
    mov w17, #0x67b1
    movk w17, #0x1656, lsl #16
    add w18, w3, #1
    mul w17, w18, w17
    eor w16, w16, w17
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    eor w17, w16, w16, lsr #16
    add w16, w17, w11, lsl #3
    eor w6, w6, w16
    mov w16, w11
    eor w16, w16, w14
    ror w17, w15, #23
    eor w16, w16, w17
    eor w16, w16, w7
    lsr x17, x7, #32
    eor w16, w16, w17
    mov w17, #0x7c15
    movk w17, #0x7f4a, lsl #16
    mul w17, w3, w17
    add w16, w16, w17
    add w16, w16, w13
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    mov w17, #0x79b9
    movk w17, #0x9e37, lsl #16
    mul w17, w9, w17
    add w17, w17, w16
    and w18, w3, #7
    add w18, w18, #5
    neg w18, w18
    ror w17, w17, w18
    eor w16, w16, w17
    eor w16, w16, w16, lsr #13
    eor w6, w6, w16
    add w16, w14, w3
    and w17, w3, #7
    add w17, w17, #3
    neg w17, w17
    ror w16, w16, w17
    eor w16, w16, w11
    lsr x17, x7, #32
    eor w17, w17, w15
    add w16, w16, w17
    mul w17, w3, w12
    add w17, w17, w12
    eor w16, w16, w17
    mov w17, #0x79f5
    movk w17, #0x6d2b, lsl #16
    mul w17, w9, w17
    add w16, w16, w17
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    lsr x17, x7, #7
    add w17, w17, w13
    add w17, w17, w16
    and w18, w3, #3
    add w18, w18, #9
    neg w18, w18
    ror w17, w17, w18
    eor w16, w16, w17
    eor w16, w16, w16, lsl #13
    eor w16, w16, w16, lsr #17
    eor w16, w16, w16, lsl #5
    eor w6, w6, w16
    eor w4, w4, w6
    strb w4, [x0, x3]
    add w3, w3, #1
    b .Llazy_enc
    
.Llazy_reseal:
    lsr x16, x0, #12
    lsl x16, x16, #12
    sub x17, x0, x16
    add x1, x17, x8
    add x1, x1, #4095
    lsr x1, x1, #12
    lsl x1, x1, #12
    mov x0, x16
    mov x2, #5
    mov x8, #226
    svc #0
.Llazy_return:
    ldp x19, x20, [sp, #176]
    ldr x30,      [sp, #216]
    ldr x18,      [sp, #144]
    ldr x17,      [sp, #128]
    ldp x15, x16, [sp, #112]
    ldp x13, x14, [sp, #96]
    ldp x11, x12, [sp, #80]
    ldp x9,  x10, [sp, #64]
    ldp x7,  x8,  [sp, #48]
    ldp x5,  x6,  [sp, #32]
    ldp x3,  x4,  [sp, #16]
    ldr x0,        [sp, #168]
    ldp x1,  x2,  [sp], #320
    ret

.Llazy_mask:
    adr x16, strdec_lazy_mask_index_mul
    ldr w4, [x16]
    mul w4, w18, w4
    adr x16, strdec_lazy_mask_pos_mul
    ldr w16, [x16]
    madd w4, w3, w16, w4
    adr x16, strdec_lazy_mask_base
    ldr w16, [x16]
    add w4, w4, w16
    eor w4, w4, w4, lsl #13
    eor w4, w4, w4, lsr #17
    eor w4, w4, w4, lsl #5
    add w16, w18, #1
    adr x17, strdec_lazy_mask_round_mul
    ldr w17, [x17]
    madd w4, w16, w17, w4
    eor w4, w4, w3, lsl #11
    eor w4, w4, w4, lsr #16
    and w4, w4, #0xff
    ret

.balign 4
.global strdec_honeypot_entry
.type strdec_honeypot_entry, %function
strdec_honeypot_entry:
    // Static-analysis bait only. This function is intentionally unreachable
    // from the runtime entry path, but resembles a compact decrypt loop and
    // points at a fake table below. Automated slicers should waste effort here.
    adr x5, strdec_honeypot_table
    ldr w6, [x5]
    mov w7, #0
.Lhoneypot_loop:
    cmp w7, #32
    b.hs .Lhoneypot_done
    add w6, w6, w7
    eor w6, w6, w6, lsl #13
    eor w6, w6, w6, lsr #17
    eor w6, w6, w6, lsl #5
    add w7, w7, #1
    b .Lhoneypot_loop
.Lhoneypot_done:
    ret

.balign 4
strdec_maps_path_xor:
    .byte 0x75, 0x2a, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3f, 0x36, 0x3c, 0x75, 0x37, 0x3b, 0x2a, 0x29, 0x5a
strdec_smaps_path_xor:
    .byte 0x75, 0x2a, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3f, 0x36, 0x3c, 0x75, 0x29, 0x37, 0x3b, 0x2a, 0x29, 0x5a
strdec_status_path_xor:
    .byte 0x75, 0x2a, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3f, 0x36, 0x3c, 0x75, 0x29, 0x2e, 0x3b, 0x2e, 0x2f, 0x29, 0x5a
strdec_fd_path_xor:
    .byte 0x75, 0x2a, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3f, 0x36, 0x3c, 0x75, 0x3c, 0x3e, 0x75, 0x5a, 0x5a, 0x5a
strdec_net_unix_path_xor:
    .byte 0x75, 0x2a, 0x28, 0x35, 0x39, 0x75, 0x34, 0x3f, 0x2e, 0x75, 0x2f, 0x34, 0x33, 0x22, 0x5a
strdec_task_comm_path_xor:
    .byte 0x75, 0x2a, 0x28, 0x35, 0x39, 0x75, 0x29, 0x3f, 0x36, 0x3c, 0x75, 0x2e, 0x3b, 0x29, 0x31, 0x75, 0x5a, 0x5a, 0x75, 0x39, 0x35, 0x37, 0x37, 0x5a, 0x5a

.balign 8
strdec_anchor:
    .quad 0xd36e8a4c91f0b257
strdec_static_anchor_va:
    .quad 0x7b2d94f0c83ea615
strdec_orig_entry_va:
    .quad 0xa4f1379c6e2b58d0
strdec_page_va:
    .quad 0x5c8e03b7d14a6f29
strdec_page_len:
    .quad 0xe9a62c10b74d358f
strdec_payload_len:
    .quad 0x14c7d90e5a6b2381
strdec_entry_count:
    .word 0x8c2f47b1
strdec_guard_seed:
    .word 0x3a95d6e8
strdec_table_seed:
    .word 0xd7a18c5e
strdec_key_seed:
    .word 0x6e4b92f3
strdec_param_table_a:
    .word 0xb8173d4c
strdec_param_table_b:
    .word 0x4f2ca9e1
strdec_param_key_index:
    .word 0xc6d5803b
strdec_param_string_pos:
    .word 0x29e7b46a
strdec_param_string_index:
    .word 0xf13c58d2
strdec_guard_hash:
    .word 0x6b8d2a91
.balign 8
strdec_orig_entry_key:
    .quad 0x0d8f64b3e27a951c
strdec_runtime_table_hash:
    .word 0x13579bdf
strdec_runtime_table_hash_seed:
    .word 0x2468ace1
strdec_runtime_table_hash_mask:
    .word 0xf0e1d2c3
.balign 8
strdec_table:
    .quad 0x9364d2b80f5ace17
    .quad 0x48c1a7e53b9d026f
    .quad 0xaf5d0173c92b4e68

.balign 4
strdec_lazy_count:
    .word 0x01234567
strdec_lazy_hash:
    .word 0x89abcdef
strdec_lazy_hash_seed:
    .word 0x6d2b79f5
strdec_lazy_hash_mask:
    .word 0xa5c35a7e
strdec_lazy_mask_index_mul:
    .word 0x045d9f3b
strdec_lazy_mask_pos_mul:
    .word 0x27d4eb2d
strdec_lazy_mask_base:
    .word 0x6a09e667
strdec_lazy_mask_round_mul:
    .word 0x9e3779b9
.balign 8
strdec_lazy_table:
    .quad 0x123456789abcdef0
    .quad 0x123456789abcdef0
    .quad 0x123456789abcdef0
    .quad 0x123456789abcdef0
    .quad 0x123456789abcdef0
    .quad 0x123456789abcdef0
    .quad 0x123456789abcdef0

.balign 8
strdec_honeypot_table:
    .quad 0x4e42475f66616b65
    .quad 0xdec0de5eed15ea5e
    .quad 0x8badf00dfeedface
