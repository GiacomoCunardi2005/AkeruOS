/* Resident Main0 guard for the optional Resource dumper module.
 * Link-time symbols bind the exact module bytes/CRC/entry and Nikon services.
 * Does not invoke Resource code unless every byte matches the built module.
 * Flag resides in the guard's explicitly reserved Main0 bytes, not Nikon BSS.
 */
.section .text,"ax",@progbits
.global akeru_ram_dump_guard
.type akeru_ram_dump_guard,@function
akeru_ram_dump_guard:
    push_s blink
    push_s r13
    push_s r14
    push_s r15
    bl nikon_after_resource_original
    mov_s r13,r0
    mov_s r14,akeru_ram_dump_guard_state
    ld_s r0,[r14]
    brne_s r0,0,.Lreturn

    mov_s r0,akeru_ram_dump_module_base
    mov r1,akeru_ram_dump_module_bytes
    mov r2,-1
.Lbyte:
    ldb_s r3,[r0]
    xor r2,r2,r3
    mov r12,8
.Lbit:
    and r3,r2,1
    lsr_s r2,r2,1
    breq_s r3,0,.Lnext_bit
    xor r2,r2,0xedb88320
.Lnext_bit:
    sub r12,r12,1
    brne r12,0,.Lbit
    add_s r0,r0,1
    sub_s r1,r1,1
    brne_s r1,0,.Lbyte
    not_s r2,r2
    mov r3,akeru_ram_dump_module_crc
    cmp_s r2,r3
    bne_s .Lreturn

    bl nikon_enter_critical
    ld_s r0,[r14]
    brne_s r0,0,.Lalready
    mov_s r0,1
    st_s r0,[r14]
    bl nikon_leave_critical
    mov_s r0,akeru_ram_dump_module_entry
    jl [r0]
    b_s .Lreturn
.Lalready:
    bl nikon_leave_critical
.Lreturn:
    mov_s r0,r13
    pop_s r15
    pop_s r14
    pop_s r13
    pop_s blink
    j_s [blink]
    nop_s
.size akeru_ram_dump_guard,.-akeru_ram_dump_guard
