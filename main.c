#include "main.h"

// Non-present page: 0x1FC00000-0x1FFFFFFF is unpresent
// Non-present page pde/pte address: 0xF03C01FC for 4KB page, 0xF00001FC for 4MB page
// Non-present address: 0x1FC00004
uint32 PF_ADDRESS = 0x1FC00004; // uint32 my_ptr = 0xF00001FC;
uint32 my_ptr = 0xF00001FC;
uint32 pf_counter = 0;
uint32 pf_old_offset;
uint16 pf_old_segment;

uint32 ud_old_offset;
uint16 ud_old_segment;

uint32 ud_counter = 0;

uint32 ud_cause_offset;
uint16 ud_cause_segment;

uint32 apic_base;
uint32 timer_counter = 0;
uint32 eoi_address = 0;
uint32 old_icr0 = 0;
uint32 old_icr1 = 0;

void __declspec( naked ) pf_handler(void) {
    __asm {
        //cli
        push eax
        push edx
        mov edx, cr2
        cmp edx, PF_ADDRESS        //"my" address
        jnz old_pf
        mov eax, my_ptr            //pde/pte corresponding to "my" unpresent address
        or dword ptr[eax], 1h      //restore P bit
        invlpg [eax]               //invalidate all paging caches for "my" address
        lea eax, pf_counter
        add [eax], 1               //inc counter of "my" #PF

        jmp pf_done
old_pf:
        pop edx
        pop eax
        sub esp, 2 // Align segment selector
        push pf_old_segment
        push pf_old_offset
        retf 
pf_done:
        pop edx
        pop eax
        //sti
        add esp, 4
        iretd
    }
}

void __declspec( naked ) ud_handler(void) {
    __asm {
        push eax
        push ebx
        // push es

        mov ebx, [esp+12] // Get error point segment selector
        cmp bx, ud_cause_segment
        jnz old_ud

        mov ebx, [esp+8] // Get error point segment offset
        cmp ebx, ud_cause_offset
        jnz old_ud
        mov [ebx], 0x90
        mov [ebx+1], 0x90
        lea eax, ud_counter
        add [eax], 1               //inc counter of #UD

        jmp ud_done
old_ud:
        pop ebx
        pop eax
        sub esp, 2 // Align segment selector
        push ud_old_segment
        push ud_old_offset
        retf
ud_done:
        // pop es
        pop ebx
        pop eax
        iretd
    }
}

void __declspec( naked ) timer_handler(void) {
    __asm {
        push eax
        
        mov eax, 0xFFE000B0
        mov [eax], 0x00000000
        
        lea eax, timer_counter
        add [eax], 1

        pop eax
        iretd
    }
}

void ud_cause(void) {
    __asm {
        rsm
        nop
        nop
    }
}

void get_sysinfo(PSYSINFO sysinfo) {
    uint32 _cpl = 0;
    uint32 _cr0 = 0;
    PDTR _gdt = &sysinfo->gdt;
    PDTR _idt = &sysinfo->idt;
    uint16* _ldtr = &sysinfo->ldtr;
    uint16* _tr = &sysinfo->tr;
    printf("LDTR = 0x%08X\n", _ldtr);
    printf("TR = 0x%08X\n", _tr);
    __asm {
        // Read CPL from code selector CS (Intel Manual 3A. Section 3.4.2)
        mov ax, cs
        and eax, 3
        mov _cpl, eax

        // Read CR0 (Intel Manual 3A. Section 2.5)
        mov eax, cr0
        mov _cr0, eax

        // Read GDT/IDT (Intel Manual 3A. Section 2.4)
        mov eax, _gdt
        sgdt [eax]
        mov eax, _idt
        sidt [eax]

        // Read LDT (Intel Manual 3A. Section 2.4)
        mov eax, _ldtr
        sldt [eax]

        // Read TR (Intel Manual 3A. Section ----)
        mov eax, _tr
        str [eax]
    }
    printf("LDTR = 0x%08X\n", _ldtr);
    printf("TR = 0x%08X\n", _tr);
    sysinfo->cpl = _cpl;
    sysinfo->cr0 = _cr0;
}

void fprint_system_info(FILE* f, PSYSINFO sysinfo) {
    fprintf(f, "================ \n");
    fprintf(f, "Protected Mode: %s \n", (sysinfo->cr0 & MASK(CR0_PE)) ? "on" : "off");
    fprintf(f, "Paging Mode: %s \n",    (sysinfo->cr0 & MASK(CR0_PG)) ? "on" : "off");
    fprintf(f, "Ring: CPL=%d \n",       sysinfo->cpl);
    fprintf(f, "================ \n");
    fprintf(f, "GDT: base=0x%08X limit=0x%04X \n", sysinfo->gdt.base, sysinfo->gdt.limit);
    fprintf(f, "IDT: base=0x%08X limit=0x%04X \n", sysinfo->idt.base, sysinfo->idt.limit);
    fprintf(f, "LDTR: 0x%04X\n", sysinfo->ldtr);
    fprintf(f, "TR: 0x%04X\n", sysinfo->tr);
}

void fprint_tss_segment(FILE* f, PTSS tss) {
    fprintf(f, "Previous Task List 0x%04X\n", tss->prev_task_list);
    fprintf(f, "ESP0 0x%08X, SS0 0x%04X\n", tss->esp0, tss->ss0);
    fprintf(f, "ESP1 0x%08X, SS1 0x%04X\n", tss->esp1, tss->ss1);
    fprintf(f, "ESP2 0x%08X, SS2 0x%04X\n", tss->esp2, tss->ss2);
    fprintf(f, "CR3 0x%08X, EIP 0x%08X, EFLAGS 0x%08X\n", tss->cr3, tss->eip, tss->eflags);

    fprintf(f, "EAX 0x%08X, ECX 0x%08X\n", tss->eax, tss->ecx);
    fprintf(f, "EDX 0x%08X, EBX 0x%08X\n", tss->edx, tss->ebx);
    fprintf(f, "ESP 0x%08X, EBP 0x%08X\n", tss->esp, tss->ebp);
    fprintf(f, "ESI 0x%08X, EDI 0x%08X\n", tss->esi, tss->edi);

    fprintf(f, "ES 0x%04X, CS 0x%04X\n", tss->es, tss->cs);
    fprintf(f, "SS 0x%04X, DS 0x%04X\n", tss->ss, tss->ds);
    fprintf(f, "FS 0x%04X, GS 0x%04X\n", tss->fs, tss->gs);

    fprintf(f, "LDT Selector 0x%04X, T 0x%01X, IO Map Base 0x%04X\n", tss->ldt_sel, tss->t, tss->io_map_base);
}

void fprint_descriptor(FILE* f, PDESCRIPTOR descriptor) {
    fprintf(f, "\tVALUE=0x%08X-%08X PRESENT=%s \n", descriptor->raw.high, descriptor->raw.low, descriptor->desc.p ? "yes" : "no");
    if (descriptor->desc.p) {
        if (descriptor->desc.s == 0) {
            // TODO: System descriptor
            fprintf(f, "\tRING=%d TYPE=0x%X SYSTEM=%s\n",
                    descriptor->desc.dpl, descriptor->desc.type, descriptor->desc.s ? "segment" : "system");
            // System descriptor type (Table 3-2)
            switch (descriptor->desc.type) {
                case 0:
                case 8:
                case 10:
                case 13:
                    fprintf(f, "\tTYPE: Reserved\n");
                    break;
                case 1:
                case 3:
                    fprintf(f, "\tTYPE: 16-bit TSS (%s)\n", descriptor->desc.type == 1 ? "Available" : "Busy");
                    fprintf(f, "\tBASE=0x%08X LIMIT=0x%08X \n", BASE_FROM_PDESCRIPTOR(descriptor), LIMIT_FROM_PDESCRIPTOR(descriptor));
                    fprintf(f, "\tRING=%d AVL=%s G=%s\n", descriptor->tss_desc.dpl, descriptor->tss_desc.avl ? "yes" : "no", descriptor->tss_desc.g ? "16bit TSS" : "32bit TSS");
                    break;
                case 2:
                    fprintf(f, "\tTYPE: LDT\n");
                    fprintf(f, "\tBASE=0x%08X LIMIT=0x%08X \n", BASE_FROM_PDESCRIPTOR(descriptor), LIMIT_FROM_PDESCRIPTOR(descriptor));
                    fprintf(f, "\tRING=%d AVL=%s G=%s\n", descriptor->tss_desc.dpl, descriptor->tss_desc.avl ? "yes" : "no", descriptor->tss_desc.g ? "16bit" : "32bit");
                    break;
                case 4:
                    fprintf(f, "\tTYPE: 16-bit Call Gate\n");
                    fprintf(f, "\tSegment: 0x%08X, Offset: 0x%08X\n", 
                            descriptor->call_gate.segment_selector, 
                            (descriptor->call_gate.segment_offset_low | (descriptor->call_gate.segment_offset_high << 16)));
                    fprintf(f, "\tRING=%d\n", descriptor->call_gate.dpl);
                    break;
                case 5:
                    fprintf(f, "\tTYPE: Task Gate\n");
                    fprintf(f, "\tTSS segment selector 0x%04X\n", descriptor->task_gate.segment_selector);
                    fprintf(f, "\tRING=%d\n", descriptor->task_gate.dpl);
                    break;
                case 6:
                    fprintf(f, "\tTYPE: 16-bit Interrupt Gate\n");
                    fprintf(f, "\tSegment: 0x%08X, Offset: 0x%08X\n", 
                            descriptor->interrupt_trap_gate.segment_selector, 
                            (descriptor->interrupt_trap_gate.segment_offset_low | (descriptor->interrupt_trap_gate.segment_offset_high << 16)));
                    fprintf(f, "\tRING=%d\n", descriptor->call_gate.dpl);
                    break;
                case 7:
                    fprintf(f, "\tTYPE: 16-bit Trap Gate\n");
                    fprintf(f, "\tSegment: 0x%08X, Offset: 0x%08X\n", 
                            descriptor->interrupt_trap_gate.segment_selector, 
                            (descriptor->interrupt_trap_gate.segment_offset_low | (descriptor->interrupt_trap_gate.segment_offset_high << 16)));
                    fprintf(f, "\tRING=%d\n", descriptor->call_gate.dpl);
                    break;
                case 9:
                case 11:
                    fprintf(f, "\tTYPE: 32-bit TSS (%s)\n", descriptor->desc.type == 9 ? "Available" : "Busy");
                    fprintf(f, "\tBASE=0x%08X LIMIT=0x%08X \n", BASE_FROM_PDESCRIPTOR(descriptor), LIMIT_FROM_PDESCRIPTOR(descriptor));
                    fprintf(f, "\tRING=%d AVL=%s G=%s\n", descriptor->tss_desc.dpl, descriptor->tss_desc.avl ? "yes" : "no", descriptor->tss_desc.g ? "16bit TSS" : "32bit TSS");
                    break;
                case 12:
                    fprintf(f, "\tTYPE: 32-bit Call Gate\n");
                    fprintf(f, "\tSegment: 0x%08X, Offset: 0x%08X\n", 
                            descriptor->call_gate.segment_selector, 
                            (descriptor->call_gate.segment_offset_low | (descriptor->call_gate.segment_offset_high << 16)));
                    fprintf(f, "\tRING=%d\n", descriptor->call_gate.dpl);
                    break;
                case 14:
                    fprintf(f, "\tTYPE: 32-bit Interrupt Gate\n");
                    fprintf(f, "\tSegment: 0x%08X, Offset: 0x%08X\n", 
                            descriptor->interrupt_trap_gate.segment_selector, 
                            (descriptor->interrupt_trap_gate.segment_offset_low | (descriptor->interrupt_trap_gate.segment_offset_high << 16)));
                    fprintf(f, "\tRING=%d\n", descriptor->call_gate.dpl);
                    break;
                case 15:
                    fprintf(f, "\tTYPE: 32-bit Trap Gate\n");
                    fprintf(f, "\tSegment: 0x%08X, Offset: 0x%08X\n", 
                            descriptor->interrupt_trap_gate.segment_selector, 
                            (descriptor->interrupt_trap_gate.segment_offset_low | (descriptor->interrupt_trap_gate.segment_offset_high << 16)));
                    fprintf(f, "\tRING=%d\n", descriptor->call_gate.dpl);
                    break;
            }
        } else {
            fprintf(f, "\tBASE=0x%08X LIMIT=0x%08X \n", BASE_FROM_PDESCRIPTOR(descriptor), LIMIT_FROM_PDESCRIPTOR(descriptor));
            fprintf(f, "\tRING=%d TYPE=0x%X SYSTEM=%s DB=%s\n",
                    descriptor->desc.dpl, descriptor->desc.type, descriptor->desc.s ? "segment" : "system",
                    descriptor->desc.db ? "32bit" : "16bit");

            if ((descriptor->desc.type >> 3) & 0x1== 1) { // Code descriptor
                fprintf(f, "\tCode page, Accessed=%s Readable:%s Conforming:%s\n", descriptor->code_desc.type_a ? "yes":"no", descriptor->code_desc.type_r ? "yes":"no", descriptor->code_desc.type_c ? "yes":"no");
            } else { // Data descriptor
                fprintf(f, "\tData page, Accessed=%s Writable:%s Expansion:%s\n", descriptor->data_desc.type_a ? "yes":"no", descriptor->data_desc.type_w ? "yes":"no", descriptor->data_desc.type_e ? "down":"up");
            }
        }
    }
}

void fprint_desctable(FILE* f, uint32* base, uint32 limit) {
    int i;
    for (i = 0;; i++) { // i used as an index in array with 64bit entries
        DESCRIPTOR d;
        if (i * 8 > limit)
            break;
        fprintf(f, "Element %d (selector = %04X): \n", i, i << 3);
        d.raw.low = base[i*2];
        d.raw.high = base[i*2 + 1];
        fprint_descriptor(f, &d);
    }
}

void fprint_mem_tables(PSYSINFO sysinfo) {
    FILE* gdt_dump_file;
    FILE* idt_dump_file;
    FILE* ldt_dump_file;
    FILE* tss_dump_file;
    DESCRIPTOR d;
    uint32* gdt;

    // Print GDT
    gdt_dump_file = fopen("gdt_dump.txt", "w");
    if (gdt_dump_file == 0) {
        fprintf(stderr, "ERROR: cannot fopen gdt_dump.txt file\n");
    } else {
        fprint_desctable(gdt_dump_file, (uint32*)sysinfo->gdt.base, sysinfo->gdt.limit);
    }
    fclose(gdt_dump_file);

    // Print IDT
    idt_dump_file = fopen("idt_dump.txt", "w");
    if (idt_dump_file == 0) {
        fprintf(stderr, "ERROR: cannot fopen idt_dump.txt file\n");
    } else {
        fprint_desctable(idt_dump_file, (uint32*)sysinfo->idt.base, sysinfo->idt.limit);
    }
    fclose(idt_dump_file);

    gdt = (uint32*)sysinfo->gdt.base;

    // Print LDT
    ldt_dump_file = fopen("ldt_dump.txt", "w");
    if (ldt_dump_file == 0) {
        fprintf(stderr, "ERROR: cannot fopen ldt_dump.txt file\n");
    } else {
        d.raw.low = gdt[(sysinfo->ldtr >> 3) * 2];
        d.raw.high = gdt[(sysinfo->ldtr >> 3) * 2 + 1];
        fprintf(ldt_dump_file, "LDT Descriptor (GDT Selector 0x%04X):\n", sysinfo->ldtr);
        fprint_descriptor(ldt_dump_file, &d);
        if (d.desc.p) {
            fprintf(ldt_dump_file, "Local Descriptors Table content:\n");
            fprint_desctable(ldt_dump_file, (uint32*)BASE_FROM_PDESCRIPTOR(&d), LIMIT_FROM_PDESCRIPTOR(&d));
        }
        fclose(ldt_dump_file);
    }

    // Print TR/TSS
    tss_dump_file = fopen("tss_dump.txt", "w");
    if (tss_dump_file == 0) {
        fprintf(stderr, "ERROR: cannot fopen tss_dump.txt file\n");
    } else {
        d.raw.low = gdt[(sysinfo->tr >> 3) * 2];
        d.raw.high = gdt[(sysinfo->tr >> 3) * 2 + 1];
        fprintf(tss_dump_file, "TSS Descriptor (GDT Selector 0x%04X):\n", sysinfo->tr);
        fprint_descriptor(tss_dump_file, &d);
        if (d.desc.p) {
            fprintf(tss_dump_file, "TSS Content:\n");
            fprint_tss_segment(tss_dump_file, (PTSS)BASE_FROM_PDESCRIPTOR(&d));
        }
        fclose(tss_dump_file);
    }
}

void idt_set_gate(PIDTENTRY idt, uint8 num, uint32 offset, uint16 seg_selector, uint8 flags) {
    idt[num].offset_low = offset & 0xFFFF;
    idt[num].offset_high = (offset >> 16) & 0xFFFF;
    idt[num].seg_selector = seg_selector;
    idt[num].zero = 0;
    idt[num].flags = flags;
}

void enable_paging() {
    int i;
    void* p = malloc(8 * 1024 * 1024);
    uint32 _p = (uint32)p;
    uint32 _p_aligned = (_p & 0xFFC00000) + 4*1024*1024;
    uint32 _pd = _p_aligned;
    PPTE pd = (PPTE) _pd;

    printf("Malloc 8MB block at 0x%08X-0x%08X, aligned address 0x%08X\n", _p, _p+8*1024*1024, _p_aligned);

    for (i = 0; i < 1024; i++) {
        pd[i].raw = i * 0x400000;
        pd[i].raw |= (i < 512) ? PTE_TRIVIAL_LARGE : PTE_TRIVIAL_NONPRESENT;
    }

    // Self-mapping
    pd[0x3C0].raw = _p_aligned | PTE_TRIVIAL_SELFMAP; // Self-mapped to 0xF0000000
    pd[0x7F].raw &= 0xFFFFFFFE; // virtual page 0x1FC00000-0x1FFFFFFF is unpresent
    __asm {
        pushfd
        cli

        mov eax, _p_aligned
        mov cr3, eax // Cause a cache reset
        
        // Enable CR4.PSE and CR4.PGE bits
        mov eax, cr4
        or eax, 0x90
        mov cr4, eax
        
        // Enable CR0.PG bit
        mov eax, cr0
        or eax, 0x80000000
        mov cr0, eax

        popfd
    }
    printf("Paging enabled\n");
}

void page_fault_test(PSYSINFO sysinfo) {
    uint32 new_offset = 0;
    uint16 new_segment = 0;
    uint32* address;
    PIDTENTRY idt_table = (PIDTENTRY) sysinfo->idt.base;
    // Save old pf_handler offset
    pf_old_offset = (idt_table[PF_EXCEPTION].offset_high << 16) | idt_table[PF_EXCEPTION].offset_low;
    pf_old_segment = idt_table[PF_EXCEPTION].seg_selector;
    
    printf("PF counter: %d\n", pf_counter);

    // Calcualte new pf_handler segment/offset
    __asm {
        mov edx, offset pf_handler
        mov new_offset, edx
        mov ax, seg pf_handler
        mov new_segment, ax
    }

    printf("Setting up new PF handler\n");

    idt_set_gate(idt_table, PF_EXCEPTION, new_offset, new_segment, idt_table[PF_EXCEPTION].flags);

    address = (uint32*) (PF_ADDRESS);
    printf("Test new handler\n");
    printf("Check memory [0x%08X]: %d\n", address, *address); // Cause page fault with following recovery

    printf("PF counter: %d\n", pf_counter);
}

void register_custom_ud_handler(PSYSINFO sysinfo) {
    uint32 new_offset = 0;
    uint16 new_segment = 0;
    PIDTENTRY idt_table = (PIDTENTRY) sysinfo->idt.base;
    ud_old_offset = (idt_table[UD_EXCEPTION].offset_high << 16) | idt_table[UD_EXCEPTION].offset_low;
    ud_old_segment = idt_table[UD_EXCEPTION].seg_selector;

    __asm {
        mov edx, offset ud_cause
        mov ud_cause_offset, edx
        mov ax, seg ud_cause
        mov ud_cause_segment, ax
    }
    ud_cause_offset += 0x18; // Position of RSM opcode in ud_cause

    __asm {
        mov edx, offset ud_handler
        mov new_offset, edx
        mov ax, seg ud_handler
        mov new_segment, ax
    }

    idt_set_gate(idt_table, UD_EXCEPTION, new_offset, new_segment, idt_table[UD_EXCEPTION].flags);
}

void undefined_opcode_test() {
    ud_cause();
    printf("UD counter: %d\n", ud_counter);
}

void register_timer_handler(PSYSINFO sysinfo) {
    uint32 new_offset = 0;
    uint16 new_segment = 0;
    uint8 flags;
    PIDTENTRY idt_table = (PIDTENTRY) sysinfo->idt.base;
    __asm {
        mov edx, offset timer_handler
        mov new_offset, edx
        mov ax, seg timer_handler
        mov new_segment, ax
    }
    flags = 0x8E;
    idt_set_gate(idt_table, TIMER_INTERRUPT, new_offset, new_segment, flags);
}

void enable_apic_timer() {
    LVT_TIMER_REG lvt_timer_reg;
    APIC_BASE_REG apic_base_reg;
    int _test = 0;

    memset(&lvt_timer_reg, 0, sizeof(lvt_timer_reg));
    lvt_timer_reg.vector = TIMER_INTERRUPT;
    lvt_timer_reg.delivery_status = 1;
    lvt_timer_reg.mask = 0;
    lvt_timer_reg.timer_mode = 0; // Once-shot
    memset(&apic_base_reg, 0, sizeof(apic_base_reg));

    __asm {
        mov ecx, 0x1B
        rdmsr
        lea ecx, apic_base_reg
        mov [ecx], eax
        mov [ecx]+4, edx
    }

    apic_base = apic_base_reg.base_address << 16;
    printf("APIC BASE: 0x%08X\n", apic_base);

    // Reset Timer configuration
    __asm {
        mov eax, apic_base
        add eax, APIC_TIMER_INITIAL_COUNTER_OFFSET
        mov [eax], 0x00000000
        
        mov eax, apic_base
        add eax, APIC_TIMER_LVT_OFFSET
        mov [eax], 0x00010000

        mov eax, apic_base
        add eax, APIC_TIMER_EOI_OFFSET
        mov [eax], 0x00000000
    }

    printf("APIC BASE REG: 0x%08X\n", apic_base_reg);
    printf("APIC BASE REG: bsp=%s, enabled=%s, base=0x%08X\n", apic_base_reg.bsp ? "yes" : "no", apic_base_reg.global_enable_bit ? "yes" : "no", apic_base_reg.base_address);

    __asm {
        mov eax, apic_base
        add eax, APIC_TIMER_DIVIDE_CONF_OFFSET
        mov [eax], 0x00000000 // No divide freq

        mov ebx, apic_base
        add ebx, APIC_TIMER_LVT_OFFSET
        lea eax, lvt_timer_reg
        mov ecx, [eax]
        mov [ebx], ecx

        mov eax, apic_base
        add eax, APIC_TIMER_INITIAL_COUNTER_OFFSET
        mov [eax], APIC_TIMER_INITIAL_TIME

        mov eax, apic_base
        add eax, APIC_TIMER_CURRENT_COUNTER_OFFSET
        mov [eax], APIC_TIMER_INITIAL_TIME
    }

    // The following code also make sufficient latency for the timer
    __asm {
        mov eax, apic_base
        add eax, APIC_TIMER_CURRENT_COUNTER_OFFSET
        mov ebx, [eax]
        mov _test, ebx
    }
    printf("Timer current counter:0x%08X\n", _test);
}

void print_info_task(PSYSINFO sysinfo) {
    FILE* sysinfo_file;
    sysinfo_file = fopen("sysinfo.txt", "w");
    fprint_system_info(sysinfo_file, sysinfo);
    fprint_mem_tables(sysinfo);
    fclose(sysinfo_file);
}

void paging_task(PSYSINFO sysinfo) {
    enable_paging();
    page_fault_test(sysinfo);
}

void exception_task(PSYSINFO sysinfo) {
    register_custom_ud_handler(sysinfo);
    undefined_opcode_test();
}

void apic_timer_task(PSYSINFO sysinfo) {
    register_timer_handler(sysinfo);
    enable_apic_timer();
    printf("Timer counter=%d\n", timer_counter);
}

void print_help() {
    printf("Usage:\n");
    printf("\tasm_task /1 - print tables information.\n");
    printf("\tasm_task /2 - enable paging and test custom #PF handler.\n");
    printf("\tasm_task /3 - configure and test custom #UD exception handler (cause by RSM opcode).\n");
    printf("\tasm_task /4 - configure and test APIC Timer.\n");
}

int main(int argc, char** argv) {
    SYSINFO sysinfo;

    if (argc != 2) {
        print_help();
        return -1;
    }

    memset(&sysinfo, 0, sizeof(sysinfo));
    get_sysinfo(&sysinfo);

    if (strcmp("/1", argv[1]) == 0) {
        print_info_task(&sysinfo);
    } else if (strcmp("/2", argv[1]) == 0) {
        paging_task(&sysinfo);
    } else if (strcmp("/3", argv[1]) == 0) {
        exception_task(&sysinfo);
    } else if (strcmp("/4", argv[1]) == 0) {
        apic_timer_task(&sysinfo);
    } else {
        print_help();
    }
    return 0;
}
