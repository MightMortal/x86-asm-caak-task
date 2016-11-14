#ifndef __ASM_TASK_MAIN_H_
#define __ASM_TASK_MAIN_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char uint8;
typedef signed char int8;
typedef unsigned short int uint16;
typedef signed short int int16;
typedef unsigned int uint32;
typedef signed int int32;

#pragma pack (push, 1)

// System Table Registers. See Intel Manual 3A. Figure 2-6 (Section 2.4)
typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 _padding;
} DTR, *PDTR;

typedef union _DESCRIPTOR {
    struct {
        uint32 low;
        uint32 high;
    } raw;
    struct {
        // Intel x86 Manual 3A. Figure 3-8
        uint16 limit_low;
        uint16 base_low;
        uint8  base_mid;
        uint8  type:4;
        uint8  s:1;
        uint8  dpl:2;
        uint8  p:1;
        uint8  limit_high:4;
        uint8  avl:1;
        uint8  l:1; // L bit valid only in 64bit mode
        uint8  db:1;
        uint8  g:1;
        uint8  base_high;
    } desc;

    struct {
        // Intel x86 Manual 3A. Figure 5-1
        uint16 limit_low;
        uint16 base_low;
        uint8  base_mid;
        uint8  type_a:1;
        uint8  type_w:1;
        uint8  type_e:1;
        uint8  type_zero:1;
        uint8  s:1;
        uint8  dpl:2;
        uint8  p:1;
        uint8  limit_high:4;
        uint8  avl:1;
        uint8  l:1; // L bit valid only in 64bit mode
        uint8  db:1;
        uint8  g:1;
        uint8  base_high;
    } data_desc;

    struct {
        // Intel x86 Manual 3A. Figure 5-1
        uint16 limit_low;
        uint16 base_low;
        uint8  base_mid;
        uint8  type_a:1;
        uint8  type_r:1;
        uint8  type_c:1;
        uint8  type_one:1;
        uint8  s:1;
        uint8  dpl:2;
        uint8  p:1;
        uint8  limit_high:4;
        uint8  avl:1;
        uint8  l:1; // L bit valid only in 64bit mode
        uint8  db:1;
        uint8  g:1;
        uint8  base_high;
    } code_desc;

    // Intel Manual 3A. Figure 7-3
    struct {
        uint16 limit_low;
        uint16 base_low;
        uint8  base_mid;
        uint8  type:4;
        uint8  zero:1;
        uint8  dpl:2;
        uint8  p:1;
        uint8  limit_high:4;
        uint8  avl:1;
        uint8  zero2:2;
        uint8  g:1;
        uint8  base_high;
    } tss_desc;

    // Intel Manual 3A. Figure 7-6
    struct {
        uint16 reserv0;
        uint16 segment_selector;
        uint8  reserv1;
        uint8  type:4;
        uint8  zero:1;
        uint8  dpl:2;
        uint8  p:1;
        uint16 reserv2;
    } task_gate;

    // Intel Manual 3A. Figure 7-6
    struct {
        uint16 segment_offset_low;
        uint16 segment_selector;
        uint8  reserv:4;
        uint8  zero:3;
        uint8  type:4;
        uint8  s:1;
        uint8  dpl:2;
        uint8  p:1;
        uint16 segment_offset_high;
    } interrupt_trap_gate;

    // Intel Manual 3A. Figure 5-8
    struct {
        uint16 segment_offset_low;
        uint16 segment_selector;
        uint8  param_count:4;
        uint8  zero:3;
        uint8  type:4;
        uint8  s:1;
        uint8  dpl:2;
        uint8  p:1;
        uint16 segment_offset_high;
    } call_gate;
} DESCRIPTOR, *PDESCRIPTOR;

// TODO: Write info about this struct
typedef union _PTE {
    uint32 raw;
    struct {
        uint32 p:1;
        uint32 rw:1;
        uint32 us:1;
        uint32 reserv:4; // PCD, PWT, A, D - bits valid only in 64bit mode
        uint32 ps:1;
        uint32 g:1;
        uint32 avl:3;
        uint32 pfn:20;
    };
} PTE, *PPTE;

typedef struct _SYSINFO {
    uint32 cpl;
    uint32 cr0;
    DTR    gdt;
    DTR    idt;
    uint16 ldtr;
    uint16 tr;
} SYSINFO, *PSYSINFO;

typedef struct _IDTENTRY {
    uint16 offset_low;
    uint16 seg_selector;
    uint8  zero;
    uint8  flags;
    uint16 offset_high;
} IDTENTRY, *PIDTENTRY;

typedef struct _LVT_TIMER_REG {
    uint8  vector;
    uint8  reserv0:4;
    uint8  delivery_status:1;
    uint8  reserv1:3;
    uint8  mask:1;
    uint8  timer_mode:2;
    uint16 reserv2:13;
} LVT_TIMER_REG, *PLVT_TIMER_REG;

typedef struct _APIC_BASE_REG {
    uint8  reserv0;
    uint8  bsp:1;
    uint8  reserv1:1;
    uint8  x2apic_enable:1;
    uint8  global_enable_bit:1;
    uint32 base_address:24;
    uint32 reserv2;
} APIC_BASE_REG, *PAPIC_BASE_REG;

typedef struct _TSS {
    uint16 prev_task_list;
    uint16 padding0;
    uint32 esp0;
    uint16 ss0;
    uint16 padding1;
    uint32 esp1;
    uint16 ss1;
    uint16 padding2;
    uint32 esp2;
    uint16 ss2;
    uint16 padding3;

    uint32 cr3;
    uint32 eip;
    uint32 eflags;
    
    uint32 eax;
    uint32 ecx;
    uint32 edx;
    uint32 ebx;
    uint32 esp;
    uint32 ebp;
    uint32 esi;
    uint32 edi;

    uint16 es;
    uint16 padding4;
    uint16 cs;
    uint16 padding5;
    uint16 ss;
    uint16 padding6;
    uint16 ds;
    uint16 padding7;
    uint16 fs;
    uint16 padding8;
    uint16 gs;
    uint16 padding9;

    uint16 ldt_sel;
    uint16 padding10;
    uint16 t:1;
    uint16 padding11:15;
    uint16 io_map_base;
} TSS, *PTSS;

#pragma pack (pop)

#define CR0_PE 0
#define CR0_PG 31
#define CR4_PSE 4
#define MASK(x) (1<<(x))
#define PF_EXCEPTION 14
#define UD_EXCEPTION 6
#define BP_EXCEPTION 3
#define TIMER_INTERRUPT 0xF8

#define APIC_SPURIOUS_INTERRUPT_OFFSET 0xF0
#define APIC_TIMER_LVT_OFFSET 0x320
#define APIC_TIMER_INITIAL_COUNTER_OFFSET 0x380
#define APIC_TIMER_CURRENT_COUNTER_OFFSET 0x390
#define APIC_TIMER_DIVIDE_CONF_OFFSET 0x3E0
#define APIC_TIMER_EOI_OFFSET 0xB0

#define APIC_TIMER_INITIAL_TIME 0x00000001


#define PTE_TRIVIAL_SELFMAP    0x007 // 0000 0000 0111 - presented read-write user 4KB page
#define PTE_TRIVIAL_LARGE      0x087 // 0000 1000 0111 - presented read-write user 4MB page
#define PTE_TRIVIAL_NONPRESENT 0xBA4 // ---- ---- ---1
#define PTE_TRIVIAL_FAULTONCE  0x086 // Same as PTE_TRIVIAL_LARGE but not presented

#define BASE_FROM_PDESCRIPTOR(x) (((x)->desc.base_low) | ((x)->desc.base_mid << 16) | ((x)->desc.base_high << 24))
#define LIMIT_FROM_PDESCRIPTOR(x) ((((x)->desc.limit_low) | ((x)->desc.limit_high << 16)) << ((x)->desc.g ? 12 : 0))

#endif // __ASM_TASK_MAIN_H
