/****************************    elf_forwardcom.h    **************************
* Author:        Agner Fog
* Date created:  2016-06-25
* Last modified: 2016-06-25
* Version:       1.02 (preliminary)
* Project:       ForwardCom development tools
* Description:
* Header file for definition of structures in 64 bit ELF object file format for the
* experimental ForwardCom instruction set architecture.
*
* To do: define formats for debug information
* To do: define exception handler and stack unwind information
* To do: define access rights of executable file or device driver
*
* Copyright 2016 GNU General Public License http://www.gnu.org/licenses/gpl.html
******************************************************************************/
#ifndef ELF_FORW_H
#define ELF_FORW_H

/********************** FILE HEADER **********************/

struct Elf64_Ehdr {
  uint8_t   e_ident[16];   // Magic number and other info
                           // e_ident[EI_CLASS] = ELFCLASS64: file class
                           // e_ident[EI_DATA] = ELFDATA2LSB: 2's complement, little endian
                           // e_ident[EI_VERSION] = EV_CURRENT: current ELF version
                           // e_ident[EI_OSABI] = ELFOSABI_FORWARDCOM
                           // e_ident[EI_ABIVERSION] = 0 
                           // The rest is unused padding   
  uint16_t  e_type;        // Object file type
  uint16_t  e_machine;     // Architecture
  uint32_t  e_version;     // Object file version
  uint64_t  e_entry;       // Entry point virtual address
  uint64_t  e_phoff;       // Program header table file offset
  uint64_t  e_shoff;       // Section header table file offset
  uint32_t  e_flags;       // Processor-specific flags. We may define any values for these flags!
  uint16_t  e_ehsize;      // ELF header size in bytes
  uint16_t  e_phentsize;   // Program header table entry size
  uint16_t  e_phnum;       // Program header table entry count
  uint16_t  e_shentsize;   // Section header table entry size
  uint16_t  e_shnum;       // Section header table entry count
  uint16_t  e_shstrndx;    // Section header string table index
};


// Fields in the e_ident array.  The EI_* macros are indices into the array.  
// The macros under each EI_* macro are the values the byte may have. 

// Conglomeration of the identification bytes, for easy testing as a word.
#define ELFMAG        "\177ELF"

// File class
#define EI_CLASS      4    // File class byte index
#define ELFCLASSNONE  0    // Invalid class
#define ELFCLASS32    1    // 32-bit objects
#define ELFCLASS64    2    // 64-bit objects *
#define ELFCLASSNUM   3

#define EI_DATA       5    // Data encoding byte index
#define ELFDATANONE   0    // Invalid data encoding
#define ELFDATA2LSB   1    // 2's complement, little endian *
#define ELFDATA2MSB   2    // 2's complement, big endian
#define ELFDATANUM    3

#define EI_VERSION    6    // File version byte index

#define EI_OSABI               7  // OS ABI identification
#define ELFOSABI_SYSV          0  // UNIX System V ABI
#define ELFOSABI_HPUX          1  // HP-UX 
#define ELFOSABI_ARM          97  // ARM 
#define ELFOSABI_STANDALONE  255  // Standalone (embedded) application
#define ELFOSABI_FORWARDCOM  250  // ForwardCom 

#define EI_ABIVERSION    8    // ABI version

#define EI_PAD           9    // Byte index of padding bytes

// Legal values for e_type (object file type). 
#define ET_NONE          0    // No file type
#define ET_REL           1    // Relocatable file
#define ET_EXEC          2    // Executable file
#define ET_DYN           3    // Shared object file (not used)
#define ET_CORE          4    // Core file 
#define ET_NUM           5    // Number of defined types
#define ET_LOOS     0xfe00    // OS-specific range start
#define ET_HIOS     0xfeff    // OS-specific range end
#define ET_LOPROC   0xff00    // Processor-specific range start
#define ET_HIPROC   0xffff    // Processor-specific range end

// Legal values for e_machine (architecture)
#define EM_NONE          0     // No machine
#define EM_M32           1     // AT&T WE 32100
#define EM_SPARC         2     // SUN SPARC
#define EM_386           3     // Intel 80386
#define EM_68K           4     // Motorola m68k family
#define EM_88K           5     // Motorola m88k family
#define EM_860           7     // Intel 80860
#define EM_MIPS          8     // MIPS R3000 big-endian
#define EM_S370          9     // IBM System/370
#define EM_MIPS_RS3_LE  10     // MIPS R3000 little-endian
#define EM_PARISC       15     // HPPA
#define EM_VPP500       17     // Fujitsu VPP500
#define EM_SPARC32PLUS  18     // Sun's "v8plus"
#define EM_960          19     // Intel 80960
#define EM_PPC          20     // PowerPC
#define EM_PPC64        21     // PowerPC 64-bit
#define EM_S390         22     // IBM S390
#define EM_V800         36     // NEC V800 series
#define EM_FR20         37     // Fujitsu FR20
#define EM_RH32         38     // TRW RH-32
#define EM_RCE          39     // Motorola RCE
#define EM_ARM          40     // ARM
#define EM_FAKE_ALPHA   41     // Digital Alpha
#define EM_SH           42     // Hitachi SH
#define EM_SPARCV9      43     // SPARC v9 64-bit
#define EM_TRICORE      44     // Siemens Tricore
#define EM_ARC          45     // Argonaut RISC Core
#define EM_H8_300       46     // Hitachi H8/300
#define EM_H8_300H      47     // Hitachi H8/300H
#define EM_H8S          48     // Hitachi H8S
#define EM_H8_500       49     // Hitachi H8/500
#define EM_IA_64        50     // Intel Merced
#define EM_MIPS_X       51     // Stanford MIPS-X
#define EM_COLDFIRE     52     // Motorola Coldfire
#define EM_68HC12       53     // Motorola M68HC12
#define EM_MMA          54     // Fujitsu MMA Multimedia Accelerator
#define EM_PCP          55     // Siemens PCP
#define EM_NCPU         56     // Sony nCPU embeeded RISC
#define EM_NDR1         57     // Denso NDR1 microprocessor
#define EM_STARCORE     58     // Motorola Start*Core processor
#define EM_ME16         59     // Toyota ME16 processor
#define EM_ST100        60     // STMicroelectronic ST100 processor
#define EM_TINYJ        61     // Advanced Logic Corp. Tinyj emb.fam
#define EM_X86_64       62     // AMD x86-64 architecture
#define EM_PDSP         63     // Sony DSP Processor
#define EM_FX66         66     // Siemens FX66 microcontroller
#define EM_ST9PLUS      67     // STMicroelectronics ST9+ 8/16 mc
#define EM_ST7          68     // STmicroelectronics ST7 8 bit mc
#define EM_68HC16       69     // Motorola MC68HC16 microcontroller
#define EM_68HC11       70     // Motorola MC68HC11 microcontroller
#define EM_68HC08       71     // Motorola MC68HC08 microcontroller
#define EM_68HC05       72     // Motorola MC68HC05 microcontroller
#define EM_SVX          73     // Silicon Graphics SVx
#define EM_AT19         74     // STMicroelectronics ST19 8 bit mc
#define EM_VAX          75     // Digital VAX
#define EM_CRIS         76     // Axis Communications 32-bit embedded processor
#define EM_JAVELIN      77     // Infineon Technologies 32-bit embedded processor
#define EM_FIREPATH     78     // Element 14 64-bit DSP Processor
#define EM_ZSP          79     // LSI Logic 16-bit DSP Processor
#define EM_MMIX         80     // Donald Knuth's educational 64-bit processor
#define EM_HUANY        81     // Harvard University machine-independent object files
#define EM_PRISM        82     // SiTera Prism
#define EM_AVR          83     // Atmel AVR 8-bit microcontroller
#define EM_FR30         84     // Fujitsu FR30
#define EM_D10V         85     // Mitsubishi D10V
#define EM_D30V         86     // Mitsubishi D30V
#define EM_V850         87     // NEC v850
#define EM_M32R         88     // Mitsubishi M32R
#define EM_MN10300      89     // Matsushita MN10300
#define EM_MN10200      90     // Matsushita MN10200
#define EM_PJ           91     // picoJava
#define EM_OPENRISC     92     // OpenRISC 32-bit embedded processor
#define EM_RISCV        243    // RISC-V
#define EM_OR32         0x8472 // Open RISC
#define EM_ALPHA        0x9026 // Digital Alpha
#define EM_FORWARDCOM   0x6233 // ForwardCom preliminary value (constructed from F=6, W=23, C=3)

// Legal values for e_version (version).
#define EV_NONE          0    // Invalid ELF version
#define EV_CURRENT       1    // Current version
#define EV_NUM           2

// Section header.
struct Elf64_Shdr {
  uint32_t  sh_name;      // Section name (string table index)
  uint32_t  sh_type;      // Section type
  uint64_t  sh_flags;     // Section flags
  uint64_t  sh_addr;      // Section virtual addr at execution
  uint64_t  sh_offset;    // Section file offset
  uint64_t  sh_size;      // Section size in bytes
  uint32_t  sh_link;      // Link to another section
  uint32_t  sh_info;      // Additional section information
  uint64_t  sh_addralign; // Section alignment
  uint64_t  sh_entsize;   // Entry size if section holds table
};


// Special section indices
#define SHN_UNDEF                     0  // Undefined section
#define SHN_LORESERVE  ((int16_t)0xff00) // Start of reserved indices
#define SHN_LOPROC     ((int16_t)0xff00) // Start of processor-specific
#define SHN_HIPROC     ((int16_t)0xff1f) // End of processor-specific
#define SHN_LOOS       ((int16_t)0xff20) // Start of OS-specific
#define SHN_HIOS       ((int16_t)0xff3f) // End of OS-specific
#define SHN_ABS        ((int16_t)0xfff1) // Associated symbol is absolute
#define SHN_COMMON     ((int16_t)0xfff2) // Associated symbol is common
#define SHN_XINDEX     ((int16_t)0xffff) // Index is in extra table
#define SHN_HIRESERVE  ((int16_t)0xffff) // End of reserved indices

// Legal values for sh_type (section type).
#define SHT_NULL                    0  // Section header table entry unused
#define SHT_PROGBITS                1  // Program data
#define SHT_SYMTAB                  2  // Symbol table
#define SHT_STRTAB                  3  // String table
#define SHT_RELA                    4  // Relocation entries with addends
#define SHT_HASH                    5  // Symbol hash table
#define SHT_DYNAMIC                 6  // Dynamic linking information
#define SHT_NOTE                    7  // Notes
#define SHT_NOBITS                  8  // Program space with no data (bss)
#define SHT_REL                     9  // Relocation entries, no addends
#define SHT_SHLIB                  10  // Reserved
#define SHT_DYNSYM                 11  // Dynamic linker symbol table
#define SHT_INIT_ARRAY             14  // Array of constructors
#define SHT_FINI_ARRAY             15  // Array of destructors
#define SHT_PREINIT_ARRAY          16  // Array of pre-constructors
#define SHT_GROUP                  17  // Section group
#define SHT_SYMTAB_SHNDX           18  // Extended section indeces
#define SHT_NUM                    19  // Number of defined types. 
#define SHT_LOOS           0x60000000  // Start OS-specific
#define SHT_STACKSIZE      0x60000001  // Records for calculation of stack size
#define SHT_ACCESSRIGHTS   0x60000002  // Records for indicating desired access rights of executable file or device driver
#define SHT_HIOS           0x6fffffff  // End OS-specific type
#define SHT_LOPROC         0x70000000  // Start of processor-specific
#define SHT_HIPROC         0x7fffffff  // End of processor-specific
#define SHT_LOUSER         0x80000000  // Start of application-specific
#define SHT_HIUSER         0x8fffffff  // End of application-specific


// Legal values for sh_flags (section flags). 
#define SHF_WRITE            (1 << 0)  // Writable
#define SHF_ALLOC            (1 << 1)  // Occupies memory during execution
#define SHF_EXECINSTR        (1 << 2)  // Executable
#define SHF_READ             (1 << 3)  // Readable (added for ForwardCom)
#define SHF_MERGE            (1 << 4)  // Might be merged
#define SHF_STRINGS          (1 << 5)  // Contains nul-terminated strings
#define SHF_INFO_LINK        (1 << 6)  // `sh_info' contains SHT index
#define SHF_LINK_ORDER       (1 << 7)  // Preserve order after combining
#define SHF_OS_NONCONFORMING (1 << 8)  // Non-standard OS specific handling required
#define SHF_MASKOS         0x0ff00000  // OS-specific. 
#define SHF_MASKPROC       0xf0000000  // Processor-specific

// Section group handling.
#define GRP_COMDAT  0x1    // Mark group as COMDAT.

// Symbol table entry.
/*
struct Elf32_Sym {
  uint32_t  st_name;       // Symbol name (string tbl index)
  uint32_t  st_value;      // Symbol value
  uint32_t  st_size;       // Symbol size
  uint8_t   st_type: 4,    // Symbol type
            st_bind: 4;    // Symbol binding
  uint8_t   st_other;      // Symbol visibility
  uint16_t  st_shndx;      // Section index
};*/

struct Elf64_Symb {
  uint32_t  st_name;       // Symbol name (string table index)
  uint16_t  st_type;       // Symbol type
  uint16_t  st_bind;       // Symbol binding
  uint32_t  st_other;      // Symbol visibility
  uint32_t  st_shndx;      // Section index
  uint64_t  st_value;      // Symbol value
  uint64_t  st_size;       // Symbol size
  uint64_t  st_reg_use;    // Register use. bit 0-31 = r0-r31, bit 32-63 = v0-v31
//uint64_t  st_reg_use2;   // Reserved for future use
};

/* Special section index.  */

#define SHN_UNDEF  0    /* No section, undefined symbol.  */


// Values for st_bind: symbol binding
#define STB_LOCAL    0    // Local symbol
#define STB_GLOBAL   1    // Global symbol
#define STB_WEAK     2    // Weak symbol
#define STB_NUM      3    // Number of defined types. 
#define STB_LOOS    10    // Start of OS-specific
#define STB_HIOS    12    // End of OS-specific
#define STB_LOPROC  13    // Start of processor-specific
#define STB_HIPROC  15    // End of processor-specific

// Values for st_type: symbol type
#define STT_NOTYPE   0    // Symbol type is unspecified
#define STT_OBJECT   1    // Symbol is a data object
#define STT_FUNC     2    // Symbol is a code object
#define STT_SECTION  3    // Symbol associated with a section
#define STT_FILE     4    // Symbol's name is file name
#define STT_COMMON   5    // Symbol is a common data object
#define STT_NUM      6    // Number of defined types. 
#define STT_LOOS    10    // Start of OS-specific
#define STT_FORWC_DISPATCH 10  // Symbol is a dispatcher function for load-time function dispatching
#define STT_HIOS    12    // End of OS-specific
#define STT_LOPROC  13    // Start of processor-specific
#define STT_HIPROC  15    // End of processor-specific

// Symbol visibility specification encoded in the st_other field. 
#define STV_DEFAULT    0       // Default symbol visibility rules
#define STV_INTERNAL   1       // Processor specific hidden class
#define STV_HIDDEN     2       // Symbol unavailable in other modules
#define STV_PROTECTED  3       // Not preemptible, not exported
// st_other types added for ForwardCom:
#define STV_MAIN       0x100   // Main entry point in executable file
#define STV_EXPORTED   0x200   // Exported from executable file
#define STV_THREAD     0x400   // Thread function. Requires own stack

/*
// Relocation table entry without addend (in section of type SHT_REL. Unused)
struct Elf64_Rel {
  uint64_t  r_offset;             // Address
  uint32_t  r_type;               // Relocation type
  uint32_t  r_sym;                // Symbol index
};*/

// Relocation table entry with addend (in section of type SHT_RELA)
struct Elf64_Rela {
  uint64_t  r_offset;               // Address
  uint32_t  r_type;                 // Relocation type
  uint32_t  r_sym;                  // Symbol index
  int64_t   r_addend;               // Addend
};

// ForwardCom relocation types are composed of these three fields:
// Relocation type in bit 16-31
// Size in bit 8-15
// Scale factor in bit 0-7.
// Other combinations than the ones named below may be supported.
// Divide the relative address by the scale factor - it will be multiplied by the same factor 
// by the instruction. All relative addresses are signed.
// Instructions with self-relative (IP-relative) addressing are using the END of the instruction 
// as reference point. The r_addend field in Elf64_Rela must compensate for the distance between 
// the end of the instruction and the beginning of the address field. This will be -7 for 
// instructions with format 2.7.3 and -4 for all other jump and call instructions. Any
// offset of the target may be added to r_addend.
// Relocations relative to an arbitrary reference point can be used in jump tables.
// The reference point is indicated by a symbol index in the high 32 bits of r_addend.
// Only the low 32 bits of r_addend are used as addend in this case.
// The system function ID relocations are done by the loader, where r_sym indicates the name
// of the function in the string table, and r_addend indicates the name of the module or
// device driver.
#define R_FORW_NONE             0x000000    // No relocation
#define R_FORW_ABS_16           0x000200    // Absolute address, 16 bit
#define R_FORW_ABS_32           0x000400    // Absolute address, 32 bit
#define R_FORW_ABS_64           0x000600    // Absolute address, 64 bit
#define R_FORW_ABS_64LO         0x000700    // Absolute address, low  32 of 64 bits
#define R_FORW_ABS_64HI         0x000800    // Absolute address, high 32 of 64 bits
#define R_FORW_IP_8             0x010100    // Self-relative, 8 bit
#define R_FORW_IP_8_S4          0x010102    // Self-relative, 8 bit, scale by 4
#define R_FORW_IP_16            0x010200    // Self-relative, 16 bit
#define R_FORW_IP_16_S4         0x010202    // Self-relative, 16 bit, scale by 4
#define R_FORW_IP_24            0x010300    // Self-relative, 24 bit
#define R_FORW_IP_24_S4         0x010302    // Self-relative, 24 bit, scale by 4
#define R_FORW_IP_32            0x010400    // Self-relative, 32 bit
#define R_FORW_IP_32_S4         0x010402    // Self-relative, 32 bit, scale by 4
#define R_FORW_CONST_8          0x040100    // Relative to CONST section begin, 8 bit
#define R_FORW_CONST_16         0x040200    // Relative to CONST section begin, 16 bit
#define R_FORW_CONST_32         0x040400    // Relative to CONST section begin, 32 bit
#define R_FORW_BSS_8            0x050100    // Relative to BSS section begin / DATA section end, 8 bit
#define R_FORW_BSS_16           0x050200    // Relative to BSS section begin / DATA section end, 16 bit
#define R_FORW_BSS_32           0x050400    // Relative to BSS section begin / DATA section end, 32 bit
#define R_FORW_REFP_8           0x080100    // Relative to arbitrary reference point, 8 bit. Reference symbol index in high 32 bits of r_addend
#define R_FORW_REFP_8_S2        0x080101    // Relative to arbitrary reference point, 8 bit, scale by  2.
#define R_FORW_REFP_8_S4        0x080102    // Relative to arbitrary reference point, 8 bit, scale by  4.
#define R_FORW_REFP_8_S8        0x080103    // Relative to arbitrary reference point, 8 bit, scale by  8.
#define R_FORW_REFP_8_S16       0x080104    // Relative to arbitrary reference point, 8 bit, scale by 16.
#define R_FORW_REFP_16          0x080200    // Relative to arbitrary reference point, 16 bit.
#define R_FORW_REFP_16_S4       0x080202    // Relative to arbitrary reference point, 16 bit, scale by  4.
#define R_FORW_REFP_24          0x080300    // Relative to arbitrary reference point, 24 bit.
#define R_FORW_REFP_24_S4       0x080302    // Relative to arbitrary reference point, 24 bit, scale by  4.
#define R_FORW_REFP_32          0x080400    // Relative to arbitrary reference point, 32 bit.
#define R_FORW_REFP_32_S4       0x080402    // Relative to arbitrary reference point, 32 bit, scale by  4.
#define R_FORW_REFP_64          0x080600    // Relative to arbitrary reference point, 64 bit.
#define R_FORW_REFP_64_S4       0x080602    // Relative to arbitrary reference point, 64 bit, scale by  4.
#define R_FORW_REFP_64LO        0x080700    // Relative to arbitrary reference point, low  32 of 64 bits.
#define R_FORW_REFP_64HI        0x080800    // Relative to arbitrary reference point, high 32 of 64 bits.
#define R_FORW_SYSFUNC_16       0x100200    // System function ID for system_call, 16 bit
#define R_FORW_SYSFUNC_32       0x100400    // System function ID for system_call, 32 bit 
#define R_FORW_SYSMODUL_16      0x110200    // System module ID for system_call, 16 bit
#define R_FORW_SYSMODUL_32      0x110400    // System module ID for system_call, 32 bit
#define R_FORW_SYSCALL_32       0x120400    // System module and function ID for system_call, 16+16=32 bit
#define R_FORW_SYSCALL_64       0x120600    // System module and function ID for system_call, 32+32=64 bit
#define R_FORW_DATASTACK_32     0x200200    // Calculated size of data stack for function, 32 bit. Resolved at load time
#define R_FORW_DATASTACK_32_S8  0x200203    // Calculated size of data stack for function, 32 bit, scale by 8. Resolved at load time
#define R_FORW_DATASTACK_64     0x200400    // Calculated size of data stack for function, 64 bit. Resolved at load time
#define R_FORW_DATASTACK_64_S8  0x200403    // Calculated size of data stack for function, 64 bit, scale by 8. Resolved at load time
#define R_FORW_CALLSTACK_32     0x210200    // Calculated size of call stack for function, 32 bit. Resolved at load time
#define R_FORW_CALLSTACK_32_S8  0x210203    // Calculated size of call stack for function, 32 bit, scale by 8. Resolved at load time
#define R_FORW_REGUSE_64        0x400600    // Register use of function, 64 bit
#define R_FORW_REGUSE_64LO      0x400700    // Register use of function, low  32 of 64 bits = general purpose registers
#define R_FORW_REGUSE_64HI      0x400800    // Register use of function, high 32 of 64 bits = vector registers

/*
// i386 Relocation types
#define R_386_NONE      0    // No reloc
#define R_386_32        1    // Direct 32 bit
#define R_386_PC32      2    // Self-relative 32 bit (not EIP relative in the sense used in COFF files)
#define R_386_GOT32     3    // 32 bit GOT entry
#define R_386_PLT32     4    // 32 bit PLT address
#define R_386_COPY      5    // Copy symbol at runtime
#define R_386_GLOB_DAT  6    // Create GOT entry
#define R_386_JMP_SLOT  7    // Create PLT entry
#define R_386_RELATIVE  8    // Adjust by program base
#define R_386_GOTOFF    9    // 32 bit offset to GOT 
#define R_386_GOTPC    10    // 32 bit self relative offset to GOT
#define R_386_IRELATIVE 42   // Reference to PLT entry of indirect function (STT_GNU_IFUNC)

// AMD x86-64 relocation types
#define R_X86_64_NONE       0  // No reloc
#define R_X86_64_64         1  // Direct 64 bit 
#define R_X86_64_PC32       2  // Self relative 32 bit signed (not RIP relative in the sense used in COFF files)
#define R_X86_64_GOT32      3  // 32 bit GOT entry
#define R_X86_64_PLT32      4  // 32 bit PLT address
#define R_X86_64_COPY       5  // Copy symbol at runtime
#define R_X86_64_GLOB_DAT   6  // Create GOT entry
#define R_X86_64_JUMP_SLOT  7  // Create PLT entry
#define R_X86_64_RELATIVE   8  // Adjust by program base
#define R_X86_64_GOTPCREL   9  // 32 bit signed self relative offset to GOT
#define R_X86_64_32        10  // Direct 32 bit zero extended
#define R_X86_64_32S       11  // Direct 32 bit sign extended
#define R_X86_64_16        12  // Direct 16 bit zero extended
#define R_X86_64_PC16      13  // 16 bit sign extended self relative
#define R_X86_64_8         14  // Direct 8 bit sign extended
#define R_X86_64_PC8       15  // 8 bit sign extended self relative
#define R_X86_64_IRELATIVE 37  // Reference to PLT entry of indirect function (STT_GNU_IFUNC)
*/


// Program segment header.

struct Elf32_Phdr {
  uint32_t  p_type;      // Segment type
  uint32_t  p_offset;    // Segment file offset
  uint32_t  p_vaddr;     // Segment virtual address
  uint32_t  p_paddr;     // Segment physical address
  uint32_t  p_filesz;    // Segment size in file
  uint32_t  p_memsz;     // Segment size in memory
  uint32_t  p_flags;     // Segment flags
  uint32_t  p_align;     // Segment alignment
};

struct Elf64_Phdr {
  uint32_t  p_type;      // Segment type
  uint32_t  p_flags;     // Segment flags
  uint64_t  p_offset;    // Segment file offset
  uint64_t  p_vaddr;     // Segment virtual address
  uint64_t  p_paddr;     // Segment physical address
  uint64_t  p_filesz;    // Segment size in file
  uint64_t  p_memsz;     // Segment size in memory
  uint64_t  p_align;     // Segment alignment
};

// Legal values for p_type (segment type). 

#define PT_NULL             0    // Program header table entry unused
#define PT_LOAD             1    // Loadable program segment
#define PT_DYNAMIC          2    // Dynamic linking information
#define PT_INTERP           3    // Program interpreter
#define PT_NOTE             4    // Auxiliary information
#define PT_SHLIB            5    // Reserved
#define PT_PHDR             6    // Entry for header table itself
#define PT_NUM              7    // Number of defined types
#define PT_LOOS    0x60000000    // Start of OS-specific
#define PT_HIOS    0x6fffffff    // End of OS-specific
#define PT_LOPROC  0x70000000    // Start of processor-specific
#define PT_HIPROC  0x7fffffff    // End of processor-specific

// Legal values for p_flags (segment flags). 

#define PF_X           (1 << 0)  // Segment is executable
#define PF_W           (1 << 1)  // Segment is writable
#define PF_R           (1 << 2)  // Segment is readable
#define PF_MASKOS    0x0ff00000  // OS-specific
#define PF_MASKPROC  0xf0000000  // Processor-specific

// Legal values for note segment descriptor types for core files.

#define NT_PRSTATUS    1    // Contains copy of prstatus struct
#define NT_FPREGSET    2    // Contains copy of fpregset struct
#define NT_PRPSINFO    3    // Contains copy of prpsinfo struct
#define NT_PRXREG      4    // Contains copy of prxregset struct
#define NT_PLATFORM    5    // String from sysinfo(SI_PLATFORM)
#define NT_AUXV        6    // Contains copy of auxv array
#define NT_GWINDOWS    7    // Contains copy of gwindows struct
#define NT_PSTATUS    10    // Contains copy of pstatus struct
#define NT_PSINFO     13    // Contains copy of psinfo struct
#define NT_PRCRED     14    // Contains copy of prcred struct
#define NT_UTSNAME    15    // Contains copy of utsname struct
#define NT_LWPSTATUS  16    // Contains copy of lwpstatus struct
#define NT_LWPSINFO   17    // Contains copy of lwpinfo struct
#define NT_PRFPXREG   20    // Contains copy of fprxregset struct*/

// Legal values for the note segment descriptor types for object files.
#define NT_VERSION  1       // Contains a version string.



// Note section contents.  Each entry in the note section begins with a header of a fixed form.

struct Elf64_Nhdr {
  uint32_t n_namesz;      /* Length of the note's name.  */
  uint32_t n_descsz;      /* Length of the note's descriptor.  */
  uint32_t n_type;        /* Type of the note.  */
};

/* Defined note types for GNU systems.  */

/* ABI information.  The descriptor consists of words:
   word 0: OS descriptor
   word 1: major version of the ABI
   word 2: minor version of the ABI
   word 3: subminor version of the ABI
*/
#define ELF_NOTE_ABI    1

/* Known OSes.  These value can appear in word 0 of an ELF_NOTE_ABI
   note section entry.  */
#define ELF_NOTE_OS_LINUX     0
#define ELF_NOTE_OS_GNU       1
#define ELF_NOTE_OS_SOLARIS2  2


/* Move records.  */
struct Elf32_Move {
  uint64_t m_value;      /* Symbol value.  */
  uint32_t m_info;       /* Size and index.  */
  uint32_t m_poffset;    /* Symbol offset.  */
  uint16_t m_repeat;     /* Repeat count.  */
  uint16_t m_stride;     /* Stride info.  */
};

struct Elf64_Move {
  uint64_t m_value;     /* Symbol value.  */
  uint64_t m_info;      /* Size and index.  */
  uint64_t m_poffset;   /* Symbol offset.  */
  uint16_t m_repeat;    /* Repeat count.  */
  uint16_t m_stride;    /* Stride info.  */
};

/* Macro to construct move records.  */
#define ELF32_M_SYM(info)        ((info) >> 8)
#define ELF32_M_SIZE(info)       ((uint8_t) (info))
#define ELF32_M_INFO(sym, size)  (((sym) << 8) + (uint8_t) (size))

#define ELF64_M_SYM(info)        ELF32_M_SYM (info)
#define ELF64_M_SIZE(info)       ELF32_M_SIZE (info)
#define ELF64_M_INFO(sym, size)  ELF32_M_INFO (sym, size)


/********************** Strings **********************/
//#define ELF_CONSTRUCTOR_NAME    ".ctors"   // Name of constructors segment


// SHT_STACKSIZE stack table entry
struct Elf64_Stacksize {
  uint32_t  ss_syma;                   // Public symbol index
  uint32_t  ss_symb;                   // External symbol index. Zero for frame function or to indicate own stack use
  uint64_t  ss_framesize;              // Size of data stack frame in syma when calling symb
  uint32_t  ss_numvectors;             // Additional data stack frame size for vectors. Multiply by maximum vector length
  uint32_t  ss_calls;                  // Size of call stack when syma calls symb (typically 1). Multiply by stack word size = 8
};


#endif // ELF_FORW_H
