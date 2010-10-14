

import struct
import sys

"""
Name       Size Alignment Purpose
Elf32_Addr    4    4      Unsigned program address
Elf32_Half    2    2      Unsigned medium integer
Elf32_Off     4    4      Unsigned file offset
Elf32_Sword   4    4      Signed large integer
Elf32_Word    4    4      Unsigned large integer
unsigned char 1    1      Unsigned small integer

Elf64_Addr    8    8      Unsigned program address
Elf64_Off     8    8      Unsigned file offset
Elf64_Half    2    2      Unsigned medium integer
Elf64_Word    4    4      Unsigned integer
Elf64_Sword   4    4      Signed integer
Elf64_Xword   8    8      Unsigned long integer
Elf64_Sxword  8    8      Signed long integer
unsigned char 1    1      Unsigned small integer

#define EI_NIDENT 16
typedef struct {
  unsigned char e_ident[EI_NIDENT];     16  16B
  Elf32_Half e_type;                    18    H
  Elf32_Half e_machine;                 20    H
  Elf32_Word e_version;                 24    I
  Elf32_Addr e_entry;                   28    I
  Elf32_Off e_phoff;                    32    I
  Elf32_Off e_shoff;                    36    I
  Elf32_Word e_flags;                   40    I
  Elf32_Half e_ehsize;                  42    H
  Elf32_Half e_phentsize;               44    H
  Elf32_Half e_phnum;                   46    H
  Elf32_Half e_shentsize;               48    H
  Elf32_Half e_shnum;                   50    H
  Elf32_Half e_shstrndx;                52    H
} Elf32_Ehdr;
typedef struct {
  unsigned char   e_ident[EI_NIDENT];
  Elf64_Half      e_type;        2  H
  Elf64_Half      e_machine;     2  H
  Elf64_Word      e_version;     4  I
  Elf64_Addr      e_entry;       8  Q
  Elf64_Off       e_phoff;       8  Q
  Elf64_Off       e_shoff;       8  Q
  Elf64_Word      e_flags;       4  I
  Elf64_Half      e_ehsize;      2  H
  Elf64_Half      e_phentsize;   2  H
  Elf64_Half      e_phnum;       2  H
  Elf64_Half      e_shentsize;   2  H
  Elf64_Half      e_shnum;       2  H
  Elf64_Half      e_shtrndx;     2  H
} Elf64_Ehdr;

"""
class ELF:
  def __init__(self,filename='a.out'):
    pass


"""
e_ident[]
Name Value Purpose
EI_MAG0       0 File identification
EI_MAG1       1 File identification
EI_MAG2       2 File identification
EI_MAG3       3 File identification
EI_CLASS      4 File class
EI_DATA       5 Data encoding
EI_VERSION    6 File version
EI_OSABI      7 Operating system/ABI identification
EI_ABIVERSION 8 ABI version
EI_PAD        9 Start of padding bytes 
EI_NIDENT 16 Size of e_ident[]
"""
"""
Name        Value   Meaning
ELFCLASSNONE  0   Invalid class
ELFCLASS32    1   32-bit objects
ELFCLASS64    2   64-bit objects
"""
"""
Name        Value Meaning
ELFDATANONE   0   Invalid data encoding
ELFDATA2LSB   1   
ELFDATA2MSB   2
"""
filename = 'a.out'
elf_class = None
end_char = None
shidx_strtab = None
def readElfHeader(f):
  global elf_class
  global end_char
  fmt_ident = '16s'
  fmt32 = 'HHIIIIIHHHHHH'
  fmt64 = 'HHIQQQIHHHHHH'
  fields = ['e_ident', 'e_type', 'e_machine', 'e_version', 'e_entry',
    'e_phoff', 'e_shoff', 'e_flags', 'e_ehsize', 'e_phentsize',
    'e_phnum', 'e_shentsize', 'e_shnum', 'e_shstrndx']
  f.seek(0)
  ident_data = f.read(struct.calcsize(fmt_ident))
  fmt = None
  if ord(ident_data[4]) == 1:
    elf_class = 32
    fmt = fmt32
    data = f.read(struct.calcsize(fmt32))
  elif ord(ident_data[4]) == 2:
    elf_class = 64
    fmt = fmt64
    data = f.read(struct.calcsize(fmt64))
  if ord(ident_data[5]) == 1: #little-endian
    fmt = '<' + fmt_ident + fmt
    end_char = '<'
  elif ord(ident_data[5]) == 2: #big-endian
    fmt = '>' + fmt_ident + fmt
    end_char = '>'
  return dict(zip(fields,struct.unpack(fmt,ident_data+data)))



"""
typedef struct {
  Elf32_Word      sh_name;        I
  Elf32_Word      sh_type;        I
  Elf32_Word      sh_flags;       I
  Elf32_Addr      sh_addr;        I
  Elf32_Off       sh_offset;      I
  Elf32_Word      sh_size;        I
  Elf32_Word      sh_link;        I
  Elf32_Word      sh_info;        I
  Elf32_Word      sh_addralign;   I
  Elf32_Word      sh_entsize;     I
} Elf32_Shdr;
typedef struct {
  Elf64_Word      sh_name;        I
  Elf64_Word      sh_type;        I
  Elf64_Xword     sh_flags;       Q
  Elf64_Addr      sh_addr;        Q
  Elf64_Off       sh_offset;      Q
  Elf64_Xword     sh_size;        Q
  Elf64_Word      sh_link;        I
  Elf64_Word      sh_info;        I
  Elf64_Xword     sh_addralign;   Q
  Elf64_Xword     sh_entsize;     Q
} Elf64_Shdr;

"""
def readShHeaders(f,elf_hdr):
  fmt = '@IIIIIIIIII'
  fmt32 = 'IIIIIIIIII'
  fmt64 = 'IIQQQQIIQQ'
  fields = ['sh_name_idx', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset', 
    'sh_size', 'sh_link', 'sh_info', 'sh_addralign', 'sh_entsize' ]
  sh_hdrs = []
  f.seek(elf_hdr['e_shoff'])
  for shentid in range(elf_hdr['e_shnum']):
    data = f.read(elf_hdr['e_shentsize'])
    sh_hdrs.append(dict(zip(fields,struct.unpack(fmt,data))))
  shstrndx_hdr = sh_hdrs[elf_hdr['e_shstrndx']]
  f.seek(shstrndx_hdr['sh_offset'])
  shstr = f.read(shstrndx_hdr['sh_size'])
  idx = 0
  for hdr in sh_hdrs:
    offset = hdr['sh_name_idx']
    hdr['sh_name'] = shstr[offset:offset+shstr[offset:].index(chr(0x0))]
    global shidx_strtab
    if '.strtab' == hdr['sh_name']:
      shidx_strtab = idx
    idx += 1
  return sh_hdrs




"""
typedef struct {
  Elf32_Word p_type;
  Elf32_Off  p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
} Elf32_Phdr;
typedef struct {
  Elf64_Word      p_type;    I
  Elf64_Word      p_flags;   I
  Elf64_Off       p_offset;  Q
  Elf64_Addr      p_vaddr;   Q
  Elf64_Addr      p_paddr;   Q
  Elf64_Xword     p_filesz;  Q
  Elf64_Xword     p_memsz;   Q
  Elf64_Xword     p_align;   Q
} Elf64_Phdr;

"""
def readPhHeaders(f,elf_header):
  fmt = '@IIIIIIII'
  fmt32 = 'IIIIIIII' 
  fmt64 = 'IIQQQQQQ'
  fields =['p_type', 'p_offset', 'p_vaddr', 'p_paddr', 'p_filesz', 'p_memsz',
           'p_flags', 'p_align']
  ph_headers = []
  f.seek(elf_header['e_phoff'])
  for shentid in range(elf_header['e_phnum']):
    data = f.read(elf_header['e_phentsize'])
    ph_headers.append(dict(zip(fields,struct.unpack(fmt,data))))
  return ph_headers



"""
typedef struct {
  Elf32_Word      st_name;
  Elf32_Addr      st_value;
  Elf32_Word      st_size;
  unsigned char   st_info;
  unsigned char   st_other;
  Elf32_Half      st_shndx;
} Elf32_Sym;

typedef struct {
  Elf64_Word      st_name;
  unsigned char   st_info;
  unsigned char   st_other;
  Elf64_Half      st_shndx;
  Elf64_Addr      st_value;
  Elf64_Xword     st_size;
} Elf64_Sym;
"""

#ident = {0:'EI_MAG0',1:'EI_MAG1',2:'EI_MAG2',3:'EI_MAG3',4:'EI_CLASS',5:'EI_DATA',6:'EI_VERSION',7:'EI_PAD',16:'EI_NIDENT'}

def isElfFile(ident):
    if ident[:4] == '\x7fELF':
        return True
    return False

def printReadElfHeader(elf_header):
  print "ELF Header:"
  print "  ELF Magic: ",
  for x in elf_header['e_ident']:
    print "%02X" % ord(x),
  print ' '
  print "  ELF Class:\t\t\t\t%s" % {0:'Invalid class',1:'ELF32',2:'ELF64'}[ord(elf_header['e_ident'][4])] 
  print "  Data:\t\t\t\t\t%s" % {0:'Invaild data encoding',1:"2's complement, little endian",2:"2's complement, big endian"}[ord(elf_header['e_ident'][5])]
  print "  Version:\t\t\t\t%s" % {0:'Invaild version',1:'1 (current)'}[ord(elf_header['e_ident'][6])]
  print "  OS/ABI:\t\t\t\t%s" % {0:'UNIX - System V',1:'HPUX',255:'Standalone'}[ord(elf_header['e_ident'][7])]
  print "  ABI Version:\t\t\t\t%d" % ord(elf_header['e_ident'][8])
  print "  Type:\t\t\t\t\t%s" % {0:'No file type',1:'Relocatable',2:'Executable',3:'Shared object',4:'Core',
                        0xfe00:'OS specific',0xfeff:'OS specific',
                        0xff00:'Processor specific',0xffff:'Processor specific'}[elf_header['e_type']]
  print "  Machine:\t\t\t\t%s" % {0:'No machine', 1:'AT&T WE32100', 2:'Sparc', 3:'Intel 80386', 4:'Moto 68K',
                         5:'Moto 88K', 7:'Intel 80860', 8:'', 10:'',40:'ARM'}[elf_header['e_machine']] 
  print "  Version:\t\t\t\t0x%x" % elf_header['e_version'] 
  print "  Entry point address:\t\t\t0x%08x" % elf_header['e_entry']
  print "  Start of program headers:\t\t%d(bytes offset of this file)" % elf_header['e_phoff']
  print "  Start of section headers:\t\t%d(bytes offset of this file)" % elf_header['e_shoff']
  print "  Flags:\t\t\t\t0x%x" % elf_header['e_flags']
  print "  Size of this header:\t\t\t%d(bytes)" % elf_header['e_ehsize']
  print "  Size of program headers:\t\t%d(bytes)" % elf_header['e_phentsize']
  print "  Number of program headers:\t\t%d" % elf_header['e_phnum']
  print "  Size of section headers:\t\t%d(bytes)" % elf_header['e_shentsize']
  print "  Number of section headers:\t\t%d" % elf_header['e_shnum']
  print "  Section header string table index:\t%d" % elf_header['e_shstrndx'] 

def printElfHeader(elf_hdr):
  print "ELF Header:"
  print "  ELF identification[16]: ",
  for x in elf_hdr['e_ident']:
    print "%02X" % ord(x),
  print ' '
  print "    ELF Class       [4]:\t\t%s" % {0:'Invalid class',1:'ELF32',2:'ELF64'}[ord(elf_hdr['e_ident'][4])] 
  print "    Data            [5]:\t\t%s" % {0:'Invaild data encoding',1:"2's complement, little endian",2:"2's complement, big endian"}[ord(elf_hdr['e_ident'][5])]
  print "    Version         [6]:\t\t%s" % {0:'Invaild version',1:'1 (current)'}[ord(elf_hdr['e_ident'][6])]
  print "    OS/ABI          [7]:\t\t%s" % {0:'UNIX - System V',1:'HPUX',255:'Standalone'}[ord(elf_hdr['e_ident'][7])]
  print "    ABI Version     [8]:\t\t%d" % ord(elf_hdr['e_ident'][8])
  print "  Type:\t\t\t\t\t%s" % {0:'No file type',1:'Relocatable',2:'Executable',3:'Shared object',4:'Core',
                        0xfe00:'OS specific',0xfeff:'OS specific',
                        0xff00:'Processor specific',0xffff:'Processor specific'}[elf_hdr['e_type']]
  print "  Machine:\t\t\t\t%s" % {0:'No machine', 1:'AT&T WE32100', 2:'Sparc', 3:'Intel 80386', 4:'Moto 68K',
                         5:'Moto 88K', 7:'Intel 80860', 8:'', 10:'',40:'ARM'}[elf_hdr['e_machine']] 
  print "  Version:\t\t\t\t0x%x" % elf_hdr['e_version'] 
  print "  Entry point address:\t\t\t0x%08x" % elf_hdr['e_entry']
  print "  Start of program headers:\t\t%d (bytes offset of this file)" % elf_hdr['e_phoff']
  print "  Start of section headers:\t\t%d (bytes offset of this file)" % elf_hdr['e_shoff']
  print "  Flags:\t\t\t\t0x%x" % elf_hdr['e_flags']
  print "  Size of this header:\t\t\t%d (bytes)" % elf_hdr['e_ehsize']
  print "  Size of program headers:\t\t%d (bytes)" % elf_hdr['e_phentsize']
  print "  Number of program headers:\t\t%d" % elf_hdr['e_phnum']
  print "  Size of section headers:\t\t%d (bytes)" % elf_hdr['e_shentsize']
  print "  Number of section headers:\t\t%d" % elf_hdr['e_shnum']
  print "  Section header string table index:\t%d" % elf_hdr['e_shstrndx']

"""
e_type
Name Value Meaning
ET_NONE   0   No file type
ET_REL    1   Relocatable file
ET_EXEC   2   Executable file
ET_DYN    3   Shared object file
ET_CORE   4   Core file
ET_LOPROC 0xff00 Processor-specific
ET_HIPROC 0xffff Processor-specific
"""

"""
Name  Value   Meaning
EM_NONE          0   No machine
EM_M32           1   AT&T WE 32100
EM_SPARC         2   SPARC
EM_386           3   Intel 80386
EM_68K           4   Motorola 68000
EM_88K           5   Motorola 88000
RESERVED         6   Reserved for future use
EM_860           7   Intel 80860
EM_MIPS          8   MIPS I Architecture
RESERVED         9   Reserved for future use
EM_MIPS_RS3_LE  10  MIPS RS3000 Little-endian
RESERVED        11-14   Reserved for future use
EM_PARISC       15  Hewlett-Packard PA-RISC
RESERVED        16  Reserved for future use
EM_VPP500       17  Fujitsu VPP500
EM_SPARC32PLUS  18  Enhanced instruction set SPARC
EM_960          19  Intel 80960
EM_PPC          20  Power PC
RESERVED        21-35   Reserved for future use
EM_V800         36  NEC V800
EM_FR20         37  Fujitsu FR20
EM_RH32         38  TRW RH-32
EM_RCE          39  Motorola RCE
EM_ARM          40  Advanced RISC Machines ARM
EM_ALPHA        41  Digital Alpha
EM_SH           42  Hitachi SH
EM_SPARCV9      43  SPARC Version 9
EM_TRICORE      44  Siemens Tricore embedded processor
EM_ARC          45  Argonaut RISC Core, Argonaut Technologies Inc.
EM_H8_300       46  Hitachi H8/300
EM_H8_300H      47  Hitachi H8/300H
EM_H8S          48  Hitachi H8S
EM_H8_500       49  Hitachi H8/500
EM_IA_64        50  Intel MercedTM Processor
EM_MIPS_X       51  Stanford MIPS-X
EM_COLDFIRE     52  Motorola Coldfire
EM_68HC12       53  Motorola M68HC12
"""

"""
e_version
Name Value Meaning
EV_NONE    0 Invalid versionn
EV_CURRENT 1 Current version

"""
def printShHeaders(f,elf_hdr,sh_hdrs):
  print "There are %d section headers, starting at offset 0x%x" % (len(sh_hdrs),elf_hdr['e_shoff']) 
  idx = 0
  print "[%2s] %-20s %-10s %-8s %-6s %-6s %-2s %3s %2s %3s %2s" %   (
         "Nr", "Name", "Type", "Addr", "Off", "Size", "ES", "Flg", "Lk", "Inf", "Al")
  for header in sh_hdrs:
    print "[%2d] %-20s %-10s %08X %06X %06X %02X %3s %2s %3s %2s" % ( idx,
       header['sh_name'], 
       {0:'NULL', 1:'PROGBITS', 2:'SYMTAB', 3:'STRTAB',
        4:'RELA', 5:'HASH', 6:'DYNAMIC', 7:'NOTE',
        8:'NOBITS', 9:'REL', 10:'SHLIB', 11:'DYNSYM',
        14:'INIT_ARRAY', 15:'FINI_ARRAY', 16:'PREINIT_ARRAY', 17:'GROUP', 18:'SYMTAB SECTION INDICIES', 
        0x60000000:'LOOS', 0x6ffffff5:'GNU_ATTRIBUTES', 0x6ffffff6:'GNU_HASH', 0x6ffffff7:'GNU_LIBLIST',  
        0x6ffffffd:'VERDEF', 0x6ffffffe:'VERNEED', 0x6fffffff:'VERSYM', 0x6ffffff0:'VERSYM', 
        0x7000000:'LOPROC', 0x7ffffffd:'AUXILIARY', 0x7ffffff:'FILTER',
        0x80000000:'LOUSER', 0xffffffff:'HIUSER'}[header['sh_type']], 
        header['sh_addr'],header['sh_offset'],header['sh_size'], 
        header['sh_entsize'],
        {0x0:' ', 0x1:'W',0x2:'A',0x1|0x2:'WA',0x2|0x4:'AX',0x30:'MS'}[header['sh_flags']],
        header['sh_link'], header['sh_info'],header['sh_addralign'])
    idx+=1
  print """Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), x (unknown)
O (extra OS processing required) o (OS specific), p (processor specific)
 """
"""
There are 30 section headers, starting at offset 0x1128:

Section Headers:
[Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
[ 0]                   NULL            00000000 000000 000000 00      0   0  0
[ 1] .interp           PROGBITS        08048134 000134 000013 00   A  0   0  1
[ 2] .note.ABI-tag     NOTE            08048148 000148 000020 00   A  0   0  4
[ 3] .note.gnu.build-i NOTE            08048168 000168 000024 00   A  0   0  4
[ 4] .hash             HASH            0804818c 00018c 000028 04   A  6   0  4
[ 5] .gnu.hash         GNU_HASH        080481b4 0001b4 000020 04   A  6   0  4
[ 6] .dynsym           DYNSYM          080481d4 0001d4 000050 10   A  7   1  4
[ 7] .dynstr           STRTAB          08048224 000224 00004a 00   A  0   0  1
[ 8] .gnu.version      VERSYM          0804826e 00026e 00000a 02   A  6   0  2
[ 9] .gnu.version_r    VERNEED         08048278 000278 000020 00   A  7   1  4
[10] .rel.dyn          REL             08048298 000298 000008 08   A  6   0  4
[11] .rel.plt          REL             080482a0 0002a0 000018 08   A  6  13  4
[12] .init             PROGBITS        080482b8 0002b8 000030 00  AX  0   0  4
[13] .plt              PROGBITS        080482e8 0002e8 000040 04  AX  0   0  4
[14] .text             PROGBITS        08048330 000330 00016c 00  AX  0   0 16
[15] .fini             PROGBITS        0804849c 00049c 00001c 00  AX  0   0  4
[16] .rodata           PROGBITS        080484b8 0004b8 000016 00   A  0   0  4
[17] .eh_frame         PROGBITS        080484d0 0004d0 000004 00   A  0   0  4
[18] .ctors            PROGBITS        08049f0c 000f0c 000008 00  WA  0   0  4
[19] .dtors            PROGBITS        08049f14 000f14 000008 00  WA  0   0  4
[20] .jcr              PROGBITS        08049f1c 000f1c 000004 00  WA  0   0  4
[21] .dynamic          DYNAMIC         08049f20 000f20 0000d0 08  WA  7   0  4
[22] .got              PROGBITS        08049ff0 000ff0 000004 04  WA  0   0  4
[23] .got.plt          PROGBITS        08049ff4 000ff4 000018 04  WA  0   0  4
[24] .data             PROGBITS        0804a00c 00100c 000008 00  WA  0   0  4
[25] .bss              NOBITS          0804a014 001014 000008 00  WA  0   0  4
[26] .comment          PROGBITS        00000000 001014 000023 01  MS  0   0  1
[27] .shstrtab         STRTAB          00000000 001037 0000ee 00      0   0  1
[28] .symtab           SYMTAB          00000000 0015d8 000410 10     29  45  4
[29] .strtab           STRTAB          00000000 0019e8 0001fb 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), x (unknown)
O (extra OS processing required) o (OS specific), p (processor specific)
"""

#def lookup_shstrndx(f,foffset,shstrndx,offset,shs):
  #f.seek(foffset)
  #shstr = f.read(shs[shstrndx]['sh_size'])
  #return shstr[offset:offset+shstr[offset:].index(chr(0x0))]
"""
typedef struct {
  Elf32_Word      st_name;  I
  Elf32_Addr      st_value; I
  Elf32_Word      st_size;  I
  unsigned char   st_info;  B
  unsigned char   st_other; B
  Elf32_Half      st_shndx; H
} Elf32_Sym;

typedef struct {
  Elf64_Word      st_name;  I
  unsigned char   st_info;  B
  unsigned char   st_other; B
  Elf64_Half      st_shndx; H
  Elf64_Addr      st_value; Q
  Elf64_Xword     st_size;  Q
} Elf64_Sym;
"""
def readsymtab(f,elf_hdr,sh_hdrs):
  #read .dynsym and .symtab
  fmt = None
  fmt32 = 'IIIBBH'
  fmt64 = 'IBBHQQ'
  fields = None
  fields32 = ['st_name_idx','st_value','st_size','st_info','st_other','st_shndx']
  fields64 = ['st_name_idx','st_info','st_other','st_shndx','st_value','st_size']
  if elf_class == 32:
    fmt = fmt32
    fields = fields32
  elif elf_class == 64:
    fmt = fmt64
    fields = fields64
  fmt = end_char + fmt
  strtab_hdr = sh_hdrs[shidx_strtab]
  f.seek(strtab_hdr['sh_offset'])
  strtab_str = f.read(strtab_hdr['sh_size'])
  symtabs = []
  for hdr in sh_hdrs:
    tab = []
    if 'sym' in hdr['sh_name']:
      f.seek(hdr['sh_offset'])
      tabsize = hdr['sh_size']
      while tabsize != 0:
        entsize = struct.calcsize(fmt)
        syment = dict(zip(fields,struct.unpack(fmt,f.read(entsize))))
        tab.append(syment)
        syment['st_bind'] = syment['st_info'] >> 4
        syment['st_type'] = syment['st_info'] & 0xf
        syment['st_vis'] = syment['st_other'] & 0x3
        offset = syment['st_name_idx']
        syment['st_name'] = strtab_str[offset:offset+strtab_str[offset:].index(chr(0x0))]
        tabsize -= entsize
      symtabs.append([hdr['sh_name'],tab])
  return symtabs

def printPhHeaders(ph_headers):
  pass

def printhelp(prog_name):
  print '%s' % prog_name

def printSymtabs(symtabs):
  for tab in symtabs:
    print "Symbol table '%s' contains %d entries:" % (tab[0],len(tab[1]))
    print "  %4s: %8s %4s %-8s %-8s %8s %3s %s" % (
    'Num', 'Value', 'Size', 'Type', 'Bind', 'Vis', 'Ndx', 'Name')
    idx = 0
    for sym in tab[1]:
      try:
        shndx = {0:'UND', 0xff00:'LOPROC', 0xff1f:'HIPROC', 0xfff1:'ABS', 0xfff2:'COM'}[sym['st_shndx']]
      except KeyError:
        shndx = str(sym['st_shndx'])
      print "  %4d: %08X %4d %-8s %-8s %8s %3s %s" % ( idx,
        sym['st_value'],
        sym['st_size'],
        {0:'NOTYPE',1:'OBJECT',2:'FUNC',3:'SECTION',4:'FILE',
         5:'COMMON', 6:'TLS',8:'RELC', 9:'SRELC',
         10:'LOOS',12:'HIOS',13:'LOPROC',15:'HIPROC'}[sym['st_type']],
        {0:'LOCAL',1:'GLOBAL',2:'WEAK',
        10:'LOOS',12:'HIOS',13:'LOPROC',15:'HIPROC'}[sym['st_bind']],
        {0:'DEFAULT', 1:'INTERNAL', 2:'HIDDEN', 3:'PROTECTED'}[sym['st_vis']],
        shndx,
        sym['st_name'])
      idx+=1
      

if __name__ == '__main__':
  #open_name = 'a.out'
  open_name = 'elf32.elf'
  
  if len(sys.argv) > 2:
    print_help(sys.argv[0])
  elif len(sys.argv) == 2:
    open_name = sys.argv[1]

  f = open(open_name,'rb')
  
  hdr = readElfHeader(f)
  
  printElfHeader(hdr)

  shs = readShHeaders(f,hdr)

  printShHeaders(f,hdr,shs)

  symtabs = readsymtab(f,hdr,shs)
  printSymtabs(symtabs)

