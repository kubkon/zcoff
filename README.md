# zcoff

Like `dumpbin.exe` but cross-platform.

## Usage

Available options:

```
> zcoff --help
zcoff [--help] [--headers] [--symbols] [--imports] [--relocations] [--out <OUT>] <FILE>
        --help
            Display this help and exit.

        --headers
            Print headers.

        --symbols
            Print symbol table.

        --imports
            Print import table.

        --relocations
            Print relocations.

        --out <OUT>
            Save to file.
```

### Examining COFF object files

```
> zcoff simple.obj --headers --symbols
No PE signature found

File type: COFF OBJECT

FILE HEADER VALUES
                8664 machine (X64)
                   8 number of sections
                   0 time date stamp
                1f66 file pointer to symbol table
                  15 number of symbols
                   0 size of optional header
                   0 characteristics


SECTION HEADER #0
               .text name
                   0 virtual size
                   0 virtual address
                  36 size of raw data
                 154 file pointer to raw data
                 18a file pointer to relocation table
                   0 file pointer to line numbers
                   1 number of relocations
                   0 number of line numbers
            60500020 flags
                       CNT_CODE
                       MEM_EXECUTE
                       MEM_READ
                       16 byte align

SECTION HEADER #1
               .data name
                   0 virtual size
                   0 virtual address
                   0 size of raw data
                 194 file pointer to raw data
                   0 file pointer to relocation table
                   0 file pointer to line numbers
                   0 number of relocations
                   0 number of line numbers
            c0300040 flags
                       CNT_INITIALIZED_DATA
                       MEM_READ
                       MEM_WRITE
                       4 byte align

...

More headers

...

COFF SYMBOL TABLE
000 00000000 SECT1     NULL   NULL     STATIC               | .text
     Section length   36, #relocs    1, #linenums    0, checksum 9cfaf420
002 00000000 SECT2     NULL   NULL     STATIC               | .data
     Section length    0, #relocs    0, #linenums    0, checksum        0
004 00000000 SECT3     NULL   NULL     STATIC               | .bss
     Section length    0, #relocs    0, #linenums    0, checksum        0
006 00000000 SECT4     NULL   NULL     STATIC               | .xdata
     Section length    c, #relocs    0, #linenums    0, checksum a1cf843c
008 00000000 SECT5     NULL   NULL     STATIC               | .debug$S
     Section length  1d8, #relocs    8, #linenums    0, checksum b097e5ef
010 00000000 SECT6     NULL   NULL     STATIC               | .debug$T
     Section length 1b74, #relocs    0, #linenums    0, checksum d2a84c0b
012 00000000 SECT7     NULL   NULL     STATIC               | .pdata
     Section length    c, #relocs    3, #linenums    0, checksum 43a25afa
014 00000000 SECT8     NULL   NULL     STATIC               | .llvm_addrsig
     Section length    0, #relocs    0, #linenums    0, checksum        0
016 00000000 ABSOLUTE  NULL   NULL     STATIC               | @feat.00
017 00000000 SECT1     NULL   FUNCTION EXTERNAL             | main
018 00000000 UNDEFINED NULL   NULL     EXTERNAL             | __main
019 00000000 DEBUG     NULL   NULL     FILE                 | .file
     empty.c

String table size = 0x12 bytes
```

### Examining PE image files

```
> zcoff a.exe --headers --symbols
PE signature found

File type: EXECUTABLE IMAGE

FILE HEADER VALUES
                8664 machine (X64)
                   7 number of sections
            6301da2e time date stamp
                   0 file pointer to symbol table
                   0 number of symbols
                  f0 size of optional header
                  22 characteristics
                       Executable
                       Application can handle > 2-GB addresses

OPTIONAL HEADER VALUES
                 20b magic # (PE32+)
                   e linker version (major)
                   0 linker version (minor)
               13200 size of code
                6400 size of initialized data
                   0 size of uninitialized data
                14a0 entry point
                1000 base of code
           140000000 image base
                1000 section alignment
                 200 file alignment
                   6 OS version (major)
                   0 OS version (minor)
                   0 image version (major)
                   0 image version (minor)
                   6 subsystem version (major)
                   0 subsystem version (minor)
                   0 Win32 version
               21000 size of image
                 400 size of headers
                   0 checksum
                   3 subsystem # (WINDOWS_CUI)
                8160 DLL flags
                       HIGH_ENTROPY_VA
                       DYNAMIC_BASE
                       NX_COMPAT
                       TERMINAL_SERVER_AWARE
             1000000 size of stack reserve
                1000 size of stack commit
              100000 size of heap reserve
                1000 size of heap commit
                   0 loader flags
                  10 number of directories
                   0 [         0] RVA [size] of Export Directory
               17ff8 [        3c] RVA [size] of Import Directory
                   0 [         0] RVA [size] of Resource Directory
               1d000 [      1338] RVA [size] of Exception Directory
                   0 [         0] RVA [size] of Certificates Directory
               20000 [        74] RVA [size] of Base Relocation Directory
               1a000 [        1c] RVA [size] of Debug Directory
                   0 [         0] RVA [size] of Architecture Directory
                   0 [         0] RVA [size] of Global Pointer Directory
               150a8 [        28] RVA [size] of Thread Storage Directory
                   0 [         0] RVA [size] of Load Configuration Directory
                   0 [         0] RVA [size] of Bound Import Directory
               18178 [       140] RVA [size] of Import Address Table Directory
                   0 [         0] RVA [size] of Delay Import Directory
                   0 [         0] RVA [size] of COM Descriptor Directory
                   0 [         0] RVA [size] of Reserved Directory

SECTION HEADER #0
               .text name
               130e6 virtual size
                1000 virtual address
               13200 size of raw data
                 400 file pointer to raw data
                   0 file pointer to relocation table
                   0 file pointer to line numbers
                   0 number of relocations
                   0 number of line numbers
            60000020 flags
                       CNT_CODE
                       MEM_EXECUTE
                       MEM_READ

SECTION HEADER #1
              .rdata name
                4744 virtual size
               15000 virtual address
                4800 size of raw data
               13600 file pointer to raw data
                   0 file pointer to relocation table
                   0 file pointer to line numbers
                   0 number of relocations
                   0 number of line numbers
            40000040 flags
                       CNT_INITIALIZED_DATA
                       MEM_READ

...

More headers

...

No symbol table found.
```
