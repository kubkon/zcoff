const std = @import("std");

pub const MachineType = std.coff.MachineType;

pub const CoffHeaderFlags = packed struct {
    /// Image only, Windows CE, and Microsoft Windows NT and later.
    /// This indicates that the file does not contain base relocations
    /// and must therefore be loaded at its preferred base address.
    /// If the base address is not available, the loader reports an error.
    /// The default behavior of the linker is to strip base relocations
    /// from executable (EXE) files.
    RELOCS_STRIPPED: u1,

    /// Image only. This indicates that the image file is valid and can be run.
    /// If this flag is not set, it indicates a linker error.
    EXECUTABLE_IMAGE: u1,

    /// COFF line numbers have been removed. This flag is deprecated and should be zero.
    LINE_NUMS_STRIPPED: u1,

    /// COFF symbol table entries for local symbols have been removed.
    /// This flag is deprecated and should be zero.
    LOCAL_SYMS_STRIPPED: u1,

    /// Obsolete. Aggressively trim working set.
    /// This flag is deprecated for Windows 2000 and later and must be zero.
    AGGRESSIVE_WS_TRIM: u1,

    /// Application can handle > 2-GB addresses.
    LARGE_ADDRESS_AWARE: u1,

    /// This flag is reserved for future use.
    RESERVED: u1,

    /// Little endian: the least significant bit (LSB) precedes the
    /// most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    BYTES_REVERSED_LO: u1,

    /// Machine is based on a 32-bit-word architecture.
    @"32BIT_MACHINE": u1,

    /// Debugging information is removed from the image file.
    DEBUG_STRIPPED: u1,

    /// If the image is on removable media, fully load it and copy it to the swap file.
    REMOVABLE_RUN_FROM_SWAP: u1,

    /// If the image is on network media, fully load it and copy it to the swap file.
    NET_RUN_FROM_SWAP: u1,

    /// The image file is a system file, not a user program.
    SYSTEM: u1,

    /// The image file is a dynamic-link library (DLL).
    /// Such files are considered executable files for almost all purposes,
    /// although they cannot be directly run.
    DLL: u1,

    /// The file should be run only on a uniprocessor machine.
    UP_SYSTEM_ONLY: u1,

    /// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    BYTES_REVERSED_HI: u1,
};

pub const CoffHeader = extern struct {
    /// The number that identifies the type of target machine.
    machine: MachineType,

    /// The number of sections. This indicates the size of the section table, which immediately follows the headers.
    number_of_sections: u16,

    /// The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value),
    /// which indicates when the file was created.
    time_date_stamp: u32,

    /// The file offset of the COFF symbol table, or zero if no COFF symbol table is present.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pointer_to_symbol_table: u32,

    /// The number of entries in the symbol table.
    /// This data can be used to locate the string table, which immediately follows the symbol table.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    number_of_symbols: u32,

    /// The size of the optional header, which is required for executable files but not for object files.
    /// This value should be zero for an object file. For a description of the header format, see Optional Header (Image Only).
    size_of_optional_header: u16,

    /// The flags that indicate the attributes of the file.
    flags: CoffHeaderFlags,
};

pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

pub const DllFlags = packed struct {
    _reserved_0: u5,

    /// Image can handle a high entropy 64-bit virtual address space.
    HIGH_ENTROPY_VA: u1,

    /// DLL can be relocated at load time.
    DYNAMIC_BASE: u1,

    /// Code Integrity checks are enforced.
    FORCE_INTEGRITY: u1,

    /// Image is NX compatible.
    NX_COMPAT: u1,

    /// Isolation aware, but do not isolate the image.
    NO_ISOLATION: u1,

    /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
    NO_SEH: u1,

    /// Do not bind the image.
    NO_BIND: u1,

    /// Image must execute in an AppContainer.
    APPCONTAINER: u1,

    /// A WDM driver.
    WDM_DRIVER: u1,

    /// Image supports Control Flow Guard.
    GUARD_CF: u1,

    /// Terminal Server aware.
    TERMINAL_SERVER_AWARE: u1,
};

pub const Subsystem = enum(u16) {
    /// An unknown subsystem
    UNKNOWN = 0,

    /// Device drivers and native Windows processes
    NATIVE = 1,

    /// The Windows graphical user interface (GUI) subsystem
    WINDOWS_GUI = 2,

    /// The Windows character subsystem
    WINDOWS_CUI = 3,

    /// The OS/2 character subsystem
    OS2_CUI = 5,

    /// The Posix character subsystem
    POSIX_CUI = 7,

    /// Native Win9x driver
    NATIVE_WINDOWS = 8,

    /// Windows CE
    WINDOWS_CE_GUI = 9,

    /// An Extensible Firmware Interface (EFI) application
    EFI_APPLICATION = 10,

    /// An EFI driver with boot services
    EFI_BOOT_SERVICE_DRIVER = 11,

    /// An EFI driver with run-time services
    EFI_RUNTIME_DRIVER = 12,

    /// An EFI ROM image
    EFI_ROM = 13,

    /// XBOX
    XBOX = 14,

    /// Windows boot application
    WINDOWS_BOOT_APPLICATION = 16,
};

pub const OptionalHeaderPE32 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_flags: DllFlags,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

pub const OptionalHeaderPE64 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_flags: DllFlags,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

pub const ImageDataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
};

pub const SectionHeader = extern struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    flags: SectionHeaderFlags,

    pub fn getName(self: *align(1) const SectionHeader) ?[]const u8 {
        if (self.name[0] == '/') return null;
        const len = std.mem.indexOfScalar(u8, &self.name, @as(u8, 0)) orelse self.name.len;
        return self.name[0..len];
    }

    pub fn getNameOffset(self: SectionHeader) ?u32 {
        if (self.name[0] != '/') return null;
        const len = std.mem.indexOfScalar(u8, &self.name, @as(u8, 0)) orelse self.name.len;
        const offset = std.fmt.parseInt(u32, self.name[1..len], 10) catch unreachable;
        return offset;
    }

    /// Applicable only to section headers in COFF objects.
    pub fn getAlignment(self: SectionHeader) ?u16 {
        if (self.flags.ALIGN == 0) return null;
        return std.math.powi(u16, 2, self.flags.ALIGN - 1) catch unreachable;
    }

    pub fn isComdat(self: SectionHeader) bool {
        return self.flags.LNK_COMDAT == 0b1;
    }
};

pub const SectionHeaderFlags = packed struct {
    _reserved_0: u3,
    /// The section should not be padded to the next boundary.
    /// This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.
    /// This is valid only for object files.
    TYPE_NO_PAD: u1,

    _reserved_1: u1,

    /// The section contains executable code.
    CNT_CODE: u1,

    /// The section contains initialized data.
    CNT_INITIALIZED_DATA: u1,

    /// The section contains uninitialized data.
    CNT_UNINITIALIZED_DATA: u1,

    /// Reserved for future use.
    LNK_OTHER: u1,

    /// The section contains comments or other information.
    /// The .drectve section has this type.
    /// This is valid for object files only.
    LNK_INFO: u1,

    _reserverd_2: u1,

    /// The section will not become part of the image.
    /// This is valid only for object files.
    LNK_REMOVE: u1,

    /// The section contains COMDAT data.
    /// For more information, see COMDAT Sections (Object Only).
    /// This is valid only for object files.
    LNK_COMDAT: u1,

    _reserved_3: u2,

    /// The section contains data referenced through the global pointer (GP).
    GPREL: u1,

    /// Reserved for future use.
    MEM_PURGEABLE: u1,

    /// Reserved for future use.
    MEM_16BIT: u1,

    /// Reserved for future use.
    MEM_LOCKED: u1,

    /// Reserved for future use.
    MEM_PRELOAD: u1,

    /// Takes on multiple values according to flags:
    /// pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x100000;
    /// pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x200000;
    /// pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x300000;
    /// pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x400000;
    /// pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x500000;
    /// pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x600000;
    /// pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x700000;
    /// pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x800000;
    /// pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x900000;
    /// pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0xA00000;
    /// pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0xB00000;
    /// pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0xC00000;
    /// pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0xD00000;
    /// pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0xE00000;
    ALIGN: u4,

    /// The section contains extended relocations.
    LNK_NRELOC_OVFL: u1,

    /// The section can be discarded as needed.
    MEM_DISCARDABLE: u1,

    /// The section cannot be cached.
    MEM_NOT_CACHED: u1,

    /// The section is not pageable.
    MEM_NOT_PAGED: u1,

    /// The section can be shared in memory.
    MEM_SHARED: u1,

    /// The section can be executed as code.
    MEM_EXECUTE: u1,

    /// The section can be read.
    MEM_READ: u1,

    /// The section can be written to.
    MEM_WRITE: u1,
};

pub const Symbol = struct {
    name: [8]u8,
    value: u32,
    section_number: SectionNumber,
    @"type": SymType,
    storage_class: StorageClass,
    number_of_aux_symbols: u8,

    pub fn sizeOf() usize {
        return 18;
    }

    pub fn getName(self: *const Symbol) ?[]const u8 {
        if (std.mem.eql(u8, self.name[0..4], "\x00\x00\x00\x00")) return null;
        const len = std.mem.indexOfScalar(u8, &self.name, @as(u8, 0)) orelse self.name.len;
        return self.name[0..len];
    }

    pub fn getNameOffset(self: Symbol) ?u32 {
        if (!std.mem.eql(u8, self.name[0..4], "\x00\x00\x00\x00")) return null;
        const offset = std.mem.readIntLittle(u32, self.name[4..8]);
        return offset;
    }
};

pub const SectionNumber = enum(u16) {
    /// The symbol record is not yet assigned a section.
    /// A value of zero indicates that a reference to an external symbol is defined elsewhere.
    /// A value of non-zero is a common symbol with a size that is specified by the value.
    UNDEFINED = 0,

    /// The symbol has an absolute (non-relocatable) value and is not an address.
    ABSOLUTE = 0xffff,

    /// The symbol provides general type or debugging information but does not correspond to a section.
    /// Microsoft tools use this setting along with .file records (storage class FILE).
    DEBUG = 0xfffe,
    _,
};

pub const SymType = packed struct {
    complex_type: ComplexType,
    base_type: BaseType,
};

pub const BaseType = enum(u8) {
    /// No type information or unknown base type. Microsoft tools use this setting
    NULL = 0,

    /// No valid type; used with void pointers and functions
    VOID = 1,

    /// A character (signed byte)
    CHAR = 2,

    /// A 2-byte signed integer
    SHORT = 3,

    /// A natural integer type (normally 4 bytes in Windows)
    INT = 4,

    /// A 4-byte signed integer
    LONG = 5,

    /// A 4-byte floating-point number
    FLOAT = 6,

    /// An 8-byte floating-point number
    DOUBLE = 7,

    /// A structure
    STRUCT = 8,

    /// A union
    UNION = 9,

    /// An enumerated type
    ENUM = 10,

    /// A member of enumeration (a specified value)
    MOE = 11,

    /// A byte; unsigned 1-byte integer
    BYTE = 12,

    /// A word; unsigned 2-byte integer
    WORD = 13,

    /// An unsigned integer of natural size (normally, 4 bytes)
    UINT = 14,

    /// An unsigned 4-byte integer
    DWORD = 15,
};

pub const ComplexType = enum(u8) {
    /// No derived type; the symbol is a simple scalar variable.
    NULL = 0,

    /// The symbol is a pointer to base type.
    POINTER = 16,

    /// The symbol is a function that returns a base type.
    FUNCTION = 32,

    /// The symbol is an array of base type.
    ARRAY = 48,
};

pub const StorageClass = enum(u8) {
    /// A special symbol that represents the end of function, for debugging purposes.
    END_OF_FUNCTION = 0xff,

    /// No assigned storage class.
    NULL = 0,

    /// The automatic (stack) variable. The Value field specifies the stack frame offset.
    AUTOMATIC = 1,

    /// A value that Microsoft tools use for external symbols.
    /// The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0).
    /// If the section number is not zero, then the Value field specifies the offset within the section.
    EXTERNAL = 2,

    /// The offset of the symbol within the section.
    /// If the Value field is zero, then the symbol represents a section name.
    STATIC = 3,

    /// A register variable.
    /// The Value field specifies the register number.
    REGISTER = 4,

    /// A symbol that is defined externally.
    EXTERNAL_DEF = 5,

    /// A code label that is defined within the module.
    /// The Value field specifies the offset of the symbol within the section.
    LABEL = 6,

    /// A reference to a code label that is not defined.
    UNDEFINED_LABEL = 7,

    /// The structure member. The Value field specifies the n th member.
    MEMBER_OF_STRUCT = 8,

    /// A formal argument (parameter) of a function. The Value field specifies the n th argument.
    ARGUMENT = 9,

    /// The structure tag-name entry.
    STRUCT_TAG = 10,

    /// A union member. The Value field specifies the n th member.
    MEMBER_OF_UNION = 11,

    /// The Union tag-name entry.
    UNION_TAG = 12,

    /// A Typedef entry.
    TYPE_DEFINITION = 13,

    /// A static data declaration.
    UNDEFINED_STATIC = 14,

    /// An enumerated type tagname entry.
    ENUM_TAG = 15,

    /// A member of an enumeration. The Value field specifies the n th member.
    MEMBER_OF_ENUM = 16,

    /// A register parameter.
    REGISTER_PARAM = 17,

    /// A bit-field reference. The Value field specifies the n th bit in the bit field.
    BIT_FIELD = 18,

    /// A .bb (beginning of block) or .eb (end of block) record.
    /// The Value field is the relocatable address of the code location.
    BLOCK = 100,

    /// A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf ), end function ( .ef ), and lines in function ( .lf ).
    /// For .lf records, the Value field gives the number of source lines in the function.
    /// For .ef records, the Value field gives the size of the function code.
    FUNCTION = 101,

    /// An end-of-structure entry.
    END_OF_STRUCT = 102,

    /// A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record.
    /// The symbol is followed by auxiliary records that name the file.
    FILE = 103,

    /// A definition of a section (Microsoft tools use STATIC storage class instead).
    SECTION = 104,

    /// A weak external. For more information, see Auxiliary Format 3: Weak Externals.
    WEAK_EXTERNAL = 105,

    /// A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token.
    /// For more information, see CLR Token Definition (Object Only).
    CLR_TOKEN = 107,
};

pub const FunctionDefinition = struct {
    /// The symbol-table index of the corresponding .bf (begin function) symbol record.
    tag_index: u32,

    /// The size of the executable code for the function itself.
    /// If the function is in its own section, the SizeOfRawData in the section header is greater or equal to this field,
    /// depending on alignment considerations.
    total_size: u32,

    /// The file offset of the first COFF line-number entry for the function, or zero if none exists.
    pointer_to_linenumber: u32,

    /// The symbol-table index of the record for the next function.
    /// If the function is the last in the symbol table, this field is set to zero.
    pointer_to_next_function: u32,

    unused: [2]u8,
};

pub const SectionDefinition = struct {
    /// The size of section data; the same as SizeOfRawData in the section header.
    length: u32,

    /// The number of relocation entries for the section.
    number_of_relocations: u16,

    /// The number of line-number entries for the section.
    number_of_linenumbers: u16,

    /// The checksum for communal data. It is applicable if the IMAGE_SCN_LNK_COMDAT flag is set in the section header.
    checksum: u32,

    /// One-based index into the section table for the associated section. This is used when the COMDAT selection setting is 5.
    number: u16,

    /// The COMDAT selection number. This is applicable if the section is a COMDAT section.
    selection: ComdatSelection,

    unused: [3]u8,
};

pub const FileDefinition = struct {
    /// An ANSI string that gives the name of the source file.
    /// This is padded with nulls if it is less than the maximum length.
    file_name: [18]u8,

    pub fn getFileName(self: *const FileDefinition) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.file_name, @as(u8, 0)) orelse self.file_name.len;
        return self.file_name[0..len];
    }
};

pub const WeakExternalDefinition = struct {
    /// The symbol-table index of sym2, the symbol to be linked if sym1 is not found.
    tag_index: u32,

    /// A value of IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY indicates that no library search for sym1 should be performed.
    /// A value of IMAGE_WEAK_EXTERN_SEARCH_LIBRARY indicates that a library search for sym1 should be performed.
    /// A value of IMAGE_WEAK_EXTERN_SEARCH_ALIAS indicates that sym1 is an alias for sym2.
    flag: WeakExternalFlag,

    unused: [10]u8,
};

// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/km/ntimage.h
pub const WeakExternalFlag = enum(u32) {
    SEARCH_NOLIBRARY = 1,
    SEARCH_LIBRARY = 2,
    SEARCH_ALIAS = 3,
    ANTI_DEPENDENCY = 4,
};

pub const ComdatSelection = enum(u8) {
    /// Not a COMDAT section.
    NONE = 0,

    /// If this symbol is already defined, the linker issues a "multiply defined symbol" error.
    NODUPLICATES = 1,

    /// Any section that defines the same COMDAT symbol can be linked; the rest are removed.
    ANY = 2,

    /// The linker chooses an arbitrary section among the definitions for this symbol.
    /// If all definitions are not the same size, a "multiply defined symbol" error is issued.
    SAME_SIZE = 3,

    /// The linker chooses an arbitrary section among the definitions for this symbol.
    /// If all definitions do not match exactly, a "multiply defined symbol" error is issued.
    EXACT_MATCH = 4,

    /// The section is linked if a certain other COMDAT section is linked.
    /// This other section is indicated by the Number field of the auxiliary symbol record for the section definition.
    /// This setting is useful for definitions that have components in multiple sections
    /// (for example, code in one and data in another), but where all must be linked or discarded as a set.
    /// The other section this section is associated with must be a COMDAT section, which can be another
    /// associative COMDAT section. An associative COMDAT section's section association chain can't form a loop.
    /// The section association chain must eventually come to a COMDAT section that doesn't have IMAGE_COMDAT_SELECT_ASSOCIATIVE set.
    ASSOCIATIVE = 5,

    /// The linker chooses the largest definition from among all of the definitions for this symbol.
    /// If multiple definitions have this size, the choice between them is arbitrary.
    LARGEST = 6,
};

pub const DebugInfoDefinition = struct {
    unused_1: [4]u8,

    /// The actual ordinal line number (1, 2, 3, and so on) within the source file, corresponding to the .bf or .ef record.
    linenumber: u16,

    unused_2: [6]u8,

    /// The symbol-table index of the next .bf symbol record.
    /// If the function is the last in the symbol table, this field is set to zero.
    /// It is not used for .ef records.
    pointer_to_next_function: u32,

    unused_3: [2]u8,
};
