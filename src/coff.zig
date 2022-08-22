const std = @import("std");

pub const MachineType = std.coff.MachineType;

/// Image only, Windows CE, and Microsoft Windows NT and later.
/// This indicates that the file does not contain base relocations
/// and must therefore be loaded at its preferred base address.
/// If the base address is not available, the loader reports an error.
/// The default behavior of the linker is to strip base relocations
/// from executable (EXE) files.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x1;

/// Image only. This indicates that the image file is valid and can be run.
/// If this flag is not set, it indicates a linker error.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x2;

/// COFF line numbers have been removed. This flag is deprecated and should be zero.
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x4;

/// COFF symbol table entries for local symbols have been removed.
/// This flag is deprecated and should be zero.
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x8;

/// Obsolete. Aggressively trim working set.
/// This flag is deprecated for Windows 2000 and later and must be zero.
pub const IMAGE_FILE_AGGRESSIVE_WS_TRIM: u16 = 0x10;

/// Application can handle > 2-GB addresses.
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x20;

/// This flag is reserved for future use.
pub const IMAGE_FILE_RESERVED: u16 = 0x40;

/// Little endian: the least significant bit (LSB) precedes the
/// most significant bit (MSB) in memory. This flag is deprecated and should be zero.
pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x80;

/// Machine is based on a 32-bit-word architecture.
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x100;

/// Debugging information is removed from the image file.
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x200;

/// If the image is on removable media, fully load it and copy it to the swap file.
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x400;

/// If the image is on network media, fully load it and copy it to the swap file.
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x800;

/// The image file is a system file, not a user program.
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;

/// The image file is a dynamic-link library (DLL).
/// Such files are considered executable files for almost all purposes,
/// although they cannot be directly run.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// The file should be run only on a uniprocessor machine.
pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;

/// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

pub const CoffHeader = extern struct {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
};

pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

/// Image can handle a high entropy 64-bit virtual address space.
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x20;

/// DLL can be relocated at load time.
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x40;

/// Code Integrity checks are enforced.
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x80;

/// Image is NX compatible.
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x100;

/// Isolation aware, but do not isolate the image.
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x200;

/// Does not use structured exception (SE) handling. No SE handler may be called in this image.
pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x400;

/// Do not bind the image.
pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x800;

/// Image must execute in an AppContainer.
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;

/// A WDM driver.
pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;

/// Image supports Control Flow Guard.
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

/// Terminal Server aware.
pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

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
    subsystem: u16,
    dll_characteristics: u16,
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
    subsystem: u16,
    dll_characteristics: u16,
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
    flags: u32,

    pub fn getName(self: *const SectionHeader) ?[]const u8 {
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
        const align_flag = @intCast(u16, (self.flags & IMAGE_SCN_ALIGN_MASK) >> comptime @ctz(u32, IMAGE_SCN_ALIGN_MASK));
        if (align_flag == 0) return null;
        return std.math.powi(u16, 2, align_flag - 1) catch unreachable;
    }
};

/// The section should not be padded to the next boundary.
/// This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.
/// This is valid only for object files.
pub const IMAGE_SCN_TYPE_NO_PAD: u32 = 0x8;

/// The section contains executable code.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x20;

/// The section contains initialized data.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;

/// The section contains uninitialized data.
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x80;

/// Reserved for future use.
pub const IMAGE_SCN_LNK_OTHER: u32 = 0x100;

/// The section contains comments or other information.
/// The .drectve section has this type.
/// This is valid for object files only.
pub const IMAGE_SCN_LNK_INFO: u32 = 0x200;

/// The section will not become part of the image.
/// This is valid only for object files.
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x800;

/// The section contains COMDAT data.
/// For more information, see COMDAT Sections (Object Only).
/// This is valid only for object files.
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x1000;

/// The section contains data referenced through the global pointer (GP).
pub const IMAGE_SCN_GPREL: u32 = 0x8000;

/// Reserved for future use.
pub const IMAGE_SCN_MEM_PURGEABLE: u32 = 0x20000;

/// Reserved for future use.
pub const IMAGE_SCN_MEM_16BIT: u32 = 0x20000;

/// Reserved for future use.
pub const IMAGE_SCN_MEM_LOCKED: u32 = 0x40000;

/// Reserved for future use.
pub const IMAGE_SCN_MEM_PRELOAD: u32 = 0x80000;

pub const IMAGE_SCN_ALIGN_MASK: u32 = 0xf00000;

/// Align data on a 1-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x100000;

/// Align data on a 2-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x200000;

/// Align data on a 4-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x300000;

/// Align data on an 8-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x400000;

/// Align data on a 16-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x500000;

/// Align data on a 32-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x600000;

/// Align data on a 64-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x700000;

/// Align data on a 128-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x800000;

/// Align data on a 256-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x900000;

/// Align data on a 512-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0xA00000;

/// Align data on a 1024-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0xB00000;

/// Align data on a 2048-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0xC00000;

/// Align data on a 4096-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0xD00000;

/// Align data on an 8192-byte boundary.
/// Valid only for object files.
pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0xE00000;

/// The section contains extended relocations.
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x1000000;

/// The section can be discarded as needed.
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x2000000;

/// The section cannot be cached.
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x4000000;

/// The section is not pageable.
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x8000000;

/// The section can be shared in memory.
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;

/// The section can be executed as code.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

/// The section can be read.
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;

/// The section can be written to.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

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

    pub fn getName(self: Symbol) ?[]const u8 {
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
