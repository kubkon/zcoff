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

pub const OptionalHeader = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
};
