#pragma once

#include <string>
#include <memory>
#include <fmt/format.h>
#include <bfd.h>

class bfd_closer {
public:
    using pointer = bfd*;

    void operator()(bfd* b) {
        if (b)
            bfd_close(b);
    }
};

using bfdup = std::unique_ptr<bfd*, bfd_closer>;

class formatted_error : public std::exception {
public:
    template<typename... Args>
    formatted_error(fmt::format_string<Args...> s, Args&&... args) : msg(fmt::format(s, std::forward<Args>(args)...)) {
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

static constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5a4d; // "MZ"

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

static constexpr unsigned int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG + 1];
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG + 1];
};

enum class pe_architecture : uint16_t {
    IMAGE_FILE_MACHINE_I386 = 0x014c,
    IMAGE_FILE_MACHINE_R3000 = 0x0162,
    IMAGE_FILE_MACHINE_R4000 = 0x0166,
    IMAGE_FILE_MACHINE_R10000 = 0x0168,
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169,
    IMAGE_FILE_MACHINE_ALPHA = 0x0184,
    IMAGE_FILE_MACHINE_SH3 = 0x01a2,
    IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
    IMAGE_FILE_MACHINE_SH3E = 0x01a4,
    IMAGE_FILE_MACHINE_SH4 = 0x01a6,
    IMAGE_FILE_MACHINE_SH5 = 0x01a8,
    IMAGE_FILE_MACHINE_ARM = 0x01c0,
    IMAGE_FILE_MACHINE_ARMV7 = 0x01c4,
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
    IMAGE_FILE_MACHINE_THUMB = 0x01c2,
    IMAGE_FILE_MACHINE_AM33 = 0x01d3,
    IMAGE_FILE_MACHINE_POWERPC = 0x01f0,
    IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
    IMAGE_FILE_MACHINE_IA64 = 0x0200,
    IMAGE_FILE_MACHINE_MIPS16 = 0x0266,
    IMAGE_FILE_MACHINE_ALPHA64 = 0x0284,
    IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,
    IMAGE_FILE_MACHINE_TRICORE = 0x0520,
    IMAGE_FILE_MACHINE_CEF = 0x0cef,
    IMAGE_FILE_MACHINE_EBC = 0x0ebc,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    IMAGE_FILE_MACHINE_M32R = 0x9041,
    IMAGE_FILE_MACHINE_CEE = 0xc0ee
};

struct IMAGE_FILE_HEADER {
    enum pe_architecture Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

static constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
static constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

#pragma pack(push,1)

struct IMAGE_SECTION_HEADER {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

struct IMAGE_NT_HEADERS {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    union {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    };
};

static constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550; // "PE\0\0"

struct IMAGE_DEBUG_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
};

static constexpr uint32_t IMAGE_DEBUG_TYPE_CODEVIEW = 2;

struct CV_INFO_PDB70 {
    uint32_t CvSignature;
    uint8_t Signature[16];
    uint32_t Age;
    char PdbFileName[];
};

static constexpr uint32_t CVINFO_PDB70_CVSIGNATURE = 0x53445352;

enum class cv_type : uint16_t {
    LF_VTSHAPE = 0x000a,
    LF_MODIFIER = 0x1001,
    LF_POINTER = 0x1002,
    LF_PROCEDURE = 0x1008,
    LF_MFUNCTION = 0x1009,
    LF_ARGLIST = 0x1201,
    LF_FIELDLIST = 0x1203,
    LF_BITFIELD = 0x1205,
    LF_METHODLIST = 0x1206,
    LF_BCLASS = 0x1400,
    LF_VBCLASS = 0x1401,
    LF_IVBCLASS = 0x1402,
    LF_INDEX = 0x1404,
    LF_VFUNCTAB = 0x1409,
    LF_ENUMERATE = 0x1502,
    LF_ARRAY = 0x1503,
    LF_CLASS = 0x1504,
    LF_STRUCTURE = 0x1505,
    LF_UNION = 0x1506,
    LF_ENUM = 0x1507,
    LF_MEMBER = 0x150d,
    LF_STMEMBER = 0x150e,
    LF_METHOD = 0x150f,
    LF_NESTTYPE = 0x1510,
    LF_ONEMETHOD = 0x1511,
    LF_VFTABLE = 0x151d,
    LF_FUNC_ID = 0x1601,
    LF_MFUNC_ID = 0x1602,
    LF_BUILDINFO = 0x1603,
    LF_SUBSTR_LIST = 0x1604,
    LF_STRING_ID = 0x1605,
    LF_UDT_SRC_LINE = 0x1606,
    LF_UDT_MOD_SRC_LINE = 0x1607,
    LF_CHAR = 0x8000,
    LF_SHORT = 0x8001,
    LF_USHORT = 0x8002,
    LF_LONG = 0x8003,
    LF_ULONG = 0x8004,
    LF_QUADWORD = 0x8009,
    LF_UQUADWORD = 0x800a
};

enum class cv_builtin : uint32_t {
    T_VOID = 0x0003,
    T_HRESULT = 0x0008,
    T_CHAR = 0x0010,
    T_UCHAR = 0x0020,
    T_RCHAR = 0x0070,
    T_WCHAR = 0x0071,
    T_CHAR16 = 0x007a,
    T_CHAR32 = 0x007b,
    T_INT1 = 0x0068,
    T_UINT1 = 0x0069,
    T_SHORT = 0x0011,
    T_USHORT = 0x0021,
    T_INT2 = 0x0072,
    T_UINT2 = 0x0073,
    T_LONG = 0x0012,
    T_ULONG = 0x0022,
    T_INT4 = 0x0074,
    T_UINT4 = 0x0075,
    T_QUAD = 0x0013,
    T_UQUAD = 0x0023,
    T_INT8 = 0x0076,
    T_UINT8 = 0x0077,
    T_REAL32 = 0x0040,
    T_REAL64 = 0x0041,
    T_BOOL08 = 0x0030
};

template<>
struct fmt::formatter<enum cv_type> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum cv_type t, format_context& ctx) const {
        switch (t) {
            case cv_type::LF_VTSHAPE:
                return fmt::format_to(ctx.out(), "LF_VTSHAPE");
            case cv_type::LF_MODIFIER:
                return fmt::format_to(ctx.out(), "LF_MODIFIER");
            case cv_type::LF_POINTER:
                return fmt::format_to(ctx.out(), "LF_POINTER");
            case cv_type::LF_PROCEDURE:
                return fmt::format_to(ctx.out(), "LF_PROCEDURE");
            case cv_type::LF_MFUNCTION:
                return fmt::format_to(ctx.out(), "LF_MFUNCTION");
            case cv_type::LF_ARGLIST:
                return fmt::format_to(ctx.out(), "LF_ARGLIST");
            case cv_type::LF_FIELDLIST:
                return fmt::format_to(ctx.out(), "LF_FIELDLIST");
            case cv_type::LF_BITFIELD:
                return fmt::format_to(ctx.out(), "LF_BITFIELD");
            case cv_type::LF_METHODLIST:
                return fmt::format_to(ctx.out(), "LF_METHODLIST");
            case cv_type::LF_BCLASS:
                return fmt::format_to(ctx.out(), "LF_BCLASS");
            case cv_type::LF_VBCLASS:
                return fmt::format_to(ctx.out(), "LF_VBCLASS");
            case cv_type::LF_IVBCLASS:
                return fmt::format_to(ctx.out(), "LF_IVBCLASS");
            case cv_type::LF_INDEX:
                return fmt::format_to(ctx.out(), "LF_INDEX");
            case cv_type::LF_VFUNCTAB:
                return fmt::format_to(ctx.out(), "LF_VFUNCTAB");
            case cv_type::LF_ENUMERATE:
                return fmt::format_to(ctx.out(), "LF_ENUMERATE");
            case cv_type::LF_ARRAY:
                return fmt::format_to(ctx.out(), "LF_ARRAY");
            case cv_type::LF_CLASS:
                return fmt::format_to(ctx.out(), "LF_CLASS");
            case cv_type::LF_STRUCTURE:
                return fmt::format_to(ctx.out(), "LF_STRUCTURE");
            case cv_type::LF_UNION:
                return fmt::format_to(ctx.out(), "LF_UNION");
            case cv_type::LF_ENUM:
                return fmt::format_to(ctx.out(), "LF_ENUM");
            case cv_type::LF_MEMBER:
                return fmt::format_to(ctx.out(), "LF_MEMBER");
            case cv_type::LF_STMEMBER:
                return fmt::format_to(ctx.out(), "LF_STMEMBER");
            case cv_type::LF_METHOD:
                return fmt::format_to(ctx.out(), "LF_METHOD");
            case cv_type::LF_NESTTYPE:
                return fmt::format_to(ctx.out(), "LF_NESTTYPE");
            case cv_type::LF_ONEMETHOD:
                return fmt::format_to(ctx.out(), "LF_ONEMETHOD");
            case cv_type::LF_VFTABLE:
                return fmt::format_to(ctx.out(), "LF_VFTABLE");
            case cv_type::LF_FUNC_ID:
                return fmt::format_to(ctx.out(), "LF_FUNC_ID");
            case cv_type::LF_MFUNC_ID:
                return fmt::format_to(ctx.out(), "LF_MFUNC_ID");
            case cv_type::LF_BUILDINFO:
                return fmt::format_to(ctx.out(), "LF_BUILDINFO");
            case cv_type::LF_SUBSTR_LIST:
                return fmt::format_to(ctx.out(), "LF_SUBSTR_LIST");
            case cv_type::LF_STRING_ID:
                return fmt::format_to(ctx.out(), "LF_STRING_ID");
            case cv_type::LF_UDT_SRC_LINE:
                return fmt::format_to(ctx.out(), "LF_UDT_SRC_LINE");
            case cv_type::LF_UDT_MOD_SRC_LINE:
                return fmt::format_to(ctx.out(), "LF_UDT_MOD_SRC_LINE");
            case cv_type::LF_CHAR:
                return fmt::format_to(ctx.out(), "LF_CHAR");
            case cv_type::LF_SHORT:
                return fmt::format_to(ctx.out(), "LF_SHORT");
            case cv_type::LF_USHORT:
                return fmt::format_to(ctx.out(), "LF_USHORT");
            case cv_type::LF_LONG:
                return fmt::format_to(ctx.out(), "LF_LONG");
            case cv_type::LF_ULONG:
                return fmt::format_to(ctx.out(), "LF_ULONG");
            case cv_type::LF_QUADWORD:
                return fmt::format_to(ctx.out(), "LF_QUADWORD");
            case cv_type::LF_UQUADWORD:
                return fmt::format_to(ctx.out(), "LF_UQUADWORD");
            default:
                return fmt::format_to(ctx.out(), "{:x}", (uint16_t)t);
        }
    }
};

// HDR in tpi.h
struct pdb_tpi_stream_header {
    uint32_t version;
    uint32_t header_size;
    uint32_t type_index_begin;
    uint32_t type_index_end;
    uint32_t type_record_bytes;
    uint16_t hash_stream_index;
    uint16_t hash_aux_stream_index;
    uint32_t hash_key_size;
    uint32_t num_hash_buckets;
    uint32_t hash_value_buffer_offset;
    uint32_t hash_value_buffer_length;
    uint32_t index_offset_buffer_offset;
    uint32_t index_offset_buffer_length;
    uint32_t hash_adj_buffer_offset;
    uint32_t hash_adj_buffer_length;
};

static const uint32_t TPI_STREAM_VERSION_80 = 20040203;

// lfEnum in cvinfo.h
struct lf_enum {
    cv_type kind;
    uint16_t num_elements;
    uint16_t properties;
    uint32_t underlying_type;
    uint32_t field_list;
    char name[];
} __attribute__((packed));

// lfEnumerate in cvinfo.h
struct lf_enumerate {
    cv_type kind;
    uint16_t attributes;
    uint16_t value;
    // then actual value if value >= 0x8000
    char name[];
} __attribute__((packed));

// from bitfield structure CV_prop_t in cvinfo.h
#define CV_PROP_FORWARD_REF     0x80
#define CV_PROP_SCOPED          0x100
#define CV_PROP_HAS_UNIQUE_NAME 0x200

// lfClass in cvinfo.h
struct lf_class {
    cv_type kind;
    uint16_t num_members;
    uint16_t properties;
    uint32_t field_list;
    uint32_t derived_from;
    uint32_t vshape;
    uint16_t length;
    char name[];
} __attribute__((packed));

// lfMember in cvinfo.h
struct lf_member {
    cv_type kind;
    uint16_t attributes;
    uint32_t type;
    uint16_t offset;
    char name[];
} __attribute__((packed));

// lfPointer in cvinfo.h
struct lf_pointer {
    cv_type kind;
    uint32_t base_type;
    uint32_t attributes;
} __attribute__((packed));

// lfArray in cvinfo.h
struct lf_array {
    cv_type kind;
    uint32_t element_type;
    uint32_t index_type;
    uint16_t length_in_bytes;
    char name[];
} __attribute__((packed));

// lfModifier in cvinfo.h
struct lf_modifier {
    cv_type kind;
    uint32_t base_type;
    uint16_t mod_const : 1;
    uint16_t mod_volatile : 1;
    uint16_t mod_unaligned : 1;
    uint16_t mod_unused : 13;
    uint16_t padding;
} __attribute__((packed));

// lfUnion in cvinfo.h
struct lf_union {
    cv_type kind;
    uint16_t num_members;
    uint16_t properties;
    uint32_t field_list;
    uint16_t length;
    char name[];
} __attribute__((packed));

// lfBitfield in cvinfo.h
struct lf_bitfield {
    cv_type kind;
    uint32_t base_type;
    uint8_t length;
    uint8_t position;
} __attribute__((packed));

// lfProc in cvinfo.h
struct lf_procedure {
    cv_type kind;
    uint32_t return_type;
    uint8_t calling_convention;
    uint8_t attributes;
    uint16_t num_parameters;
    uint32_t arglist;
} __attribute__((packed));

// lfArgList in cvinfo.h
struct lf_arglist {
    cv_type kind;
    uint32_t num_entries;
    uint32_t args[];
} __attribute__((packed));
