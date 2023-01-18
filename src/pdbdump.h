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

static const uint32_t TPI_STREAM_VERSION_80 = 20040203;
