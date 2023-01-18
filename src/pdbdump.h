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
