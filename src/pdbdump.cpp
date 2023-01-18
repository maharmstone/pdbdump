#include <iostream>
#include <vector>
#include <span>
#include "pdbdump.h"

using namespace std;

static void walk_fieldlist(span<const uint8_t> fl, invocable<span<const uint8_t>> auto func) {
    if (fl.size() < sizeof(cv_type))
        throw formatted_error("Field list was truncated.");

    auto kind = *(cv_type*)fl.data();

    // FIXME - formatter
    if (kind != cv_type::LF_FIELDLIST)
        throw formatted_error("Type kind was {:x}, expected LF_FIELDLIST.", (uint16_t)kind);

    fl = fl.subspan(sizeof(cv_type));

    while (!fl.empty()) {
        if (fl.size() < sizeof(cv_type))
            throw formatted_error("Field list was truncated.");

        auto kind = *(cv_type*)fl.data();

        switch (kind) {
            case cv_type::LF_ENUMERATE: {
                if (fl.size() < offsetof(lf_enumerate, name))
                    throw formatted_error("Truncated LF_ENUMERATE ({} bytes, expected at least {})", fl.size(), offsetof(lf_enumerate, name));

                const auto& en = *(lf_enumerate*)fl.data();

                if (en.value >= 0x8000)
                    throw runtime_error("FIXME - large enum values"); // FIXME

                auto name = string_view(en.name, fl.size() - offsetof(lf_enumerate, name));

                if (auto st = name.find('\0'); st != string::npos)
                    name = name.substr(0, st);
                else
                    throw runtime_error("No terminating null found in LF_ENUMERATE name.");

                auto len = offsetof(lf_enumerate, name) + name.size() + 1;

                if (len & 3)
                    len += 4 - (len & 3);

                if (len > fl.size())
                    throw formatted_error("Field list was truncated.");

                func(span(fl.data(), len));

                fl = fl.subspan(len);

                break;
            }

            // FIXME - other types

            default:
                throw formatted_error("Unhandled field list subtype {:x}", (uint16_t)kind);
        }
    }
}

static void print_enum(span<const uint8_t> t, const pdb_tpi_stream_header& h, const vector<span<const uint8_t>>& types) {
    if (t.size() < offsetof(lf_enum, name))
        throw formatted_error("Truncated LF_ENUM ({} bytes, expected at least {})", t.size(), offsetof(lf_enum, name));

    const auto& en = *(struct lf_enum*)t.data();

    // FIXME - print underlying type if not what is implied

    if (en.field_list < h.type_index_begin || en.field_list >= h.type_index_end)
        throw formatted_error("Enum field list {:x} was out of bounds.", en.field_list);

    const auto& fl = types[en.field_list - h.type_index_begin];

    auto name = string_view((char*)t.data() + offsetof(lf_enum, name), t.size() - offsetof(lf_enum, name));

    if (auto st = name.find('\0'); st != string::npos)
        name = name.substr(0, st);

    fmt::print("enum {} {{\n", name);

    walk_fieldlist(fl, [](span<const uint8_t> d) {
        const auto& e = *(lf_enumerate*)d.data();

        if (e.kind != cv_type::LF_ENUMERATE)
            throw formatted_error("Type {:x} found in enum field list, expected LF_ENUMERATE.", (uint16_t)e.kind);

        // FIXME - large types

        auto name = string_view(e.name, d.size() - offsetof(lf_enumerate, name));

        if (auto st = name.find('\0'); st != string::npos)
            name = name.substr(0, st);

        // FIXME - trailing comma
        // FIXME - omit value if follows on from previous

        fmt::print("    {} = {},\n", name, e.value);
    });

    fmt::print("}};\n\n");
}

static void extract_types(bfd* types_stream) {
    pdb_tpi_stream_header h;
    vector<uint8_t> type_records;

    if (bfd_seek(types_stream, 0, SEEK_SET))
        throw runtime_error("bfd_seek failed");

    if (bfd_bread(&h, sizeof(h), types_stream) != sizeof(h))
        throw runtime_error("bfd_bread failed");

    if (h.version != TPI_STREAM_VERSION_80)
        throw formatted_error("Type stream version was {}, expected {}.", h.version, TPI_STREAM_VERSION_80);

    if (bfd_seek(types_stream, h.header_size, SEEK_SET))
        throw runtime_error("bfd_seek failed");

    type_records.resize(h.type_record_bytes);

    if (bfd_bread(type_records.data(), type_records.size(), types_stream) != type_records.size())
        throw runtime_error("bfd_bread failed");

    span sp(type_records);
    vector<span<const uint8_t>> types;

    types.reserve(h.type_index_end - h.type_index_begin);

    while (!sp.empty()) {
        if (sp.size() < sizeof(uint16_t))
            throw runtime_error("type_records was truncated");

        auto len = *(uint16_t*)sp.data();

        sp = sp.subspan(sizeof(uint16_t));

        if (sp.size() < len)
            throw runtime_error("type_records was truncated");

        types.emplace_back(sp.data(), len);

        sp = sp.subspan(len);
    }

    uint32_t cur_type = h.type_index_begin;

    for (const auto& t : types) {
        if (t.size() < sizeof(cv_type))
            continue;

        auto kind = *(cv_type*)t.data();

        try {
            switch (kind) {
                case cv_type::LF_ENUM:
                    print_enum(t, h, types);
                    break;

                // FIXME - LF_STRUCTURE / LF_CLASS

                default:
                    break;
            }
        } catch (const exception& e) {
            fmt::print(stderr, "Error parsing type {:x}: {}\n", cur_type, e.what());
        }

        cur_type++;
    }
}

static void load_file(const string& fn) {
    bfdup b;

    // FIXME - show BFD errors in exceptions

    {
        auto arch = bfd_openr(fn.c_str(), "pdb");

        if (!arch)
            throw runtime_error("Could not load PDB file " + fn + ".");

        b.reset(arch);
    }

    if (!bfd_check_format(b.get(), bfd_archive))
        throw runtime_error("bfd_check_format failed");

    bfd* types_stream = nullptr;
    unsigned int count = 0;

    for (auto f = bfd_openr_next_archived_file(b.get(), nullptr); f; f = bfd_openr_next_archived_file(b.get(), f)) {
        if (count == 2) {
            types_stream = f;
            break;
        }

        count++;
    }

    if (!types_stream)
        throw runtime_error("Could not extract types stream 0002.");

    extract_types(types_stream);
}

int main() {
    try {
        // FIXME - show options if no args
        // FIXME - get filename from args
        // FIXME - if filename is PE image, lookup PDB file on symbol servers

        load_file("ntkrnlmp.pdb");
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
