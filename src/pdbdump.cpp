#include <iostream>
#include <vector>
#include <span>
#include "pdbdump.h"

using namespace std;

class pdb {
public:
    pdb(bfd* types_stream) : types_stream(types_stream) { }

    void extract_types();
    void print_struct(span<const uint8_t> t);
    void print_enum(span<const uint8_t> t);
    void print_member(span<const uint8_t> mt, string_view name);
    size_t get_type_size(uint32_t type);
    string type_name(span<const uint8_t> t);

private:
    bfd* types_stream;
    pdb_tpi_stream_header h;
    vector<uint8_t> type_records;
    vector<span<const uint8_t>> types;
};

static unsigned int extended_value_len(cv_type type) {
    switch (type) {
        case cv_type::LF_CHAR:
            return 1;

        case cv_type::LF_SHORT:
        case cv_type::LF_USHORT:
            return 2;

        case cv_type::LF_LONG:
        case cv_type::LF_ULONG:
            return 4;

        case cv_type::LF_QUADWORD:
        case cv_type::LF_UQUADWORD:
            return 8;

        default:
            throw formatted_error("Unrecognized extended value type {}", type);
    }
}

static void walk_fieldlist(span<const uint8_t> fl, invocable<span<const uint8_t>> auto func) {
    if (fl.size() < sizeof(cv_type))
        throw formatted_error("Field list was truncated.");

    auto kind = *(cv_type*)fl.data();

    if (kind != cv_type::LF_FIELDLIST)
        throw formatted_error("Type kind was {}, expected LF_FIELDLIST.", kind);

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

                size_t off = offsetof(lf_enumerate, name);

                if (en.value >= 0x8000) {
                    auto extlen = extended_value_len((cv_type)en.value);

                    if (fl.size() < off + extlen)
                        throw formatted_error("Truncated LF_ENUMERATE ({} bytes, expected at least {})", fl.size(), off + extlen);

                    off += extlen;
                }

                auto name = string_view((char*)&en + off, fl.size() - off);

                if (auto st = name.find('\0'); st != string::npos)
                    name = name.substr(0, st);
                else
                    throw runtime_error("No terminating null found in LF_ENUMERATE name.");

                auto len = off + name.size() + 1;

                if (len & 3)
                    len += 4 - (len & 3);

                if (len > fl.size())
                    throw formatted_error("Field list was truncated.");

                func(span(fl.data(), len));

                fl = fl.subspan(len);

                break;
            }

            case cv_type::LF_MEMBER: {
                if (fl.size() < offsetof(lf_member, name))
                    throw formatted_error("Truncated LF_MEMBER ({} bytes, expected at least {})", fl.size(), offsetof(lf_member, name));

                const auto& mem = *(lf_member*)fl.data();

                size_t off = offsetof(lf_member, name);

                if (mem.offset >= 0x8000) {
                    auto extlen = extended_value_len((cv_type)mem.offset);

                    if (fl.size() < off + extlen)
                        throw formatted_error("Truncated LF_MEMBER ({} bytes, expected at least {})", fl.size(), off + extlen);

                    off += extlen;
                }

                auto name = string_view((char*)&mem + off, fl.size() - off);

                if (auto st = name.find('\0'); st != string::npos)
                    name = name.substr(0, st);
                else
                    throw runtime_error("No terminating null found in LF_MEMBER name.");

                auto len = off + name.size() + 1;

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
                throw formatted_error("Unhandled field list subtype {}", kind);
        }
    }
}

void pdb::print_enum(span<const uint8_t> t) {
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

    bool first = true;
    int64_t exp_val = 0;

    walk_fieldlist(fl, [&](span<const uint8_t> d) {
        const auto& e = *(lf_enumerate*)d.data();

        if (e.kind != cv_type::LF_ENUMERATE)
            throw formatted_error("Type {} found in enum field list, expected LF_ENUMERATE.", e.kind);

        size_t off = offsetof(lf_enumerate, name);
        int64_t value;

        // FIXME - distinguish between int64_t and uint64_t values?

        if (e.value < 0x8000)
            value = e.value;
        else {
            switch ((cv_type)e.value) {
                case cv_type::LF_CHAR:
                    value = *(int8_t*)&e.name;
                    off += sizeof(int8_t);
                break;

                case cv_type::LF_SHORT:
                    value = *(int16_t*)&e.name;
                    off += sizeof(int16_t);
                break;

                case cv_type::LF_USHORT:
                    value = *(uint16_t*)&e.name;
                    off += sizeof(uint16_t);
                break;

                case cv_type::LF_LONG:
                    value = *(int32_t*)&e.name;
                    off += sizeof(int32_t);
                break;

                case cv_type::LF_ULONG:
                    value = *(uint32_t*)&e.name;
                    off += sizeof(uint32_t);
                break;

                case cv_type::LF_QUADWORD:
                    value = *(int64_t*)&e.name;
                    off += sizeof(int64_t);
                break;

                case cv_type::LF_UQUADWORD:
                    value = *(uint64_t*)&e.name;
                    off += sizeof(uint64_t);
                break;

                default:
                    break;
            }
        }

        auto name = string_view((char*)&e + off, d.size() - off);

        if (auto st = name.find('\0'); st != string::npos)
            name = name.substr(0, st);

        if (!first)
            fmt::print(",\n");

        if (value == exp_val)
            fmt::print("    {}", name, value);
        else
            fmt::print("    {} = {}", name, value);

        exp_val = value + 1;
        first = false;
    });

    fmt::print("\n}};\n\n");
}

static string builtin_type(uint32_t t) {
    if (t >> 8 == 4 || t >> 8 == 6) // pointers
        return builtin_type(t & 0xff) + "*";

    switch ((cv_builtin)t) {
        case cv_builtin::T_VOID:
            return "void";
        case cv_builtin::T_HRESULT:
            return "HRESULT";
        case cv_builtin::T_CHAR:
            return "signed char";
        case cv_builtin::T_UCHAR:
            return "unsigned char";
        case cv_builtin::T_RCHAR:
            return "char";
        case cv_builtin::T_WCHAR:
            return "wchar_t";
        case cv_builtin::T_CHAR16:
            return "char16_t";
        case cv_builtin::T_CHAR32:
            return "char32_t";
        case cv_builtin::T_INT1:
            return "int8_t";
        case cv_builtin::T_UINT1:
            return "uint8_t";
        case cv_builtin::T_SHORT:
            return "short";
        case cv_builtin::T_USHORT:
            return "unsigned short";
        case cv_builtin::T_INT2:
            return "int16_t";
        case cv_builtin::T_UINT2:
            return "uint16_t";
        case cv_builtin::T_LONG:
            return "long";
        case cv_builtin::T_ULONG:
            return "unsigned long";
        case cv_builtin::T_INT4:
            return "int";
        case cv_builtin::T_UINT4:
            return "unsigned int";
        case cv_builtin::T_QUAD:
            return "long long";
        case cv_builtin::T_UQUAD:
            return "unsigned long long";
        case cv_builtin::T_INT8:
            return "int64_t";
        case cv_builtin::T_UINT8:
            return "uint64_t";
        case cv_builtin::T_REAL32:
            return "float";
        case cv_builtin::T_REAL64:
            return "double";
        case cv_builtin::T_BOOL08:
            return "bool";
    }

    throw formatted_error("Unhandled builtin type {:x}\n", t);
}

string pdb::type_name(span<const uint8_t> t) {
    if (t.size() < sizeof(cv_type))
        throw formatted_error("Truncated type");

    auto kind = *(cv_type*)t.data();

    switch (kind) {
        case cv_type::LF_POINTER: {
            if (t.size() < sizeof(lf_pointer))
                throw formatted_error("Truncated LF_POINTER ({} bytes, expected {})", t.size(), sizeof(lf_pointer));

            const auto& p = *(lf_pointer*)t.data();

            if (p.base_type < h.type_index_begin)
                return builtin_type(p.base_type) + "*";

            if (p.base_type >= h.type_index_end)
                throw formatted_error("Pointer base type {:x} was out of bounds.", p.base_type);

            const auto& bt = types[p.base_type - h.type_index_begin];

            return type_name(bt) + "*";
        }

        case cv_type::LF_STRUCTURE:
        case cv_type::LF_CLASS: {
            if (t.size() < offsetof(lf_class, name))
                throw formatted_error("Truncated LF_STRUCTURE / LF_CLASS ({} bytes, expected at least {})", t.size(), offsetof(lf_class, name));

            const auto& str = *(lf_class*)t.data();

            // FIXME - anonymous structs

            auto name = string_view(str.name, t.size() - offsetof(lf_class, name));

            if (auto st = name.find('\0'); st != string::npos)
                name = name.substr(0, st);

            return string{name};
        }

        case cv_type::LF_MODIFIER: {
            if (t.size() < sizeof(lf_modifier))
                throw formatted_error("Truncated LF_MODIFIER ({} bytes, expected {})", t.size(), sizeof(lf_modifier));

            const auto& mod = *(lf_modifier*)t.data();

            string pref;

            if (mod.mod_const)
                pref = "const ";

            if (mod.mod_volatile)
                pref += "volatile ";

            if (mod.base_type < h.type_index_begin)
                return pref + builtin_type(mod.base_type);

            if (mod.base_type >= h.type_index_end)
                throw formatted_error("Modifier base type {:x} was out of bounds.", mod.base_type);

            const auto& bt = types[mod.base_type - h.type_index_begin];

            return pref + type_name(bt);
        }

        case cv_type::LF_ENUM: {
            if (t.size() < offsetof(lf_enum, name))
                throw formatted_error("Truncated LF_ENUM ({} bytes, expected at least {})", t.size(), offsetof(lf_enum, name));

            const auto& en = *(lf_enum*)t.data();

            auto name = string_view(en.name, t.size() - offsetof(lf_enum, name));

            if (auto st = name.find('\0'); st != string::npos)
                name = name.substr(0, st);

            return string{name};
        }

        // FIXME - LF_ARRAY
        // FIXME - LF_BITFIELD
        // FIXME - LF_UNION
        // FIXME - LF_PROCEDURE

        default:
            throw formatted_error("FIXME - {} type\n", kind);
    }
}

static size_t array_length(const lf_array& arr) {
    // FIXME - long arrays

    return arr.length_in_bytes;
}

size_t pdb::get_type_size(uint32_t type) {
    if (type < h.type_index_begin) {
        if (type >> 8 == 4)
            return 4; // 32-bit pointer
        else if (type >> 8 == 6)
            return 8; // 64-bit pointer

        switch ((cv_builtin)type) {
            case cv_builtin::T_HRESULT:
                return 4;

            case cv_builtin::T_CHAR:
            case cv_builtin::T_UCHAR:
            case cv_builtin::T_RCHAR:
            case cv_builtin::T_INT1:
            case cv_builtin::T_UINT1:
            case cv_builtin::T_BOOL08:
                return 1;

            case cv_builtin::T_WCHAR:
            case cv_builtin::T_CHAR16:
            case cv_builtin::T_SHORT:
            case cv_builtin::T_USHORT:
            case cv_builtin::T_INT2:
            case cv_builtin::T_UINT2:
                return 2;

            case cv_builtin::T_CHAR32:
            case cv_builtin::T_LONG:
            case cv_builtin::T_ULONG:
            case cv_builtin::T_INT4:
            case cv_builtin::T_UINT4:
            case cv_builtin::T_REAL32:
                return 4;

            case cv_builtin::T_QUAD:
            case cv_builtin::T_UQUAD:
            case cv_builtin::T_INT8:
            case cv_builtin::T_UINT8:
            case cv_builtin::T_REAL64:
                return 8;

            default:
                throw formatted_error("Could not find size of builtin type {:x}\n", type);
        }
    }

    if (type >= h.type_index_end)
        throw formatted_error("Type {:x} was out of bounds.", type);

    const auto& t = types[type - h.type_index_begin];

    if (t.size() < sizeof(cv_type))
        throw formatted_error("Type {:x} was truncated.", type);

    switch (*(cv_type*)t.data()) {
        case cv_type::LF_POINTER: {
            if (t.size() < sizeof(lf_pointer))
                throw formatted_error("Pointer type {:x} was truncated.", type);

            const auto& ptr = *(lf_pointer*)t.data();

            return (ptr.attributes & 0x7e000) >> 13; // pointer size
        }

        case cv_type::LF_ARRAY: {
            if (t.size() < offsetof(lf_array, name))
                throw formatted_error("Array type {:x} was truncated.", type);

            return array_length(*(lf_array*)t.data());
        }

        case cv_type::LF_STRUCTURE:
        case cv_type::LF_CLASS: {
            if (t.size() < offsetof(lf_class, name))
                throw formatted_error("Structure type {:x} was truncated.", type);

            const auto& str = *(lf_class*)t.data();

            if (str.properties & CV_PROP_FORWARD_REF) {
                // resolve forward ref

                auto name = string_view(str.name, t.size() - offsetof(lf_class, name));

                if (auto st = name.find('\0'); st != string::npos)
                    name = name.substr(0, st);

                // FIXME - use hash stream

                for (const auto& t2 : types) {
                    if (t2.size() < sizeof(cv_type) || *(cv_type*)t2.data() != *(cv_type*)t.data())
                        continue;

                    if (t2.size() < offsetof(lf_class, name))
                        continue;

                    const auto& str2 = *(lf_class*)t2.data();

                    if (str2.properties & CV_PROP_FORWARD_REF)
                        continue;

                    // FIXME - long structs

                    auto name2 = string_view(str2.name, t2.size() - offsetof(lf_class, name));

                    if (auto st = name2.find('\0'); st != string::npos)
                        name2 = name2.substr(0, st);

                    if (name == name2)
                        return str2.length;
                }

                throw formatted_error("Could not resolve forward ref for struct {}.", name);
            }

            // FIXME - long structs

            return str.length;
        }

        default:
            throw formatted_error("Could not find size of {} type {:x}\n", *(cv_type*)t.data(), type);
    }
}

void pdb::print_member(span<const uint8_t> mt, string_view name) {
    if (mt.size() >= sizeof(cv_type) && *(cv_type*)mt.data() == cv_type::LF_ARRAY) {
        const auto* arr = (lf_array*)mt.data();

        if (mt.size() < offsetof(lf_array, name))
            throw formatted_error("Truncated LF_ARRAY ({} bytes, expected at least {})", mt.size(), offsetof(lf_array, name));

        string name2{name};
        size_t num_els = array_length(*arr) / get_type_size(arr->element_type);

        name2 += "[" + to_string(num_els) + "]";

        do {
            if (arr->element_type < h.type_index_begin) {
                fmt::print("    {} {};\n", builtin_type(arr->element_type), name2);
                return;
            }

            if (arr->element_type >= h.type_index_end)
                throw formatted_error("Array element type {:x} was out of bounds.", arr->element_type);

            const auto& mt2 = types[arr->element_type - h.type_index_begin];

            if (mt2.size() < sizeof(cv_type) || *(cv_type*)mt2.data() != cv_type::LF_ARRAY) {
                fmt::print("    {} {};\n", type_name(mt2), name2);
                return;
            }

            arr = (lf_array*)mt2.data();

            num_els = array_length(*arr) / get_type_size(arr->element_type);

            name2 += "[" + to_string(num_els) + "]";
        } while (true);
    }

    fmt::print("    {} {};\n", type_name(mt), name);
}

void pdb::print_struct(span<const uint8_t> t) {
    if (t.size() < offsetof(lf_class, name))
        throw formatted_error("Truncated LF_STRUCTURE / LF_CLASS ({} bytes, expected at least {})", t.size(), offsetof(lf_class, name));

    const auto& str = *(lf_class*)t.data();

    // ignore forward declarations
    if (str.properties & CV_PROP_FORWARD_REF)
        return;

    // FIXME - skip anonymous structs

    if (str.field_list < h.type_index_begin || str.field_list >= h.type_index_end)
        throw formatted_error("Struct field list {:x} was out of bounds.", str.field_list);

    // FIXME - derived_from
    // FIXME - vshape

    // FIXME - static_asserts (sizeof, offsetof)

    const auto& fl = types[str.field_list - h.type_index_begin];

    auto name = string_view(str.name, t.size() - offsetof(lf_class, name));

    if (auto st = name.find('\0'); st != string::npos)
        name = name.substr(0, st);

    // FIXME - "class" instead if LF_CLASS
    fmt::print("struct {} {{\n", name);

    // FIXME - anonymous structs
    // FIXME - unions

    walk_fieldlist(fl, [&](span<const uint8_t> d) {
        const auto& mem = *(lf_member*)d.data();

        if (mem.kind != cv_type::LF_MEMBER)
            return;

        size_t off = offsetof(lf_member, name);

        if (mem.offset >= 0x8000)
            off += extended_value_len((cv_type)mem.offset);

        auto name = string_view((char*)&mem + off, d.size() - off);

        if (auto st = name.find('\0'); st != string::npos)
            name = name.substr(0, st);

        if (mem.type < h.type_index_begin) {
            fmt::print("    {} {};\n", builtin_type(mem.type), name);
            return;
        }

        if (mem.type >= h.type_index_end)
            throw formatted_error("Member type {:x} was out of bounds.", mem.type);

        const auto& mt = types[mem.type - h.type_index_begin];

        print_member(mt, name);
    });

    fmt::print("}};\n\n");
}

void pdb::extract_types() {
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
                    print_enum(t);
                    break;

                case cv_type::LF_STRUCTURE:
                case cv_type::LF_CLASS:
                    print_struct(t);
                    break;

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

    pdb p(types_stream);

    p.extract_types();
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
