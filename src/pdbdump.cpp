#include <iostream>
#include <vector>
#include <span>
#include <filesystem>
#include <curl/curl.h>
#include <fstream>
#include "pdbdump.h"

using namespace std;

struct sa {
    sa(string_view name, uint64_t off) : name(name), off(off) { }

    string name;
    uint64_t off;
};

template<typename T>
concept union_or_struct = std::is_same_v<T, lf_union> || std::is_same_v<T, lf_class>;

class pdb {
public:
    pdb(bfd* types_stream) : types_stream(types_stream) { }

    void extract_types();
    void print_struct(span<const uint8_t> t);
    void print_union(span<const uint8_t> t);
    void print_enum(span<const uint8_t> t);
    string format_member(span<const uint8_t> mt, string_view name, string_view prefix);
    uint64_t get_type_size(uint32_t type);
    string type_name(span<const uint8_t> t);
    string arg_list_to_string(uint32_t arg_list);
    void add_asserts(const union_or_struct auto& d, string_view name, uint64_t off, vector<sa>& asserts);

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

static string_view struct_name(span<const uint8_t> t) {
    const auto& str = *(lf_class*)t.data();

    size_t off = offsetof(lf_class, name);

    if (str.length >= 0x8000)
        off += extended_value_len((cv_type)str.length);

    auto name = string_view((char*)&str + off, t.size() - off);

    if (auto st = name.find('\0'); st != string::npos)
        name = name.substr(0, st);

    return name;
}

static uint64_t struct_length(span<const uint8_t> t) {
    const auto& str = *(lf_class*)t.data();

    if (str.length < 0x8000)
        return str.length;

    if (t.size() < offsetof(lf_class, name) + extended_value_len((cv_type)str.length))
        throw formatted_error("Struct type was truncated.");

    switch ((cv_type)str.length) {
        case cv_type::LF_CHAR:
            return *(int8_t*)&str.name;

        case cv_type::LF_SHORT:
            return *(int16_t*)&str.name;

        case cv_type::LF_USHORT:
            return *(uint16_t*)&str.name;

        case cv_type::LF_LONG:
            return *(int32_t*)&str.name;

        case cv_type::LF_ULONG:
            return *(uint32_t*)&str.name;

        case cv_type::LF_QUADWORD:
            return *(int64_t*)&str.name;

        case cv_type::LF_UQUADWORD:
            return *(uint64_t*)&str.name;

        default:
            throw formatted_error("Could not parse struct length type {}\n", (cv_type)str.length);
    }
}

static string_view union_name(span<const uint8_t> t) {
    const auto& str = *(lf_union*)t.data();

    size_t off = offsetof(lf_union, name);

    if (str.length >= 0x8000)
        off += extended_value_len((cv_type)str.length);

    auto name = string_view((char*)&str + off, t.size() - off);

    if (auto st = name.find('\0'); st != string::npos)
        name = name.substr(0, st);

    return name;
}

static string_view member_name(span<const uint8_t> t) {
    const auto& mem = *(lf_member*)t.data();

    size_t off = offsetof(lf_member, name);

    if (mem.offset >= 0x8000)
        off += extended_value_len((cv_type)mem.offset);

    auto name = string_view((char*)&mem + off, t.size() - off);

    if (auto st = name.find('\0'); st != string::npos)
        name = name.substr(0, st);

    return name;
}

static uint64_t member_offset(span<const uint8_t> t) {
    const auto& mem = *(lf_member*)t.data();

    if (mem.offset < 0x8000)
        return mem.offset;

    if (t.size() < offsetof(lf_union, name) + extended_value_len((cv_type)mem.offset))
        throw formatted_error("Member type was truncated.");

    switch ((cv_type)mem.offset) {
        case cv_type::LF_CHAR:
            return *(int8_t*)&mem.name;

        case cv_type::LF_SHORT:
            return *(int16_t*)&mem.name;

        case cv_type::LF_USHORT:
            return *(uint16_t*)&mem.name;

        case cv_type::LF_LONG:
            return *(int32_t*)&mem.name;

        case cv_type::LF_ULONG:
            return *(uint32_t*)&mem.name;

        case cv_type::LF_QUADWORD:
            return *(int64_t*)&mem.name;

        case cv_type::LF_UQUADWORD:
            return *(uint64_t*)&mem.name;

        default:
            throw formatted_error("Could not parse member offset type {}\n", (cv_type)mem.offset);
    }
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

            auto name = struct_name(t);

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

        case cv_type::LF_UNION: {
            if (t.size() < offsetof(lf_union, name))
                throw formatted_error("Truncated LF_UNION ({} bytes, expected at least {})", t.size(), offsetof(lf_union, name));

            auto name = union_name(t);

            return string{name};
        }

        default:
            throw formatted_error("Unhandled type {}\n", kind);
    }
}

static size_t array_length(const lf_array& arr) {
    // FIXME - long arrays

    return arr.length_in_bytes;
}

uint64_t pdb::get_type_size(uint32_t type) {
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

        case cv_type::LF_MODIFIER: {
            if (t.size() < sizeof(lf_modifier))
                throw formatted_error("Modifier type {:x} was truncated.", type);

            const auto& mod = *(lf_modifier*)t.data();

            return get_type_size(mod.base_type);
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
                auto name = struct_name(t);

                // FIXME - use hash stream

                for (const auto& t2 : types) {
                    if (t2.size() < sizeof(cv_type) || *(cv_type*)t2.data() != *(cv_type*)t.data())
                        continue;

                    if (t2.size() < offsetof(lf_class, name))
                        continue;

                    const auto& str2 = *(lf_class*)t2.data();

                    if (str2.properties & CV_PROP_FORWARD_REF)
                        continue;

                    auto name2 = struct_name(t2);

                    if (name == name2)
                        return str2.length;
                }

                throw formatted_error("Could not resolve forward ref for struct {}.", name);
            }

            // FIXME - long structs

            return str.length;
        }

        case cv_type::LF_ENUM: {
            if (t.size() < offsetof(lf_enum, name))
                throw formatted_error("Enum type {:x} was truncated.", type);

            const auto& en = *(lf_enum*)t.data();

            return get_type_size(en.underlying_type);
        }

        case cv_type::LF_UNION: {
            if (t.size() < offsetof(lf_union, name))
                throw formatted_error("Union type {:x} was truncated.", type);

            const auto* un = (lf_union*)t.data();

            if (un->properties & CV_PROP_FORWARD_REF) {
                // resolve forward ref

                bool found = false;
                auto name = union_name(t);

                // FIXME - use hash stream

                for (const auto& t2 : types) {
                    if (t2.size() < sizeof(cv_type) || *(cv_type*)t2.data() != *(cv_type*)t.data())
                        continue;

                    if (t2.size() < offsetof(lf_union, name))
                        continue;

                    const auto& un2 = *(lf_union*)t2.data();

                    if (un2.properties & CV_PROP_FORWARD_REF)
                        continue;

                    auto name2 = union_name(t2);

                    if (name == name2) {
                        found = true;
                        un = &un2;
                        break;
                    }
                }

                if (!found)
                    throw formatted_error("Could not resolve forward ref for union {}.", name);
            }

            if (un->length < 0x8000)
                return un->length;

            if (t.size() < offsetof(lf_union, name) + extended_value_len((cv_type)un->length))
                throw formatted_error("Union type {:x} was truncated.", type);

            switch ((cv_type)un->length) {
                case cv_type::LF_CHAR:
                    return *(int8_t*)&un->name;

                case cv_type::LF_SHORT:
                    return *(int16_t*)&un->name;

                case cv_type::LF_USHORT:
                    return *(uint16_t*)&un->name;

                case cv_type::LF_LONG:
                    return *(int32_t*)&un->name;

                case cv_type::LF_ULONG:
                    return *(uint32_t*)&un->name;

                case cv_type::LF_QUADWORD:
                    return *(int64_t*)&un->name;

                case cv_type::LF_UQUADWORD:
                    return *(uint64_t*)&un->name;

                default:
                    throw formatted_error("Could not parse union length type {}\n", (cv_type)un->length);
            }
        }

        default:
            throw formatted_error("Could not find size of {} type {:x}\n", *(cv_type*)t.data(), type);
    }
}

string pdb::arg_list_to_string(uint32_t arg_list) {
    if (arg_list < h.type_index_begin || arg_list >= h.type_index_end)
        throw formatted_error("Arg list type {:x} was out of bounds.", arg_list);

    const auto& t = types[arg_list - h.type_index_begin];

    if (t.size() < sizeof(cv_type))
        throw formatted_error("Arg list {:x} was truncated.", arg_list);

    if (*(cv_type*)t.data() != cv_type::LF_ARGLIST)
        throw formatted_error("LF_PROCEDURE pointed to {}, expected LF_ARGLIST.", *(cv_type*)t.data());

    if (t.size() < offsetof(lf_arglist, args))
        throw formatted_error("Arg list {:x} was truncated.", arg_list);

    const auto& al = *(lf_arglist*)t.data();

    if (t.size() < offsetof(lf_arglist, args) + (sizeof(uint32_t) * al.num_entries))
        throw formatted_error("Arg list {:x} was truncated.", arg_list);

    string s;

    for (uint32_t i = 0; i < al.num_entries; i++) {
        if (i != 0)
            s += ", ";

        auto n = al.args[i];

        if (n < h.type_index_begin) {
            s += builtin_type(n);
            continue;
        }

        if (n >= h.type_index_end)
            throw formatted_error("Argument type {:x} was out of bounds.", n);

        const auto& t2 = types[n - h.type_index_begin];

        s += format_member(t2, "" ,"");
    }

    return s;
}

static bool is_name_anonymous(string_view name) {
    if (name == "<unnamed-tag>")
        return true;

    if (name == "__unnamed")
        return true;

    if (name == "<anonymous-tag>")
        return true;

    auto tag1 = "::<unnamed-tag>"sv;
    auto tag2 = "::__unnamed"sv;
    auto tag3 = "::<anonymous-tag>"sv;

    if (name.size() >= tag1.size() && name.substr(name.size() - tag1.size()) == tag1)
        return true;

    if (name.size() >= tag2.size() && name.substr(name.size() - tag2.size()) == tag2)
        return true;

    if (name.size() >= tag3.size() && name.substr(name.size() - tag3.size()) == tag3)
        return true;

    return false;
}

string pdb::format_member(span<const uint8_t> mt, string_view name, string_view prefix) {
    if (mt.size() >= sizeof(cv_type)) {
        switch (*(cv_type*)mt.data()) {
            case cv_type::LF_ARRAY: {
                const auto* arr = (lf_array*)mt.data();

                if (mt.size() < offsetof(lf_array, name))
                    throw formatted_error("Truncated LF_ARRAY ({} bytes, expected at least {})", mt.size(), offsetof(lf_array, name));

                string name2{name};
                size_t num_els = array_length(*arr) / get_type_size(arr->element_type);

                name2 += "[" + to_string(num_els) + "]";

                do {
                    if (arr->element_type < h.type_index_begin)
                        return fmt::format("{} {}", builtin_type(arr->element_type), name2);

                    if (arr->element_type >= h.type_index_end)
                        throw formatted_error("Array element type {:x} was out of bounds.", arr->element_type);

                    const auto& mt2 = types[arr->element_type - h.type_index_begin];

                    if (mt2.size() < sizeof(cv_type) || *(cv_type*)mt2.data() != cv_type::LF_ARRAY)
                        return format_member(mt2, name2, prefix);

                    arr = (lf_array*)mt2.data();

                    num_els = array_length(*arr) / get_type_size(arr->element_type);

                    name2 += "[" + to_string(num_els) + "]";
                } while (true);
            }

            case cv_type::LF_BITFIELD: {
                const auto& bf = *(lf_bitfield*)mt.data();

                if (mt.size() < sizeof(lf_bitfield))
                    throw formatted_error("Truncated LF_BITFIELD ({} bytes, expected {})", mt.size(), sizeof(lf_bitfield));

                if (bf.base_type < h.type_index_begin)
                    return fmt::format("{} {} : {}", builtin_type(bf.base_type), name, bf.length);

                if (bf.base_type >= h.type_index_end)
                    throw formatted_error("Bitfield base type {:x} was out of bounds.", bf.base_type);

                const auto& mt2 = types[bf.base_type - h.type_index_begin];

                return fmt::format("{} {} : {}", type_name(mt2), name, bf.length);
            }

            case cv_type::LF_POINTER: {
                // handle procedure pointers

                if (mt.size() < sizeof(lf_pointer))
                    break;

                const auto& ptr = *(lf_pointer*)mt.data();

                if (ptr.base_type < h.type_index_begin)
                    break;

                if (ptr.base_type >= h.type_index_end)
                    break;

                const auto* mt2 = &types[ptr.base_type - h.type_index_begin];
                unsigned int depth = 1;

                do {
                    if (mt2->size() < sizeof(cv_type))
                        break;

                    if (*(cv_type*)mt2->data() == cv_type::LF_PROCEDURE) {
                        if (mt2->size() < sizeof(lf_procedure))
                            throw formatted_error("Truncated LF_PROCEDURE ({} bytes, expected {})", mt2->size(), sizeof(lf_procedure));

                        const auto& proc = *(lf_procedure*)mt2->data();

                        string ret;

                        if (proc.return_type < h.type_index_begin)
                            ret = builtin_type(proc.return_type);
                        else {
                            if (proc.return_type >= h.type_index_end)
                                throw formatted_error("Procedure return type {:x} was out of bounds.", proc.return_type);

                            const auto& rt = types[proc.return_type - h.type_index_begin];

                            ret = format_member(rt, "", prefix);
                        }

                        return fmt::format("{} ({:*>{}}{})({})", ret, "", depth, name, arg_list_to_string(proc.arglist));
                    } else if (*(cv_type*)mt2->data() == cv_type::LF_POINTER) {
                        depth++;

                        if (mt2->size() < sizeof(lf_pointer))
                            break;

                        const auto& ptr = *(lf_pointer*)mt2->data();

                        if (ptr.base_type < h.type_index_begin)
                            break;

                        if (ptr.base_type >= h.type_index_end)
                            break;

                        mt2 = &types[ptr.base_type - h.type_index_begin];
                    } else
                        break;
                } while (true);

                break;
            }

            case cv_type::LF_UNION: {
                if (mt.size() < offsetof(lf_union, name))
                    break;

                const auto& un = *(lf_union*)mt.data();

                if (!is_name_anonymous(union_name(mt)))
                    break;

                if (un.field_list < h.type_index_begin || un.field_list >= h.type_index_end)
                    break;

                const auto& fl = types[un.field_list - h.type_index_begin];

                auto s = fmt::format("union {{\n");

                string prefix2{prefix};

                prefix2 += "    ";

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
                        s += fmt::format("{}{} {};\n", prefix2, builtin_type(mem.type), name);
                        return;
                    }

                    if (mem.type >= h.type_index_end)
                        throw formatted_error("Member type {:x} was out of bounds.", mem.type);

                    const auto& mt = types[mem.type - h.type_index_begin];

                    s += fmt::format("{}{};\n", prefix2, format_member(mt, name, prefix2));
                });

                s += fmt::format("{}}} {}", prefix, name);

                return s;
            }

            case cv_type::LF_STRUCTURE:
            case cv_type::LF_CLASS: {
                if (mt.size() < offsetof(lf_class, name))
                    break;

                const auto& str = *(lf_class*)mt.data();

                if (!is_name_anonymous(struct_name(mt)))
                    break;

                if (str.field_list < h.type_index_begin || str.field_list >= h.type_index_end)
                    break;

                const auto& fl = types[str.field_list - h.type_index_begin];

                auto s = fmt::format("struct {{\n");

                string prefix2{prefix};

                prefix2 += "    ";

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
                        s += fmt::format("{}{} {};\n", prefix2, builtin_type(mem.type), name);
                        return;
                    }

                    if (mem.type >= h.type_index_end)
                        throw formatted_error("Member type {:x} was out of bounds.", mem.type);

                    const auto& mt = types[mem.type - h.type_index_begin];

                    s += fmt::format("{}{};\n", prefix2, format_member(mt, name, prefix2));
                });

                s += fmt::format("{}}} {}", prefix, name);

                return s;
            }

            default:
                break;
        }
    }

    if (name.empty())
        return type_name(mt);
    else
        return fmt::format("{} {}", type_name(mt), name);
}

void pdb::add_asserts(const union_or_struct auto& d, string_view name, uint64_t off, vector<sa>& asserts) {
    if (d.field_list < h.type_index_begin || d.field_list >= h.type_index_end)
        throw formatted_error("Field list {:x} was out of bounds.", d.field_list);

    const auto& fl = types[d.field_list - h.type_index_begin];

    walk_fieldlist(fl, [&](span<const uint8_t> d) {
        const auto& mem = *(lf_member*)d.data();

        if (mem.kind != cv_type::LF_MEMBER)
            return;

        string mem_name{member_name(d)};

        if (mem.type < h.type_index_begin) {
            asserts.emplace_back(string{name} + "."s + mem_name, off + member_offset(d));
            return;
        }

        if (mem.type >= h.type_index_end)
            throw formatted_error("Member type {:x} was out of bounds.", mem.type);

        const auto& mt = types[mem.type - h.type_index_begin];

        if (mt.size() >= sizeof(cv_type)) {
            switch (*(cv_type*)mt.data()) {
                case cv_type::LF_BITFIELD:
                    return;

                case cv_type::LF_STRUCTURE:
                case cv_type::LF_CLASS: {
                    if (!is_name_anonymous(struct_name(mt))) {
                        asserts.emplace_back(string{name} + "."s + mem_name, off + member_offset(d));
                        break;
                    }

                    const auto& str = *(lf_class*)mt.data();

                    add_asserts(str, string{name} + "."s + mem_name, off + member_offset(d), asserts);

                    break;
                }

                case cv_type::LF_UNION: {
                    if (!is_name_anonymous(union_name(mt))) {
                        asserts.emplace_back(string{name} + "."s + mem_name, off + member_offset(d));
                        return;
                    }

                    const auto& un = *(lf_union*)mt.data();

                    add_asserts(un, string{name} + "."s + mem_name, off + member_offset(d), asserts);

                    break;
                }

                default:
                    asserts.emplace_back(string{name} + "."s + mem_name, off + member_offset(d));
                    return;
            }
        }
    });
}

void pdb::print_struct(span<const uint8_t> t) {
    struct memb {
        memb(string_view str, string_view name, uint64_t off, bool bitfield) :
            str(str), name(name), off(off), bitfield(bitfield) { }

        string str;
        string name;
        uint64_t off;
        bool bitfield;
    };

    if (t.size() < offsetof(lf_class, name))
        throw formatted_error("Truncated LF_STRUCTURE / LF_CLASS ({} bytes, expected at least {})", t.size(), offsetof(lf_class, name));

    const auto& str = *(lf_class*)t.data();

    // ignore forward declarations
    if (str.properties & CV_PROP_FORWARD_REF)
        return;

    if (is_name_anonymous(struct_name(t)))
        return;

    if (str.field_list < h.type_index_begin || str.field_list >= h.type_index_end)
        throw formatted_error("Struct field list {:x} was out of bounds.", str.field_list);

    // FIXME - derived_from
    // FIXME - vshape

    const auto& fl = types[str.field_list - h.type_index_begin];

    auto name = struct_name(t);

    vector<memb> members;
    vector<sa> asserts;

    // FIXME - "class" instead if LF_CLASS
    fmt::print("struct {} {{\n", name);

    walk_fieldlist(fl, [&](span<const uint8_t> d) {
        const auto& mem = *(lf_member*)d.data();

        if (mem.kind != cv_type::LF_MEMBER)
            return;

        auto name = member_name(d);
        auto off = member_offset(d) * 8;

        if (mem.type < h.type_index_begin) {
            members.emplace_back(fmt::format("    {} {};", builtin_type(mem.type), name), name, off, false);
            asserts.emplace_back(name, off / 8);
            return;
        }

        if (mem.type >= h.type_index_end)
            throw formatted_error("Member type {:x} was out of bounds.", mem.type);

        const auto& mt = types[mem.type - h.type_index_begin];
        bool bitfield = false;

        if (mt.size() >= sizeof(cv_type)) {
            switch (*(cv_type*)mt.data()) {
                case cv_type::LF_BITFIELD: {
                    const auto& bf = *(lf_bitfield*)mt.data();

                    off += bf.position;
                    bitfield = true;
                    break;
                }

                case cv_type::LF_STRUCTURE:
                case cv_type::LF_CLASS: {
                    if (!is_name_anonymous(struct_name(mt))) {
                        asserts.emplace_back(name, off / 8);
                        break;
                    }

                    const auto& str = *(lf_class*)mt.data();

                    add_asserts(str, name, off / 8, asserts);

                    break;
                }

                case cv_type::LF_UNION: {
                    if (!is_name_anonymous(union_name(mt))) {
                        asserts.emplace_back(name, off / 8);
                        break;
                    }

                    const auto& un = *(lf_union*)mt.data();

                    add_asserts(un, name, off / 8, asserts);

                    break;
                }

                default:
                    asserts.emplace_back(name, off / 8);
                    break;
            }
        }

        members.emplace_back(fmt::format("    {};", format_member(mt, name, "    ")), name, off, bitfield);
    });

    for (auto it = members.begin(); it != members.end(); it++) {
        if (next(it) != members.end() && next(it)->off == it->off) {
            fmt::print("    union {{\n");

            while (true) {
                fmt::print("    {}\n", it->str);

                if (next(it) != members.end() && next(it)->off == it->off)
                    it++;
                else
                    break;
            }

            fmt::print("    }};\n");
        } else
            fmt::print("{}\n", it->str);
    }

    fmt::print("}};\n\n");

    fmt::print("static_assert(sizeof({}) == 0x{:x});\n", name, struct_length(t));

    for (const auto& a : asserts) {
        fmt::print("static_assert(offsetof({}, {}) == 0x{:x});\n", name, a.name, a.off);
    }

    fmt::print("\n");
}

void pdb::print_union(span<const uint8_t> t) {
    if (t.size() < offsetof(lf_union, name))
        throw formatted_error("Truncated LF_UNION ({} bytes, expected at least {})", t.size(), offsetof(lf_union, name));

    const auto& un = *(lf_union*)t.data();

    // ignore forward declarations
    if (un.properties & CV_PROP_FORWARD_REF)
        return;

    if (is_name_anonymous(union_name(t)))
        return;

    if (un.field_list < h.type_index_begin || un.field_list >= h.type_index_end)
        throw formatted_error("Union field list {:x} was out of bounds.", un.field_list);

    // FIXME - static_asserts (sizeof, offsetof)

    const auto& fl = types[un.field_list - h.type_index_begin];

    auto name = union_name(t);

    vector<pair<string, uint64_t>> members;

    fmt::print("union {} {{\n", name);

    walk_fieldlist(fl, [&](span<const uint8_t> d) {
        const auto& mem = *(lf_member*)d.data();

        if (mem.kind != cv_type::LF_MEMBER)
            return;

        auto name = member_name(d);
        auto off = member_offset(d) * 8;

        if (mem.type < h.type_index_begin) {
            members.emplace_back(fmt::format("    {} {};", builtin_type(mem.type), name), off);
            return;
        }

        if (mem.type >= h.type_index_end)
            throw formatted_error("Member type {:x} was out of bounds.", mem.type);

        const auto& mt = types[mem.type - h.type_index_begin];

        if (mt.size() >= sizeof(lf_bitfield) && *(cv_type*)mt.data() == cv_type::LF_BITFIELD) {
            const auto& bf = *(lf_bitfield*)mt.data();

            off += bf.position;
        }

        members.emplace_back(fmt::format("    {};", format_member(mt, name, "    ")), off);
    });

    // FIXME - bitfields in implicit structs
    // FIXME - unions within implicit structs?

    for (auto it = members.begin(); it != members.end(); it++) {
        if (next(it) != members.end() && next(it)->second != 0) {
            fmt::print("    struct {{\n");

            while (true) {
                fmt::print("    {}\n", it->first);

                if (next(it) != members.end() && next(it)->second != 0)
                    it++;
                else
                    break;
            }

            fmt::print("    }};\n");
        } else
            fmt::print("{}\n", it->first);
    }

    fmt::print("}};\n\n");
}

void pdb::extract_types() {
    if (bfd_seek(types_stream, 0, SEEK_SET))
        throw formatted_error("bfd_seek failed ({})", bfd_errmsg(bfd_get_error()));

    if (bfd_bread(&h, sizeof(h), types_stream) != sizeof(h))
        throw formatted_error("bfd_bread failed ({})", bfd_errmsg(bfd_get_error()));

    if (h.version != TPI_STREAM_VERSION_80)
        throw formatted_error("Type stream version was {}, expected {}.", h.version, TPI_STREAM_VERSION_80);

    if (bfd_seek(types_stream, h.header_size, SEEK_SET))
        throw formatted_error("bfd_seek failed ({})", bfd_errmsg(bfd_get_error()));

    type_records.resize(h.type_record_bytes);

    if (bfd_bread(type_records.data(), type_records.size(), types_stream) != type_records.size())
        throw formatted_error("bfd_bread failed ({})", bfd_errmsg(bfd_get_error()));

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

                case cv_type::LF_UNION:
                    print_union(t);
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

static vector<uint8_t> read_image_rsds(bfd* b) {
    IMAGE_DOS_HEADER dh;
    IMAGE_NT_HEADERS pe;

    struct map_ctx {
        const IMAGE_DATA_DIRECTORY* dd;
        uint64_t base;
        exception_ptr exc;
        vector<uint8_t> dir;
    };

    if (bfd_seek(b, 0, SEEK_SET))
        throw formatted_error("bfd_seek failed ({})", bfd_errmsg(bfd_get_error()));

    if (bfd_bread(&dh, sizeof(dh), b) != sizeof(dh))
        throw formatted_error("bfd_bread failed ({})", bfd_errmsg(bfd_get_error()));

    if (dh.e_magic != IMAGE_DOS_SIGNATURE)
        throw formatted_error("e_magic was {:04x}, expected {:04x}", dh.e_magic, IMAGE_DOS_SIGNATURE);

    if (bfd_seek(b, dh.e_lfanew, SEEK_SET))
        throw formatted_error("bfd_seek failed ({})", bfd_errmsg(bfd_get_error()));

    if (bfd_bread(&pe, sizeof(pe), b) != sizeof(pe))
        throw formatted_error("bfd_bread failed ({})", bfd_errmsg(bfd_get_error()));

    if (pe.Signature != IMAGE_NT_SIGNATURE)
        throw formatted_error("PE Signature was {:08x}, expected {:08x}", pe.Signature, IMAGE_NT_SIGNATURE);

    map_ctx ctx;
    span<const IMAGE_DATA_DIRECTORY> dirs;

    if (pe.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        dirs = span(pe.OptionalHeader32.DataDirectory, pe.OptionalHeader32.NumberOfRvaAndSizes);
        ctx.base = pe.OptionalHeader32.ImageBase;
    } else if (pe.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        dirs = span(pe.OptionalHeader64.DataDirectory, pe.OptionalHeader64.NumberOfRvaAndSizes);
        ctx.base = pe.OptionalHeader64.ImageBase;
    } else
        throw formatted_error("PE Magic was {:04x}, expected {:04x} or {:04x}", pe.OptionalHeader32.Magic,
                              IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    if (dirs.size() <= IMAGE_DIRECTORY_ENTRY_DEBUG)
        throw runtime_error("Image did not contain a IMAGE_DIRECTORY_ENTRY_DEBUG directory.");

    const auto& dd = dirs[IMAGE_DIRECTORY_ENTRY_DEBUG];

    if (dd.Size == 0)
        throw runtime_error("Image did not contain a IMAGE_DIRECTORY_ENTRY_DEBUG directory.");

    ctx.dd = &dd;

    bfd_map_over_sections(b, [](bfd* b, asection* sect, void* obj) {
        auto& ctx = *(map_ctx*)obj;

        if (ctx.exc || !ctx.dir.empty())
            return;

        try {
            if (sect->vma > ctx.base + ctx.dd->VirtualAddress)
                return;

            if (sect->vma + sect->size <= ctx.base + ctx.dd->VirtualAddress)
                return;

            ctx.dir.resize(ctx.dd->Size);

            bfd_byte* data = nullptr;

            if (!bfd_get_full_section_contents(b, sect, &data))
                throw formatted_error("bfd_get_full_section_contents failed ({})", bfd_errmsg(bfd_get_error()));

            memcpy(ctx.dir.data(), data + ctx.dd->VirtualAddress + ctx.base - sect->vma, ctx.dd->Size);

            free(data);
        } catch (...) {
            ctx.exc = current_exception();
        }
    }, &ctx);

    if (ctx.exc)
        rethrow_exception(ctx.exc);

    span<const IMAGE_DEBUG_DIRECTORY> dbginfo;
    const IMAGE_DEBUG_DIRECTORY* cvinfo = nullptr;

    dbginfo = span((IMAGE_DEBUG_DIRECTORY*)ctx.dir.data(), ctx.dir.size() / sizeof(IMAGE_DEBUG_DIRECTORY));

    for (const auto& d : dbginfo) {
        if (d.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
            continue;

        cvinfo = &d;
        break;
    }

    if (!cvinfo)
        throw runtime_error("Image does not contain CodeView debug information.");

    if (bfd_seek(b, cvinfo->PointerToRawData, SEEK_SET))
        throw formatted_error("bfd_seek failed ({})", bfd_errmsg(bfd_get_error()));

    vector<uint8_t> rsds;

    rsds.resize(cvinfo->SizeOfData);

    if (bfd_bread(rsds.data(), rsds.size(), b) != rsds.size())
        throw formatted_error("bfd_bread failed ({})", bfd_errmsg(bfd_get_error()));

    return rsds;
}

static filesystem::path xdg_cache_dir() {
    if (auto s = getenv("XDG_CACHE_HOME"))
        return s;

    auto s = getenv("HOME");

    if (!s)
        throw runtime_error("HOME environment variable not set.");

    auto p = filesystem::path{s};

    p /= ".cache";

    return p;
}

static size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto& h = *(ofstream*)userdata;

    h.write(ptr, size * nmemb);

    return size * nmemb;
}

static void download_file(const string& url, const filesystem::path& dest) {
    CURL* curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    try {
        curl = curl_easy_init();

        if (!curl)
            throw runtime_error("Failed to initialize cURL.");

        try {
            long error_code;

            {
                ofstream h(dest, ios::binary);

                if (!h.good())
                    throw formatted_error("Could not open {} for writing.", dest.string());

                h.exceptions(ofstream::failbit | ofstream::badbit);

                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); // everything that libcurl supports

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &h);

                res = curl_easy_perform(curl);

                if (res != CURLE_OK)
                    throw runtime_error(curl_easy_strerror(res));
            }

            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &error_code); // FIXME - only do if HTTP or HTTPS?

            if (error_code >= 400)
                throw formatted_error("HTTP error {}", error_code);
        } catch (...) {
            curl_easy_cleanup(curl);
            throw;
        }

        curl_easy_cleanup(curl);
    } catch (...) {
        curl_global_cleanup();
        throw;
    }

    curl_global_cleanup();
}

static bfdup load_pdb(span<const uint8_t, 16> sig, uint32_t age, string_view name) {
    auto hexstr = fmt::format("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                              sig[3], sig[2], sig[1], sig[0], sig[5], sig[4], sig[7], sig[6],
                              sig[8], sig[9], sig[10], sig[11], sig[12], sig[13], sig[14], sig[15], age);

    auto cache_dir = xdg_cache_dir() / "pdb";

    if (!filesystem::exists(cache_dir)) {
        if (!filesystem::create_directory(cache_dir))
            throw formatted_error("Failed to create directory {}.", cache_dir.string());
    }

    auto fn = cache_dir / name / hexstr / name;

    if (filesystem::exists(fn)) {
        fmt::print(stderr, "Using cached file at {}\n", fn.string());

        auto pdb = bfd_openr(fn.string().c_str(), nullptr);

        if (!pdb)
            throw formatted_error("Could not load PDB file {} ({}).", fn.string(), bfd_errmsg(bfd_get_error()));

        return bfdup{pdb};
    }

    filesystem::create_directories(cache_dir / name / hexstr);

    auto url = fmt::format("https://msdl.microsoft.com/download/symbols/{}/{}/{}",
                           name, hexstr, name);

    fmt::print(stderr, "Trying to download from {}\n", url);

    download_file(url, fn);

    fmt::print(stderr, "Saved to {}\n", fn.string());

    auto pdb = bfd_openr(fn.string().c_str(), nullptr);

    if (!pdb)
        throw formatted_error("Could not load PDB file {} ({}).", fn.string(), bfd_errmsg(bfd_get_error()));

    return bfdup{pdb};
}

static void load_file(const string& fn) {
    bfdup b;

    {
        auto arch = bfd_openr(fn.c_str(), nullptr);

        if (!arch)
            throw formatted_error("Could not load PDB file {} ({}).", fn, bfd_errmsg(bfd_get_error()));

        b.reset(arch);
    }

    if (bfd_check_format(b.get(), bfd_object)) {
        auto vec = read_image_rsds(b.get());

        if (vec.size() < offsetof(CV_INFO_PDB70, PdbFileName))
            throw formatted_error("CV debug info was {} bytes, expected at least {}.", vec.size(), offsetof(CV_INFO_PDB70, PdbFileName));

        const auto& rsds = *(CV_INFO_PDB70*)vec.data();

        if (rsds.CvSignature != CVINFO_PDB70_CVSIGNATURE)
            throw formatted_error("CV signature was {:x}, expected {:x}.", rsds.CvSignature, CVINFO_PDB70_CVSIGNATURE);

        auto name = string_view(rsds.PdbFileName, vec.size() - offsetof(CV_INFO_PDB70, PdbFileName));

        if (auto st = name.find('\0'); st != string::npos)
            name = name.substr(0, st);

        auto pdb = load_pdb(rsds.Signature, rsds.Age, name);

        if (bfd_check_format(pdb.get(), bfd_archive))
            b.swap(pdb);
    }

    if (!bfd_check_format(b.get(), bfd_archive))
        throw formatted_error("bfd_check_format failed ({})", bfd_errmsg(bfd_get_error()));

    // FIXME - check format is PDB

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

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            fmt::print(stderr, "Usage: pdbout <PDB file>\n");
            fmt::print(stderr, "Usage: pdbout <PE image>\n");
            return 1;
        }

        auto fn = string{argv[1]};

        load_file(fn);
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
