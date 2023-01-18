#include <iostream>
#include <vector>
#include "pdbdump.h"

using namespace std;

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

    // FIXME - allocate buffers for types
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
