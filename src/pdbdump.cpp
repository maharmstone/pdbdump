#include <string>
#include <memory>
#include <iostream>
#include <bfd.h>

using namespace std;

class bfd_closer {
public:
    using pointer = bfd*;

    void operator()(bfd* b) {
        if (b)
            bfd_close(b);
    }
};

using bfdup = unique_ptr<bfd*, bfd_closer>;

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

    printf("arch = %p, types_stream = %p\n", b.get(), types_stream);
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
