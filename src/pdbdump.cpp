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

    {
        auto arch = bfd_openr(fn.c_str(), "pdb");

        // FIXME - show BFD error in exception

        if (!arch)
            throw runtime_error("Could not load PDB file " + fn + ".");

        b.reset(arch);
    }

    printf("arch = %p\n", b.get());
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
