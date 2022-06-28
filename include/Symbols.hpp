#include <iostream>
#include <elf/elf++.hh>
namespace Symbols {
    enum class symbol_type {
        notype,     // No type (e.g: absolute symbol)
        object,     // Data object
        func,       // Function entry point
        section,    // Symbol is associated with a section
        file,       // Source file associated with the object file
    };


    struct symbol {
        symbol_type type;
        std::string name;
        std::uintptr_t addr;
    };

    std::string to_string(symbol_type st);
    symbol_type to_symbol_type(elf::stt symbol);
};
