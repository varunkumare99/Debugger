#include <algorithm>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "Registers.hpp"
#include "Utility.hpp"

namespace Registers {
    uint64_t get_register_value(pid_t pid, reg r) {
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
            Debug_Utility::printError("PTRACE_GETREGS get error");
        }

        // the position of reg r in the g_register_descriptors array
        auto itr = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [r] (auto&&rd) { return rd.register_reg == r; });
        auto itr_offset = itr - g_register_descriptors.begin();

        // return the reg r value from regs struct
        return *(reinterpret_cast<uint64_t*>(&regs) + itr_offset);
    }

    void set_register_value(pid_t pid, reg r, uint64_t value) {
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
            Debug_Utility::printError("PTRACE_GETREGS set error");
        }

        // the position of reg r in the g_register_descriptors array
        auto itr = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [r] (auto&&rd) { return rd.register_reg == r; });
        auto itr_offset = itr - g_register_descriptors.begin();

        // set the value of the reg r in regs struct
        *(reinterpret_cast<uint64_t*>(&regs) + itr_offset) = value;
        if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
            Debug_Utility::printError("PTRACE_SETREGS error");
        }
    }

    uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regNum) {
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
            Debug_Utility::printError("PTRACE_GETREGS dwarf reg error");
        }
        // the position of reg r in the g_register_descriptors array
        auto itr = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [regNum] (auto&&rd) { return rd.dwarf_r == regNum; });
        if (itr == g_register_descriptors.end()) {
            throw std::out_of_range {"unknown dwarf register"};
        }

        return get_register_value(pid, itr->register_reg); 
    }


    std::string get_register_name(reg r) {
        // the position of reg r in the g_register_descriptors array
        auto itr = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [r] (auto&&rd) { return rd.register_reg == r; });

        if (itr == g_register_descriptors.end()) {
            throw std::out_of_range {"unknown register"};
        }

        return itr->reg_name;
    }

    reg get_register_from_name(const std::string& name) {
        // the position of reg r in the g_register_descriptors array
        auto itr = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [name] (auto&&rd) { return rd.reg_name == name; });
        
        if (itr == g_register_descriptors.end()) {
            throw std::out_of_range {"unknown register"};
        }

        return itr->register_reg;
    }
};
