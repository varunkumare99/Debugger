#include <sys/ptrace.h>
#include "Breakpoint.hpp"
#include "Utility.hpp"

void Breakpoint::enable() {
    uint64_t inst_at_breakpoint;
    if ((inst_at_breakpoint = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr)) == -1){
        Debug_Utility::printError("PTRACE_PEEKDATA error");
    }

    // we need to replace the first byte with int3 (0xcc)
    // since x86 is little endian we replace the last byte
    m_saved_data = static_cast<uint8_t> (inst_at_breakpoint & 0xff); //save the bottom byte

    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((inst_at_breakpoint & ~0xff) | int3);

    if (ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3) == -1){
        Debug_Utility::printError("PTRACE_POKEDATA error");
    }

    m_enabled = true;
}

void Breakpoint::disable() {
    uint64_t data;
    if ((data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr)) == -1){
        Debug_Utility::printError("PTRACE_POKEDATA error");
    }

    auto restore_data = ((data & ~0xff) | m_saved_data); //restore the saved byte at bottom

    if (ptrace(PTRACE_POKEDATA, m_pid, m_addr, restore_data) == -1){
        Debug_Utility::printError("PTRACE_POKEDATA error");
    }
}

