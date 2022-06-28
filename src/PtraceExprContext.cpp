#include <sys/ptrace.h>
#include <sys/user.h>
#include "PtraceExprContext.hpp"
#include "Registers.hpp"
#include "dwarf/data.hh"
#include "Utility.hpp"

dwarf::taddr PtraceExprContext::reg(unsigned regnum){
    return Registers::get_register_value_from_dwarf_register(m_pid, regnum);
}

dwarf::taddr PtraceExprContext::pc() {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs) == -1) {
        Debug_Utility::printError("PTRACE_GETREGS get error");
    }
    return regs.rip -  m_load_address;
}

dwarf::taddr PtraceExprContext::deref_size (dwarf::taddr address, unsigned size) {
    //TODO
    return ptrace(PTRACE_PEEKDATA, m_pid, address + m_load_address, nullptr); 
}
