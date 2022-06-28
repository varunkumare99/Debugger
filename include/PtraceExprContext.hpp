#include "dwarf/dwarf++.hh"
class PtraceExprContext : public dwarf::expr_context {
    public:
        PtraceExprContext (pid_t pid, uint64_t load_address) : m_pid {pid}, m_load_address{load_address} {}
        dwarf::taddr reg(unsigned regnum) override;
        dwarf::taddr pc() override;
        dwarf::taddr deref_size (dwarf::taddr address, unsigned size) override;
    private:
        pid_t m_pid;
        uint64_t m_load_address;
};
