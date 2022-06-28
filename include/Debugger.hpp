#include <unordered_map>
#include <vector>
#include <iostream>
#include <fcntl.h>
#include <signal.h>

#include "elf/elf++.hh"
#include "dwarf/dwarf++.hh"
#include "Breakpoint.hpp"
#include "Symbols.hpp"

namespace MiniDebugger {
    class Debugger {
        public:
            Debugger (std::string progName, pid_t child_pid) 
                :m_progName{std::move(progName)}, m_pid{child_pid} {
                    auto fd = open(m_progName.c_str(), O_RDONLY);
                    m_elf = elf::elf {elf::create_mmap_loader(fd)};
                    m_dwarf = dwarf::dwarf{ dwarf::elf::create_loader(m_elf)};
                }

            void run();
            void handle_command(const std::string& line);
            void continue_execution();
            void set_breakpoint_at_address(std::intptr_t addr);
            void dump_registers();
            uint64_t read_memory(uint64_t address);
            void write_memory(uint64_t address, uint64_t values);
            void step_over_breakpoint();
            void single_step_instruction_with_breakpoint_check();
            void step_out();
            void step_in();
            void step_over();
            void set_breakpoint_at_function(const std::string& funcName);
            void set_breakpoint_at_source_line(const std::string& file, unsigned line);
            std::vector<Symbols::symbol> lookup_symbol(const std::string& name);
            void print_backtrace();
            void read_variables();
            void print_available_commands();

        private:
            uint64_t get_pc();
            void set_pc(uint64_t pc);
            void wait_for_signal();
            dwarf::die get_function_from_pc(uint64_t pc);
            dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
            void initialise_load_address();
            uint64_t offset_load_address(uint64_t addr);
            void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context=2);
            siginfo_t get_signal_info();
            void handle_sigtrap(siginfo_t sigInfo);
            void single_step_instruction();
            void remove_breakpoint(std::intptr_t addr);
            uint64_t get_offset_pc();
            uint64_t offset_dwarf_address(uint64_t addr);

            std::string m_progName;
            pid_t m_pid;
            std::unordered_map<std::intptr_t, Breakpoint> m_breakpoints;
            dwarf::dwarf m_dwarf;
            elf::elf m_elf;
            uint64_t m_load_address;
    };

}
