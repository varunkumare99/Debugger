#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <iomanip>
#include <string>
#include <vector>
#include "dwarf/dwarf++.hh"
#include "linenoise.h"
#include "Debugger.hpp"
#include "Registers.hpp"
#include "PtraceExprContext.hpp"
#include "Utility.hpp"

namespace MiniDebugger {
    void Debugger::run() {
        //wait after child executed execl
        wait_for_signal();

        initialise_load_address();
        char* line = nullptr;
        std::cout << "\nType help to get list of available commands\n\n";
        while ((line = linenoise("minidbg> ")) != nullptr) {
            handle_command(line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
        }
    }

    void Debugger::handle_command(const std::string& line) {
        auto args = Debug_Utility::split(line, ' ');
        auto command = args[0];

        if (Debug_Utility::is_prefix(command, "continue")) {
            continue_execution();
        }

        else if (Debug_Utility::is_prefix(command, "register")) {
            if (Debug_Utility::is_prefix(args[1], "dump")) {
                dump_registers();
            }
            else if (Debug_Utility::is_prefix(args[1], "read")) {
                std::cout << "0x" << std::hex << Registers::get_register_value(m_pid, Registers::get_register_from_name(args[2])) << std::endl;
            }
            else if (Debug_Utility::is_prefix(args[1], "write")) {
                std::string val {args[3], 2}; //assume 0xVal
                Registers::set_register_value(m_pid, Registers::get_register_from_name(args[2]), std::stol(val, 0, 16));
            }
        }

        else if (Debug_Utility::is_prefix(command, "memory")) {
            std::string addr {args[2], 2}; //assume 0xADDRESS

            if (Debug_Utility::is_prefix(args[1], "read")) {
                std::cout << "0x" << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
            }

            else if (Debug_Utility::is_prefix(args[1], "write")) {
                std::string val {args[3], 2}; //assume 0xVAL
                write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
            }
        }

        else if (Debug_Utility::is_prefix(command, "stepi")) {
            single_step_instruction_with_breakpoint_check();
            auto line_entry = get_line_entry_from_pc(get_offset_pc());
            print_source(line_entry->file->path, line_entry->line);
        }

        else if (Debug_Utility::is_prefix(command, "step")) {
            step_in();
        }

        else if (Debug_Utility::is_prefix(command, "next")) {
            step_over();
        }

        else if (Debug_Utility::is_prefix(command, "finish")) {
            step_out();
        }

        else if (Debug_Utility::is_prefix(command, "break")) {
            if (args[1][0] == '0' && args[1][1] == 'x') {
                std::string address{args[1], 2};
                set_breakpoint_at_address(std::stol(address, 0, 16));
            }
            else if (args[1].find(':') != std::string::npos) {
                auto file_and_line = Debug_Utility::split(args[1], ':');
                set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
            }
            else {
                set_breakpoint_at_function(args[1]);
            }
        }

        else if (Debug_Utility::is_prefix(command, "symbol")) {
            auto symbols = lookup_symbol(args[1]);
            for (auto&& currSym: symbols){
                std::cout << currSym.name << " " << to_string(currSym.type) << " 0x" << std::hex << currSym.addr << std::endl;
            }
        }

        else if (Debug_Utility::is_prefix(command, "backtrace")) {
            print_backtrace();
        }

        else if (Debug_Utility::is_prefix(command, "variables")) {
            read_variables();
        }
        
        else if (Debug_Utility::is_prefix(command, "help")) {
            print_available_commands();
        }

        else {
            std::cerr << "unknown command\n";
        }
    }

    void Debugger::continue_execution() {
        step_over_breakpoint();
        if (ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) == -1) {
            Debug_Utility::printError("PTRACE_CONT error");
        }
        wait_for_signal();
    }

    void Debugger::set_breakpoint_at_address(std::intptr_t addr) {
        std::cout << "Set breakpoint at address 0x"  << std::hex << addr << std::endl;
        Breakpoint breakpoint{m_pid, addr};
        breakpoint.enable();
        m_breakpoints.insert(std::make_pair(addr, breakpoint));
    }

    void Debugger::dump_registers() {
        for (const auto& rd: Registers::g_register_descriptors) {
            std::cout << rd.reg_name << " 0x" << std::setfill('0') << std::setw(16) << std::hex << Registers::get_register_value(m_pid, rd.register_reg) << std::endl;
        }
    }

    uint64_t Debugger::read_memory(uint64_t address) {
        uint64_t register_data;
        if ((register_data = ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr)) < 0) {
            Debug_Utility::printError("PTRACE_PEEKDATA error");
        }
        return register_data;
    }

    void Debugger::write_memory(uint64_t address, uint64_t value) {
        if (ptrace(PTRACE_POKEDATA, m_pid, address, value) < 0) {
            Debug_Utility::printError("PTRACE_POKEDATA error");
        }
    }

    uint64_t Debugger::get_pc() {
        return Registers::get_register_value(m_pid, Registers::reg::rip);
    }

    void Debugger::set_pc(uint64_t pc) {
        set_register_value(m_pid, Registers::reg::rip, pc);
    }


    void Debugger::step_over_breakpoint() {
        if (m_breakpoints.count(get_pc())) {
            auto& breakpoint = m_breakpoints.at(get_pc());

            if (breakpoint.is_enabled()) {
                // once disabled the int3 inst will be replaced by the previous saved instruction
                // execute the previous original instructrion and wait
                breakpoint.disable();
                if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) < 0) {
                    Debug_Utility::printError("PTRACE_SINGLESTEP error");
                }
                wait_for_signal();
                breakpoint.enable();
            }
        }
    }

    void Debugger::wait_for_signal() {
        int wait_status;
        auto options = 0;
        waitpid(m_pid, &wait_status, options);

        if (!WIFEXITED(wait_status)) {
            auto sigInfo = get_signal_info();

            switch (sigInfo.si_signo) {
                case SIGTRAP:
                    handle_sigtrap(sigInfo);
                    break;
                case SIGSEGV:
                    std::cout << "Segfault, Reason: " << sigInfo.si_code << std::endl;
                    break;
                default:
                    std::cout << "Got signal " << strsignal(sigInfo.si_signo)   << " sig value : " << sigInfo.si_signo<< std::endl;
            }
        }
        else {
            std::cout << "(process " << std::to_string(m_pid) << ") exited normally " << std::endl;
        }
    }

    //determine when SIGTRAP was generated on breakpoints or single step execution
    void Debugger::handle_sigtrap(siginfo_t sigInfo) {
        switch (sigInfo.si_code) {
            //one of these will be set if a breakpoint was hit
            case SI_KERNEL:
            case TRAP_BRKPT:
                {
                    set_pc(get_pc() - 1); //put the pc back  where it should be
                    std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << "\n\n";
                    auto line_entry = get_line_entry_from_pc(get_offset_pc());
                    print_source(line_entry->file->path, line_entry->line);
                    return;
                }
                //This will be set if the signal was sent by single stepping
            case TRAP_TRACE:
                return;
            default:
                std::cout << "Unknown SIGTRAP code " << sigInfo.si_code  << ", signal value : " << sigInfo.si_signo<< std::endl;
                return;
        }
    }


    /* check if pc is in compilation unit (iterate through all compilation units)
     * if true, check if pc is in any function in the compilation unit (iterate through all functions in the compilation unit)
     * return function when found, else throw error
     */
    dwarf::die Debugger::get_function_from_pc(uint64_t pc) {
        for (auto& compilation_unit : m_dwarf.compilation_units()) {
            if (die_pc_range(compilation_unit.root()).contains(pc)) {
                for (const auto& dwarf_info_entry : compilation_unit.root()) {
                    if (dwarf_info_entry.tag == dwarf::DW_TAG::subprogram) {
                        if (die_pc_range(dwarf_info_entry).contains(pc)) {
                            return dwarf_info_entry;
                        }
                    }
                }
            }
        }
        throw std::out_of_range{"cannot find function"};
    }

    /* check if pc is in compilation unit (iterate through all compilation units)
     * if true, check if pc is in the line table of the compilation unit 
     * return line entry address, else throw error
     */
    dwarf::line_table::iterator Debugger::get_line_entry_from_pc(uint64_t pc) {
        for (auto& compilation_unit : m_dwarf.compilation_units()) {
            if (die_pc_range(compilation_unit.root()).contains(pc)) {
                auto& line_table = compilation_unit.get_line_table();
                auto itr = line_table.find_address(pc);

                if (itr == line_table.end()) {
                    throw std::out_of_range {"Cannot find line entry in line table"};
                }
                else {
                    return itr;
                }
            }
        }
        throw std::out_of_range {"Cannot find line table"};
    }


    void Debugger::initialise_load_address() {
        //if this is a dynamic library 
        if (m_elf.get_hdr().type == elf::et::dyn) {
            // The load address is found in /proc/<pid>/maps
            std::ifstream procMaps("/proc/" + std::to_string(m_pid) + "/maps");

            // Read the first address from the file
            std::string addr;
            std::getline(procMaps, addr, '-');
            m_load_address = std::stol(addr, 0, 16);
        }
    }

    uint64_t Debugger::offset_load_address(uint64_t addr) {
        return addr - m_load_address;
    }

    void Debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
        std::ifstream file {file_name};

        //workout a window around the desired line
        auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
        auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

        char current_char{};
        auto current_line = 1u;

        //skip lines up until start line
        while (current_line != start_line && file.get(current_char)) {
            if (current_char == '\n') {
                ++current_line;
            }
        }

        //Output cursor if we're at the current line
        std::cout << (current_line == line ? "> " : " ");

        //Write line up until end_line
        while (current_line != end_line && file.get(current_char)) {
            std::cout << current_char;
            if (current_char == '\n') {
                ++current_line;
                //Output cursor if we're at the current line
                std::cout << (current_line == line ? "> " : " ");
            }
        }
        //Write newline and make sure that the stream is flushed properly
        std::cout << std::endl;
    }

    siginfo_t Debugger::get_signal_info() {
        siginfo_t sigInfo;
        if (ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &sigInfo) < 0) {
            Debug_Utility::printError("PTRACE_GETSIGINFO error");
        }
        return sigInfo; 
    }

    void Debugger::single_step_instruction() {
        if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) < 0) {
            Debug_Utility::printError("PTRACE_SINGLESTEP error");
        }
        wait_for_signal();
    }

    void Debugger::single_step_instruction_with_breakpoint_check() {
        //first, check if breakpoint needs to be disabled and then enabled
        if (m_breakpoints.count(get_pc())){
            step_over_breakpoint();
        }
        else {
            single_step_instruction();
        }
    }

    void Debugger::step_out() {
        auto frame_pointer = Registers::get_register_value(m_pid, Registers::reg::rbp);
        //return_address is 8 bytes from frame pointer
        auto return_address = read_memory(frame_pointer + 8);

        bool should_remove_breakpoint = false;
        if (!m_breakpoints.count(return_address)) {
            set_breakpoint_at_address(return_address);
            should_remove_breakpoint = true;
        }

        continue_execution();

        if (should_remove_breakpoint) {
            remove_breakpoint(return_address);
        }
    }

    void Debugger::remove_breakpoint(std::intptr_t addr) {
        if (m_breakpoints.at(addr).is_enabled()) {
            m_breakpoints.at(addr).disable();
        }
        m_breakpoints.erase(addr);
    }

    void Debugger::step_in() {
        auto current_line = get_line_entry_from_pc(get_offset_pc())->line;

        //loop till next line
        while (get_line_entry_from_pc(get_offset_pc())->line == current_line) {
            single_step_instruction_with_breakpoint_check();
        }

        auto line_entry = get_line_entry_from_pc(get_offset_pc());
        print_source(line_entry->file->path, line_entry->line);
    }

    uint64_t Debugger::get_offset_pc() {
        return offset_load_address(get_pc());
    }

    uint64_t Debugger::offset_dwarf_address(uint64_t addr) {
        return addr + m_load_address;
    }

    void Debugger::step_over() {
        auto func = get_function_from_pc(get_offset_pc());
        auto func_entry_point = at_low_pc(func);
        auto func_exit_point = at_high_pc(func);

        auto func_entry_line = get_line_entry_from_pc(func_entry_point);
        auto start_line = get_line_entry_from_pc(get_offset_pc());

        std::vector<std::intptr_t> to_delete{};

        while (func_entry_line->address < func_exit_point) {
            auto load_address = offset_dwarf_address(func_entry_line->address);
            if (func_entry_line->address != start_line->address && !m_breakpoints.count(load_address)) {
                set_breakpoint_at_address(load_address);
                to_delete.push_back(load_address);
            }
            ++func_entry_line;
        }

        auto frame_pointer = get_register_value(m_pid, Registers::reg::rbp);
        auto return_address = read_memory(frame_pointer + 8);

        if (!m_breakpoints.count(return_address)) {
            set_breakpoint_at_address(return_address);
            to_delete.push_back(return_address);
        }

        continue_execution();

        for (auto addr : to_delete) {
            remove_breakpoint(addr);
        }
    }

    std::vector<Symbols::symbol> Debugger::lookup_symbol(const std::string& name) {
        std::vector<Symbols::symbol> symbols;

        for (auto& elf_section: m_elf.sections()) {
            if ((elf_section.get_hdr().type != elf::sht::symtab) && (elf_section.get_hdr().type != elf::sht::dynsym))
                continue;

            for (const auto& currSym: elf_section.as_symtab()) {
                if (currSym.get_name() == name) {
                    auto& currSymData = currSym.get_data();
                    symbols.push_back(Symbols::symbol{Symbols::to_symbol_type(currSymData.type()), currSym.get_name(), currSymData.value});
                }
            }
        }
        return symbols;
    }

    void Debugger::set_breakpoint_at_function(const std::string& funcName) {
        for (const auto& compilation_unit : m_dwarf.compilation_units()) {
            for (const auto& dwarf_info_entry: compilation_unit.root()) {
                if (dwarf_info_entry.has(dwarf::DW_AT::name) && at_name(dwarf_info_entry) == funcName) {
                    auto start_addr_func = at_low_pc(dwarf_info_entry);
                    auto line_entry = get_line_entry_from_pc(start_addr_func);
                    //we want to set a break point at the first line of the function 
                    //this is the the first statement after function definition
                    ++line_entry;
                    set_breakpoint_at_address(offset_dwarf_address(line_entry->address));

                }
            }
        }
    }

    void Debugger::set_breakpoint_at_source_line(const std::string& file, unsigned line){
        for (const auto& compilation_unit : m_dwarf.compilation_units()) {
            if (Debug_Utility::is_suffix(file, at_name(compilation_unit.root()))) {
                const auto& line_table = compilation_unit.get_line_table();

                for (const auto& line_entry : line_table) {
                    if (line_entry.is_stmt && line_entry.line == line) {
                        set_breakpoint_at_address(offset_dwarf_address(line_entry.address));
                    }
                }
            }
        }
    }

    void Debugger::print_backtrace() {

        //function to print frame details
        auto output_frame = [frame_number = 0] (auto&& func) mutable {
            std::cout << "frame #" << frame_number++ << ": 0x" << dwarf::at_low_pc(func) << ' ' << dwarf::at_name(func) << std::endl;
        };

        auto current_function = get_function_from_pc(offset_load_address(get_pc()));
        output_frame(current_function);

        //Frame pointer is stored at rbp
        auto frame_pointer = get_register_value(m_pid, Registers::reg::rbp);
        auto return_address = read_memory(frame_pointer + 8); 

        while (dwarf::at_name(current_function) != "main") {
            current_function = get_function_from_pc(offset_load_address(return_address));
            output_frame(current_function);
            frame_pointer = read_memory(frame_pointer);
            return_address = read_memory(frame_pointer + 8);
        }
    }

    void Debugger::read_variables() {
        auto current_function = get_function_from_pc(get_offset_pc());

        for (const auto& dwarf_info_entry: current_function) {
            if (dwarf_info_entry.tag == dwarf::DW_TAG::variable) {
                auto local_var = dwarf_info_entry[dwarf::DW_AT::location];

                if (local_var.get_type() == dwarf::value::type::exprloc) {
                    PtraceExprContext context {m_pid, m_load_address};
                    auto result = local_var.as_exprloc().evaluate(&context);
                    switch (result.location_type) {
                        case dwarf::expr_result::type::address:
                            {
                                auto offset_address = result.value;
                                auto value = read_memory(offset_address);
                                std::cout << at_name(dwarf_info_entry) << " (0x" << std::hex << result.value << ") = " << value << std::endl;
                                break;
                            }
                        case dwarf::expr_result::type::reg:
                            {
                                auto value = Registers::get_register_value_from_dwarf_register(m_pid, result.value);
                                std::cout << at_name(dwarf_info_entry) << " (reg " << result.value << ") = " << value << std::endl;
                                break;
                            }
                        default:
                            throw std::runtime_error {"unhandled variable location"};
                    }
                }
            }
        }
    }

    void Debugger::print_available_commands() {
        std::cout << std::endl;
        std::cout << "1.  continue\n";
        std::cout << "2.  break 0xADDRESS\n";
        std::cout << "3.  break FunctionName\n";
        std::cout << "4.  break FileName:LineNumber\n";
        std::cout << "7.  registers read registerName\n";
        std::cout << "8.  registers write registerName 0xVal\n";
        std::cout << "9.  registers dump\n";
        std::cout << "10. memory read 0xADDRESS\n";
        std::cout << "11. memory write 0xADDRESS 0xVal\n";
        std::cout << "13. backtrace\n";
        std::cout << "14. variables\n";
        std::cout << "15. stepi\n";
        std::cout << "16. step\n";
        std::cout << "17. next\n";
        std::cout << "18. finish\n";
        std::cout << "19. symbol symbolName\n";
        std::cout << std::endl;
    }
}
