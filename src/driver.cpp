#include <sys/ptrace.h>
#include <sys/personality.h>
#include <unistd.h>
#include <errno.h>
#include "Debugger.hpp"
#include "Utility.hpp"

int main (int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified\n";
        return -1;
    }

    auto progName = argv[1];

    pid_t child_pid = fork();

    if (child_pid == 0) {
        personality(ADDR_NO_RANDOMIZE);
        Debug_Utility::execute_debuggee(progName);
    }

    else if (child_pid >= 1) {
        std::cout  << "started debugging process id:" << child_pid << std::endl;
        MiniDebugger::Debugger debugger {progName, child_pid};
        debugger.run();
    }
    else {
        perror("fork error");
        return 1;
    }
}
