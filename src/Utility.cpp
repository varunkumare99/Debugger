#include <sys/ptrace.h>
#include <unistd.h>
#include <sstream>
#include "Utility.hpp"
namespace Debug_Utility{
    bool is_prefix(const std::string& source, const std::string& target) {
        if (source.size() > target.size())
            return false;
        return std::equal(source.begin(), source.end(), target.begin());
    }

    bool is_suffix(const std::string& source, const std::string& target) {
        if (source.size() > target.size())
            return false;
        auto diff = target.size() - source.size();
        return std::equal(source.begin(), source.end(), target.begin() + diff);
    }

    std::vector<std::string> split(const std::string& text, char delimiter) {
        std::vector<std::string> vecString{};
        std::stringstream ss {text};
        std::string item;

        while (std::getline(ss, item, delimiter)) {
            vecString.push_back(item);
        }
        return vecString;
    }
    void printError(const std::string& errMsg) {
        perror(errMsg.c_str());
        std::cerr << "Errno : " << errno << std::endl;
    }

    void execute_debuggee(const std::string& progName) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            printError("PTRACE_TRACEME error");
        }
        execl(progName.c_str(), progName.c_str(), nullptr);
    }
}

