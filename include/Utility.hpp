#include <iostream>
#include <vector>
namespace Debug_Utility{
    std::vector<std::string> split(const std::string& text, char delimiter);
    bool is_prefix(const std::string& source, const std::string& target);
    bool is_suffix(const std::string& source, const std::string& target);
    void printError(const std::string& errMsg);
    void execute_debuggee(const std::string& progName);
}
