# Linux Debugger 
[Reference] (https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/)

### Debugger supports the following operations:

* Setting Breakpoints
    - break 0xAddress
    - break functionName
    - break fileName:lineNumber
* Accessing Registers
    - register read registerName
    - register write registerName 0xval
    - register dump
* Accessing Memory
    - memory read 0xADDRESS
    - memory write 0xADDRESS 0xVAL
* Accessing symbols
    - symbol symbolName(ex: function name, variable name)
* StackTrace (with all function calls)
    - backtrace
* Variables (list all variables active in the function)
    - variables
* Execute single instruction
    - stepi
* Stepping over functions (on simple functions, i.e no support for dynamic library)
    - step (step next)
    - next (step over function)
    - finish (step return)

### Build
* run cmake
* make
* ./debugger <executable_name>
