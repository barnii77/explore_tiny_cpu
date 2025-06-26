# explore_tiny_cpu
an educational cpu explorer command line tool to help people understand how assembly and cpus work (heavily simplified)

# why
if you are anything like me, you have probably tried to explain how cpus work to people before. now, not everyone has a background of low level programming, and for js or python programmers, it can be really hard and tiring to try to explain this stuff. this is not to shit on them, they just don't have the right background. i hope this tool makes it easier for people to understand.

## Web Debugger

A web-based interactive debugger is provided in `index.html`. Open this file in a modern web browser to explore the sample Fibonacci program visually. The interface includes:

- **Code view** with the current instruction highlighted.
- **Register state** panel showing A, B, PC, and ZF.
- **Memory view** displaying memory in hex and ASCII.
- **Controls** for stepping over instructions and resetting the program.
