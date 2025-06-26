class TinyEmulator:
    def __init__(self, mem_size=256):
        self.memory = [0] * mem_size
        self.reg   = {'A': 0, 'B': 0}
        self.PC    = 0
        self.ZF    = 0
        self.running = False

        # instruction set
        # 0x01..0x07,0x08..0x09 reused for future extensions if desired
        self.ops = {
            0x01: ('LDA',  self._lda_imm),     # load imm→A
            0x02: ('LDB',  self._ldb_imm),     # load imm→B
            0x03: ('ADD',  self._add),         # A=A+B
            0x04: ('STA',  self._sta),         # mem[addr]=A
            0x05: ('LDAM', self._lda_mem),     # A=mem[addr]
            0x06: ('JMP',  self._jmp),         # PC=addr
            0x07: ('JZ',   self._jz),          # if ZF jump
            0x08: ('DEC',  self._dec),         # A = A-1
            0x09: ('LDBM', self._ldb_mem),     # B = mem[addr]
            0x0A: ('STAB', self._stab),        # mem[B]=A (store A to addr in B)
            0xFF: ('HLT',  self._hlt),         # halt
        }

        self.prog_start = 0
        self.prog_end   = 0

    def load_program(self, prog_bytes, start_addr=0):
        """Load code & set program bounds."""
        self.prog_start = start_addr
        self.prog_end   = start_addr + len(prog_bytes)
        for i, b in enumerate(prog_bytes):
            self.memory[start_addr+i] = b & 0xFF
        self.PC = start_addr

    def disassemble(self):
        """Return list of (addr, opcode_hex, name, operand) in program."""
        out = []
        i = self.prog_start
        while i < self.prog_end:
            opc = self.memory[i]
            if opc in self.ops:
                name, _ = self.ops[opc]
                if name in ('LDA','LDB','STA','LDAM','JMP','JZ','LDBM'):
                    op2 = self.memory[i+1]
                    out.append((i, f"{opc:02X}", name, op2))
                    i += 2
                else:
                    out.append((i, f"{opc:02X}", name, ''))
                    i += 1
            else:
                # treat invalid/zero as NOP
                out.append((i, f"{opc:02X}", 'NOP', ''))
                i += 1
        return out

    def print_trace(self):
        """LLDB-style listing, arrow at PC (aligned)."""
        print("   Addr   Opcode   Mnemonic   Operand")
        print("   ----   -------  --------   -------")
        for addr, op_hex, name, op2 in self.disassemble():
            if addr == self.PC:
                prefix = '→ '
            else:
                prefix = '   '
            a_s = f"{addr:03}"
            op_s = f"0x{op_hex}".ljust(7)
            n_s  = name.ljust(9)
            o_s  = (str(op2) if op2!='' else '').ljust(7)
            print(f"{prefix}{a_s}   {op_s}  {n_s}  {o_s}")
        print()

    def explain_current(self, name, op2):
        expl = {
            'LDA':  f"Load the number {op2} directly into register A.",
            'LDB':  f"Load the number {op2} directly into register B.",
            'LDAM': f"Read the byte at address {op2} into register A.",
            'LDBM': f"Read the byte at address {op2} into register B.",
            'ADD':  ("Fetch A and B, compute A+B mod 256, and store result back in A."),
            'STA':  f"Write the value in A to memory address {op2}.",
            'STAB': "Write the value in A to the memory address stored in register B.",
            'JMP':  f"Unconditionally set PC to {op2}.",
            'JZ':   f"If zero-flag is set, jump to {op2}; otherwise continue.",
            'DEC':  "Subtract 1 from A (mod 256), set zero-flag if result==0.",
            'HLT':  "Stop execution forever.",
            'NOP':  "No operation.",
        }
        print(">>> " + expl.get(name, "Unknown instruction.") + "\n")

    def step(self):
        self.print_trace()

        # snapshot pre-state
        regs_before = dict(self.reg, PC=self.PC, ZF=self.ZF)
        mem_before  = list(self.memory)

        # fetch
        opc = self.memory[self.PC]
        if opc not in self.ops:
            name, handler = ('NOP', lambda: None)
        else:
            name, handler = self.ops[opc]
        self.PC += 1

        # fetch operand if needed
        op2 = None
        if name in ('LDA','LDB','STA','LDAM','JMP','JZ','LDBM'):
            op2 = self.memory[self.PC]
            self.PC += 1

        # execute
        handler()

        # explain
        self.explain_current(name, op2)

        # diff registers
        print("  registers changed:")
        for r in ('A','B','PC','ZF'):
            if r == 'A' or r == 'B':
                before = regs_before[r]
                after  = self.reg[r]
            elif r == 'PC':
                before = regs_before['PC']
                after  = self.PC
            else:  # ZF
                before = regs_before['ZF']
                after  = self.ZF
            if before != after:
                print(f"    {r}: {before} → {after}")
        # diff memory
        diffs = [(i,mem_before[i],self.memory[i])
                 for i in range(len(self.memory))
                 if mem_before[i] != self.memory[i]]
        if diffs:
            print("  memory changed:")
            for addr, old, new in diffs:
                print(f"    [{addr}] {old} → {new}")
        print()

    def print_memory(self, start=0, end=None):
        """Print memory contents in hexdump style format."""
        if end is None:
            end = len(self.memory)
        
        print("Memory contents:")
        print("Addr:  +0 +1 +2 +3 +4 +5 +6 +7  ASCII")
        print("----   -- -- -- -- -- -- -- --  --------")
        
        addr = start
        while addr < end:
            if addr + 8 <= end and all(self.memory[addr + i] == 0 for i in range(8)):
                zero_start = addr
                while addr + 8 <= end and all(self.memory[addr + i] == 0 for i in range(8)):
                    addr += 8
                if addr - zero_start > 8:
                    print(f"{zero_start:04X}: 00 00 00 00 00 00 00 00  ........")
                    print("*")
                    if addr < end:
                        print(f"{addr-8:04X}: 00 00 00 00 00 00 00 00  ........")
                else:
                    addr = zero_start
                    line = f"{addr:04X}: "
                    hex_part = ""
                    ascii_part = ""
                    for i in range(8):
                        if addr + i < end:
                            byte_val = self.memory[addr + i]
                            hex_part += f"{byte_val:02X} "
                            ascii_part += chr(byte_val) if 32 <= byte_val <= 126 else "."
                        else:
                            hex_part += "   "
                            ascii_part += " "
                    print(f"{line}{hex_part} {ascii_part}")
                    addr += 8
            else:
                line = f"{addr:04X}: "
                hex_part = ""
                ascii_part = ""
                for i in range(8):
                    if addr + i < end:
                        byte_val = self.memory[addr + i]
                        hex_part += f"{byte_val:02X} "
                        ascii_part += chr(byte_val) if 32 <= byte_val <= 126 else "."
                    else:
                        hex_part += "   "
                        ascii_part += " "
                print(f"{line}{hex_part} {ascii_part}")
                addr += 8
        print()

    def run(self):
        """Interactive run: after HLT, you can still inspect but Enter only reports stop."""
        self.running = True
        while True:
            cmd = input("Enter register (A/B/PC/ZF) to inspect, 'mem' for memory view, or just Enter to step: ")
            up = cmd.strip().upper()
            if up in ('A', 'B'):
                print(f"  {up} = {self.reg[up]}")
                continue
            if up in ('PC', 'ZF'):
                val = getattr(self, up)
                print(f"  {up} = {val}")
                continue
            if up == 'MEM':
                self.print_memory()
                continue
            if up == '':
                if self.running:
                    self.step()
                else:
                    print("  execution has stopped.")
                continue
            print("  unknown command; try A, B, PC, ZF, mem or Enter\n")

    # --- handlers ---
    def _lda_imm(self):
        val = self.memory[self.PC-1]
        self.reg['A'] = val
        self.ZF = int(val == 0)

    def _ldb_imm(self):
        val = self.memory[self.PC-1]
        self.reg['B'] = val
        self.ZF = int(val == 0)

    def _add(self):
        s = (self.reg['A'] + self.reg['B']) & 0xFF
        self.reg['A'] = s
        self.ZF = int(s == 0)

    def _sta(self):
        addr = self.memory[self.PC-1]
        self.memory[addr] = self.reg['A']

    def _lda_mem(self):
        addr = self.memory[self.PC-1]
        v = self.memory[addr]
        self.reg['A'] = v
        self.ZF = int(v == 0)

    def _ldb_mem(self):
        addr = self.memory[self.PC-1]
        v = self.memory[addr]
        self.reg['B'] = v
        self.ZF = int(v == 0)

    def _jmp(self):
        addr = self.memory[self.PC-1]
        self.PC = addr

    def _jz(self):
        addr = self.memory[self.PC-1]
        if self.ZF:
            self.PC = addr

    def _dec(self):
        a = (self.reg['A'] - 1) & 0xFF
        self.reg['A'] = a
        self.ZF = int(a == 0)

    def _hlt(self):
        self.running = False

    def _stab(self):
        addr = self.reg['B']
        self.memory[addr] = self.reg['A']


# assembler

OPCODES = {
    'LDA':  0x01, 'LDB':  0x02, 'ADD':  0x03,
    'STA':  0x04, 'LDAM': 0x05, 'JMP':  0x06,
    'JZ':   0x07, 'DEC':  0x08, 'LDBM': 0x09,
    'STAB': 0x0A, 'HLT':  0xFF,
}

def assemble(txt, load_addr=None):
    """Two-pass assembler with proper label support and configurable load address."""
    if load_addr is None:
        load_addr = 200  # Default to loading near end of 256-byte memory
    
    # Parse all lines first
    parsed_lines = []
    for line_num, line in enumerate(txt.splitlines()):
        code = line.split(';', 1)[0].strip()
        if not code:
            continue
        parsed_lines.append((line_num, code))
    
    # PASS 1: Calculate addresses and collect labels
    labels = {}
    instructions = []
    addr = load_addr
    
    for line_num, code in parsed_lines:
        # Handle labels (ending with ':')
        if ':' in code:
            parts = code.split(':', 1)
            label = parts[0].strip()
            labels[label] = addr
            
            # Check if there's an instruction after the label on same line
            remaining = parts[1].strip()
            if remaining:
                instructions.append((addr, remaining, line_num))
                # Calculate instruction size
                p = remaining.split()
                m = p[0].upper()
                if m in OPCODES:
                    addr += 1
                    if m in ('LDA','LDB','STA','LDAM','JMP','JZ','LDBM'):
                        addr += 1
        else:
            instructions.append((addr, code, line_num))
            # Calculate instruction size
            p = code.split()
            m = p[0].upper()
            if m in OPCODES:
                addr += 1
                if m in ('LDA','LDB','STA','LDAM','JMP','JZ','LDBM'):
                    addr += 1
    
    print(f"Assembly pass 1 complete. Labels found: {labels}")
    print(f"Program will occupy addresses {load_addr:04X} to {addr-1:04X}")
    
    # PASS 2: Generate bytecode with label resolution
    prog = []
    for addr, code, line_num in instructions:
        p = code.split()
        m = p[0].upper()
        
        if m not in OPCODES:
            raise ValueError(f"Line {line_num+1}: Unknown instruction '{m}'")
            
        prog.append(OPCODES[m])
        
        if m in ('LDA','LDB','STA','LDAM','JMP','JZ','LDBM'):
            if len(p) < 2:
                raise ValueError(f"Line {line_num+1}: Instruction '{m}' requires an operand")
            
            operand = p[1]
            # Check if operand is a label
            if operand in labels:
                resolved_addr = labels[operand] & 0xFF
                prog.append(resolved_addr)
                print(f"Resolved label '{operand}' to address {labels[operand]:04X} (byte: {resolved_addr:02X})")
            else:
                # Parse as number
                try:
                    prog.append(int(operand, 0) & 0xFF)
                except ValueError:
                    raise ValueError(f"Line {line_num+1}: Invalid operand '{operand}' - not a number or label")
    
    return prog, load_addr

if __name__ == '__main__':
    fib_asm = '''
        ; Compute N Fibonacci numbers into mem[50..]
        ; mem[2] = counter (N)
        ; mem[3] = output pointer
        ; mem[0] = fib_prev
        ; mem[1] = fib_curr
        ; mem[4] = scratch for next fib

        LDA 8         ; load N=8
        STA 2         ; store counter

        LDA 50        ; load base output address
        STA 3         ; store pointer

        ; initialize fib_prev=0, fib_curr=1
        LDA 0
        STA 0
        LDA 1
        STA 1

    loop:
        LDAM 2        ; load counter
        JZ done       ; if zero → finish

        ; --- output current fib ---
        LDAM 1        ; A = fib_curr
        LDBM 3        ; B = output pointer
        STAB          ; mem[B] = A

        ; bump pointer
        LDAM 3
        LDB 1
        ADD           ; A = ptr + 1
        STA 3

        ; --- compute next = prev + curr ---
        LDAM 0        ; A = fib_prev
        LDBM 1        ; B = fib_curr
        ADD           ; A = prev+curr
        STA 4         ; scratch next

        ; shift: prev = curr
        LDAM 1
        STA 0

        ; shift: curr = next (from scratch)
        LDAM 4
        STA 1

        ; decrement counter
        LDAM 2
        DEC
        STA 2

        JMP loop

    done:
        HLT
    '''

    code, load_addr = assemble(fib_asm)
    print("Assembled bytes:", code)
    print(f"Program loaded at address {load_addr:04X}")
    emu = TinyEmulator()
    emu.load_program(code, load_addr)
    emu.run()