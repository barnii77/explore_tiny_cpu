const OPCODES = {
  'LDA': 0x01, 'LDB': 0x02, 'ADD': 0x03,
  'STA': 0x04, 'LDAM':0x05, 'JMP':0x06,
  'JZ':  0x07, 'DEC': 0x08, 'LDBM':0x09,
  'STAB':0x0A, 'HLT': 0xFF
};
const INSTRUCTION_SET = {
  0x01: { name:'LDA',  operand:true, exec(op){ this.reg.A = op; this.ZF = (op === 0) ? 1 : 0; } },
  0x02: { name:'LDB',  operand:true, exec(op){ this.reg.B = op; this.ZF = (op === 0) ? 1 : 0; } },
  0x03: { name:'ADD',  operand:false, exec(){ const s = (this.reg.A + this.reg.B) & 0xFF; this.reg.A = s; this.ZF = (s === 0) ? 1 : 0; } },
  0x04: { name:'STA',  operand:true, exec(op){ this.memory[op] = this.reg.A; } },
  0x05: { name:'LDAM', operand:true, exec(op){ const v = this.memory[op]; this.reg.A = v; this.ZF = (v === 0) ? 1 : 0; } },
  0x06: { name:'JMP',  operand:true, exec(op){ this.PC = op; } },
  0x07: { name:'JZ',   operand:true, exec(op){ if (this.ZF) this.PC = op; } },
  0x08: { name:'DEC',  operand:false, exec(){ const a = (this.reg.A - 1) & 0xFF; this.reg.A = a; this.ZF = (a === 0) ? 1 : 0; } },
  0x09: { name:'LDBM', operand:true, exec(op){ const v = this.memory[op]; this.reg.B = v; this.ZF = (v === 0) ? 1 : 0; } },
  0x0A: { name:'STAB', operand:false, exec(){ this.memory[this.reg.B] = this.reg.A; } },
  0xFF: { name:'HLT',  operand:false, exec(){ this.running = false; } }
};
const EXPLANATIONS = {
  'LDA':  op2 => `Load the number ${op2} directly into register A.`,
  'LDB':  op2 => `Load the number ${op2} directly into register B.`,
  'LDAM': op2 => `Read the byte at address ${op2} into register A.`,
  'LDBM': op2 => `Read the byte at address ${op2} into register B.`,
  'ADD':  ()  => `Fetch A and B, compute A+B mod 256, and store result back in A.`,
  'STA':  op2 => `Write the value in A to memory address ${op2}.`,
  'STAB': ()  => `Write the value in A to the memory address stored in register B.`,
  'JMP':  op2 => `Unconditionally set PC to ${op2}.`,
  'JZ':   op2 => `If zero-flag is set, jump to ${op2}; otherwise continue.`,
  'DEC':  ()  => `Subtract 1 from A (mod 256), set zero-flag if result==0.`,
  'HLT':  ()  => `Stop execution forever.`,
  'NOP':  ()  => `No operation.`,
};

function generateExplanation(name, op2) {
  const fn = EXPLANATIONS[name];
  return fn ? fn(op2) : 'Unknown instruction.';
}

class TinyEmulator {
  constructor(memSize = 256) {
    this.memory = new Uint8Array(memSize);
    this.reg = { A: 0, B: 0 };
    this.PC = 0;
    this.ZF = 0;
    this.running = false;
    this.prog_start = 0;
    this.prog_end = 0;
  }
  loadProgram(prog, startAddr = 0) {
    this.memory.fill(0);
    this.prog_start = startAddr;
    this.prog_end = startAddr + prog.length;
    for (let i = 0; i < prog.length; i++) {
      this.memory[startAddr + i] = prog[i] & 0xFF;
    }
    this.PC = startAddr;
    this.running = true;
  }
  disassemble() {
    const out = [];
    let i = this.prog_start;
    while (i < this.prog_end) {
      const opc = this.memory[i];
      const inst = INSTRUCTION_SET[opc];
      if (inst) {
        const op2 = inst.operand ? this.memory[i+1] : null;
        out.push({ addr: i, opHex: opc.toString(16).padStart(2,'0').toUpperCase(), name: inst.name, operand: op2 });
        i += 1 + (inst.operand ? 1 : 0);
      } else {
        out.push({ addr: i, opHex: opc.toString(16).padStart(2,'0').toUpperCase(), name: 'NOP', operand: null });
        i += 1;
      }
    }
    return out;
  }
  step() {
    if (!this.running) return;
    this._beforeRegs = { A: this.reg.A, B: this.reg.B, PC: this.PC, ZF: this.ZF };
    this._beforeMem = Array.from(this.memory);
    const opc = this.memory[this.PC];
    const inst = INSTRUCTION_SET[opc] || { name: 'NOP', operand: false, exec(){} };
    this.PC++;
    let op2 = null;
    if (inst.operand) {
      op2 = this.memory[this.PC];
      this.PC++;
    }
    inst.exec.call(this, op2);
    this.last = { name: inst.name, operand: op2 };
  }
}

function assemble(txt, loadAddr = 200) {
  const parsed = [];
  txt.split('\n').forEach(line => {
    const code = line.split(';',1)[0].trim();
    if (code) parsed.push(code);
  });
  const labels = {};
  const instructions = [];
  let addr = loadAddr;
  parsed.forEach(code => {
    const m = code.match(/^(\w+):\s*(.*)$/);
    if (m) {
      labels[m[1]] = addr;
      if (m[2]) {
        instructions.push({ addr, code: m[2] });
        const op = m[2].split(/\s+/)[0].toUpperCase();
        addr += 1 + (['LDA','LDB','STA','LDAM','JMP','JZ','LDBM'].includes(op) ? 1 : 0);
      }
    } else {
      instructions.push({ addr, code });
      const op = code.split(/\s+/)[0].toUpperCase();
      addr += 1 + (['LDA','LDB','STA','LDAM','JMP','JZ','LDBM'].includes(op) ? 1 : 0);
    }
  });
  const prog = [];
  instructions.forEach(inst => {
    const parts = inst.code.split(/\s+/);
    const op = parts[0].toUpperCase();
    if (!(op in OPCODES)) throw new Error(`Unknown instruction '${op}'`);
    prog.push(OPCODES[op]);
    if (['LDA','LDB','STA','LDAM','JMP','JZ','LDBM'].includes(op)) {
      if (parts.length < 2) throw new Error(`Instruction '${op}' requires an operand`);
      const operand = parts[1];
      const imm = operand in labels ? labels[operand] & 0xFF : parseInt(operand,0) & 0xFF;
      prog.push(imm);
    }
  });
  return { prog, loadAddr };
}

const fibAsm = `
; Compute N Fibonacci numbers into mem[50..]
; mem[2] = counter (N)
; mem[3] = output pointer
; mem[0] = fib_prev
; mem[1] = fib_curr
; mem[4] = scratch for next fib

LDA 8
STA 2
LDA 50
STA 3
LDA 0
STA 0
LDA 1
STA 1

loop:
LDAM 2
JZ done
LDAM 1
LDBM 3
STAB
LDAM 3
LDB 1
ADD
STA 3
LDAM 0
LDBM 1
ADD
STA 4
LDAM 1
STA 0
LDAM 4
STA 1
LDAM 2
DEC
STA 2
JMP loop

done:
HLT
`;

let emu, initial;
function init() {
  initial = assemble(fibAsm);
  emu = new TinyEmulator();
  emu.loadProgram(initial.prog, initial.loadAddr);
  updateUI();
}

function updateUI() {
  renderCode();
  renderRegs();
  renderInfo();
  renderMemory();
  const btn = document.getElementById('step-btn');
  btn.disabled = !emu.running;
  document.getElementById('status').textContent = emu.running ? 'Running' : 'Halted';
}

function renderCode() {
  const view = document.getElementById('code-view');
  view.innerHTML = '';
  emu.disassemble().forEach(inst => {
    const div = document.createElement('div');
    div.className = 'code-line' + (inst.addr === emu.PC ? ' active' : '');
    const prefix = inst.addr === emu.PC ? '→' : ' ';
    const addr = inst.addr.toString().padStart(3,' ');
    const ophex = inst.opHex.padEnd(2,' ');
    const name = inst.name.padEnd(5,' ');
    const oper = inst.operand != null ? inst.operand.toString().padStart(3,' ') : '   ';
    div.textContent = `${prefix}${addr} 0x${ophex}  ${name}  ${oper}`;
    view.appendChild(div);
  });
}

function renderRegs() {
  const view = document.getElementById('regs');
  view.innerHTML = '<table>' +
    `<tr><th>A</th><td>${emu.reg.A}</td></tr>` +
    `<tr><th>B</th><td>${emu.reg.B}</td></tr>` +
    `<tr><th>PC</th><td>${emu.PC}</td></tr>` +
    `<tr><th>ZF</th><td>${emu.ZF}</td></tr>` +
    '</table>';
}

function renderMemory() {
  const view = document.getElementById('memory-view');
  let html = '<table><thead><tr><th>Addr</th>';
  for (let i = 0; i < 8; i++) html += `<th>+${i}</th>`;
  html += '<th>ASCII</th></tr></thead><tbody>';
  for (let addr = 0; addr < emu.memory.length; addr += 8) {
    html += `<tr><td>${addr.toString(16).padStart(4,'0').toUpperCase()}</td>`;
    let ascii = '';
    for (let i = 0; i < 8; i++) {
      const v = emu.memory[addr + i];
      html += `<td>${v.toString(16).padStart(2,'0').toUpperCase()}</td>`;
      ascii += v >= 32 && v <= 126 ? String.fromCharCode(v) : '.';
    }
    html += `<td>${ascii}</td></tr>`;
  }
  html += '</tbody></table>';
  view.innerHTML = html;
}

function renderInfo() {
  const view = document.getElementById('info');
  if (!emu.last) {
    view.innerHTML = '';
    return;
  }
  const { name, operand } = emu.last;
  const expl = generateExplanation(name, operand);
  let html = '<div><strong>Instruction:</strong> ' + name + (operand != null ? ' ' + operand : '') + '</div>';
  html += '<div><strong>Explanation:</strong> ' + expl + '</div>';

  html += '<div style="margin-top:8px;"><strong>Registers changed:</strong><ul>';
  ['A','B','PC','ZF'].forEach(r => {
    const before = emu._beforeRegs ? emu._beforeRegs[r] : null;
    const after = (r === 'PC' ? emu.PC : r === 'ZF' ? emu.ZF : emu.reg[r]);
    if (before != null && before !== after) html += `<li>${r}: ${before} → ${after}</li>`;
  });
  html += '</ul></div>';

  html += '<div style="margin-top:8px;"><strong>Memory changed:</strong><ul>';
  if (emu._beforeMem) {
    emu.memory.forEach((v,i) => {
      const old = emu._beforeMem[i];
      if (old !== v) html += `<li>[${i}] ${old} → ${v}</li>`;
    });
  }
  html += '</ul></div>';

  view.innerHTML = html;
}

window.addEventListener('load', init);
document.getElementById('step-btn').addEventListener('click', () => { emu.step(); updateUI(); });
document.getElementById('reset-btn').addEventListener('click', () => {
  emu.loadProgram(initial.prog, initial.loadAddr);
  emu.last = null;
  emu._beforeRegs = null;
  emu._beforeMem = null;
  updateUI();
});
