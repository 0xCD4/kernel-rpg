const canvas = document.getElementById('game-canvas');
const ctx = canvas.getContext('2d');

const gameRoot = document.getElementById('game-root');
const bootOverlay = document.getElementById('boot-overlay');
const bootLog = document.getElementById('boot-log');
const panicOverlay = document.getElementById('panic-overlay');
const panicLog = document.getElementById('panic-log');
const panicRetry = document.getElementById('panic-retry');
const panicInput = document.getElementById('panic-input');
const panicFeedback = document.getElementById('panic-feedback');

/* Valid recovery commands */
const RECOVERY_COMMANDS = [
  'reboot',
  'reboot -f',
  'echo b > /proc/sysrq-trigger',
  'echo 1 > /proc/sys/kernel/sysrq',
  'systemctl reboot',
  'shutdown -r now',
  'init 6',
  'sysrq reboot',
  'echo s > /proc/sysrq-trigger',
  'kexec -e',
];

const hudLevel = document.getElementById('hud-level');
const hudXp = document.getElementById('hud-xp');
const hudAttempts = document.getElementById('hud-attempts');
const operatorStatus = document.getElementById('operator-status');
const operatorPosition = document.getElementById('operator-position');
const operatorObjective = document.getElementById('operator-objective');
const incidentTitle = document.getElementById('incident-title');
const incidentDesc = document.getElementById('incident-desc');
const incidentTrace = document.getElementById('incident-trace');
const lessonList = document.getElementById('lesson-list');
const missionList = document.getElementById('mission-list');
const conceptList = document.getElementById('concept-list');
const statusLine = document.getElementById('status-line');

const themeSelect = document.getElementById('theme-select');
const themePreview = document.getElementById('theme-preview');

const dialogOverlay = document.getElementById('dialog-overlay');
const dialogTitle = document.getElementById('dialog-title');
const dialogSpeaker = document.getElementById('dialog-speaker');
const dialogPortrait = document.getElementById('dialog-portrait');
const dialogText = document.getElementById('dialog-text');
const dialogCode = document.getElementById('dialog-code');
const dialogClose = document.getElementById('dialog-close');

const terminalOverlay = document.getElementById('terminal-overlay');
const terminalTitle = document.getElementById('terminal-title');
const terminalText = document.getElementById('terminal-text');
const terminalCode = document.getElementById('terminal-code');
const terminalInput = document.getElementById('terminal-input');
const terminalFeedback = document.getElementById('terminal-feedback');
const terminalSubmit = document.getElementById('terminal-submit');
const terminalClose = document.getElementById('terminal-close');

const THEMES = {
  deep: {
    name: 'Deep Kernel',
    floor: '#143547',
    wall: '#1a304a',
    wallStroke: '#2e4f76',
    gateClosed: '#9b4057',
    gateOpen: '#5ce29d',
    border: '#355b85',
  },
  emerald: {
    name: 'Emerald Ops',
    floor: '#183f3c',
    wall: '#1d2e2b',
    wallStroke: '#2f7065',
    gateClosed: '#a04953',
    gateOpen: '#6df7bc',
    border: '#3c877a',
  },
  violet: {
    name: 'Violet Night',
    floor: '#2d2744',
    wall: '#1f1b33',
    wallStroke: '#5d4e87',
    gateClosed: '#9a4d79',
    gateOpen: '#8ef3ca',
    border: '#6654a0',
  },
  amber: {
    name: 'Amber Debug',
    floor: '#3a3020',
    wall: '#2a2116',
    wallStroke: '#7a6543',
    gateClosed: '#aa4e42',
    gateOpen: '#a7f38e',
    border: '#8a724c',
  },
};

/* ═══════════════════════════════════════════════
   8-BIT SFX ENGINE (Web Audio API)
   ═══════════════════════════════════════════════ */
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

function playSfx(type) {
  const o = audioCtx.createOscillator();
  const g = audioCtx.createGain();
  o.connect(g);
  g.connect(audioCtx.destination);
  g.gain.value = 0.08;
  const now = audioCtx.currentTime;

  switch (type) {
    case 'move':
      o.type = 'square'; o.frequency.setValueAtTime(220, now);
      o.frequency.setValueAtTime(280, now + 0.03);
      g.gain.setValueAtTime(0.04, now);
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.06);
      o.start(now); o.stop(now + 0.06); break;
    case 'interact':
      o.type = 'triangle'; o.frequency.setValueAtTime(440, now);
      o.frequency.setValueAtTime(660, now + 0.08);
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
      o.start(now); o.stop(now + 0.15); break;
    case 'correct':
      o.type = 'square'; o.frequency.setValueAtTime(523, now);
      o.frequency.setValueAtTime(659, now + 0.1);
      o.frequency.setValueAtTime(784, now + 0.2);
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
      o.start(now); o.stop(now + 0.35); break;
    case 'wrong':
      o.type = 'sawtooth'; o.frequency.setValueAtTime(200, now);
      o.frequency.setValueAtTime(100, now + 0.15);
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
      o.start(now); o.stop(now + 0.25); break;
    case 'panic':
      o.type = 'sawtooth'; o.frequency.setValueAtTime(80, now);
      o.frequency.setValueAtTime(40, now + 0.3);
      g.gain.setValueAtTime(0.12, now);
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.5);
      o.start(now); o.stop(now + 0.5); break;
    case 'levelup':
      o.type = 'square';
      [523, 659, 784, 1047].forEach((f, i) => {
        o.frequency.setValueAtTime(f, now + i * 0.12);
      });
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.6);
      o.start(now); o.stop(now + 0.6); break;
    case 'concept':
      o.type = 'sine'; o.frequency.setValueAtTime(880, now);
      o.frequency.setValueAtTime(1100, now + 0.08);
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
      o.start(now); o.stop(now + 0.2); break;
    case 'gate':
      o.type = 'triangle';
      o.frequency.setValueAtTime(330, now);
      o.frequency.setValueAtTime(440, now + 0.1);
      o.frequency.setValueAtTime(550, now + 0.2);
      o.frequency.setValueAtTime(660, now + 0.3);
      g.gain.exponentialRampToValueAtTime(0.001, now + 0.45);
      o.start(now); o.stop(now + 0.45); break;
  }
}

/* ═══════════════════════════════════════════════
   PARTICLE SYSTEM
   ═══════════════════════════════════════════════ */
const particles = [];

function spawnParticles(worldX, worldY, count, color, speed) {
  for (let i = 0; i < count; i++) {
    const angle = Math.random() * Math.PI * 2;
    const vel = (0.5 + Math.random()) * (speed || 2);
    particles.push({
      x: worldX, y: worldY,
      vx: Math.cos(angle) * vel, vy: Math.sin(angle) * vel,
      life: 1.0, decay: 0.02 + Math.random() * 0.03,
      size: 2 + Math.random() * 3, color: color || '#ffd37e',
    });
  }
}

function updateParticles() {
  for (let i = particles.length - 1; i >= 0; i--) {
    const p = particles[i];
    p.x += p.vx; p.y += p.vy;
    p.vy += 0.05; // gravity
    p.life -= p.decay;
    if (p.life <= 0) particles.splice(i, 1);
  }
}

function drawParticles() {
  particles.forEach(p => {
    ctx.save();
    ctx.globalAlpha = p.life;
    ctx.fillStyle = p.color;
    ctx.fillRect(p.x - p.size / 2, p.y - p.size / 2, p.size, p.size);
    ctx.restore();
  });
}

/* ═══════════════════════════════════════════════
   GAME STATE
   ═══════════════════════════════════════════════ */
const state = {
  levelIndex: 0,
  xp: 0,
  map: [],
  points: null,
  player: { x: 1, y: 1 },
  concepts: new Set(),
  mission: [],
  mentorDone: false,
  diagnosisDone: false,
  patchDone: false,
  gateOpen: false,
  attemptsUsed: 0,
  dialogOpen: false,
  terminalOpen: false,
  completed: false,
  terminalType: null,
  tileSize: 20,
  mapOffsetX: 0,
  mapOffsetY: 0,
  theme: 'deep',
  // Enemy system
  enemies: [],
  enemyTimer: null,
  invulnerable: false,
  hitFlashTimer: null,
  panicSource: null,
  // Smooth movement
  animX: 0, animY: 0, animTargetX: 0, animTargetY: 0, animating: false,
  // Walk animation
  walkFrame: 0, walkDir: 'down', walkTimer: 0,
  // Fog of War
  fogRadius: 4,
  // Bonus terminal
  bonusOpen: false, bonusDone: false,
  // Level complete
  levelXpGained: 0,
  // Game mode: 'training' or 'ctf'
  gameMode: null,
  // CTF state
  ctf: {
    timer: 0,
    timerInterval: null,
    flagsCollected: [],
    totalStartTime: 0,
    levelStartTime: 0,
  },
};

/* ═══════════════════════════════════════════════
   UTILITY
   ═══════════════════════════════════════════════ */
function setStatus(msg) {
  statusLine.textContent = msg;
}

function overlayLocked() {
  return !panicOverlay.classList.contains('hidden') || state.dialogOpen || state.terminalOpen || state.bonusOpen || !lcOverlay.classList.contains('hidden') || !flagOverlay.classList.contains('hidden');
}

function renderList(container, items) {
  container.innerHTML = '';
  items.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    container.appendChild(li);
  });
}

/* Normalization for answer matching */
function normalize(v) {
  return v
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[İIıi]/g, 'i')
    .replace(/[şŞ]/g, 's')
    .replace(/[çÇ]/g, 'c')
    .replace(/[ğĞ]/g, 'g')
    .replace(/[üÜ]/g, 'u')
    .replace(/[öÖ]/g, 'o');
}

/* ═══════════════════════════════════════════════
   BOOT SEQUENCE
   ═══════════════════════════════════════════════ */
function bootSequence() {
  const lines = [
    '',
    '  ██████╗  ██╗ ███╗   ██╗  ██████╗    ██████╗ ',
    '  ██╔══██╗ ██║ ████╗  ██║ ██╔════╝   ██╔═████╗',
    '  ██████╔╝ ██║ ██╔██╗ ██║ ██║  ███╗  ██║██╔██║',
    '  ██╔══██╗ ██║ ██║╚██╗██║ ██║   ██║  ████╔╝██║',
    '  ██║  ██║ ██║ ██║ ╚████║ ╚██████╔╝  ╚██████╔╝',
    '  ╚═╝  ╚═╝ ╚═╝ ╚═╝  ╚═══╝  ╚═════╝    ╚═════╝ ',
    '',
    '  kernel incident training ground v1.0',
    '  -------------------------------------------',
    '',
    '[    0.000000] Linux version 6.8.0-ring0 (gcc 13.2.0) #1 SMP PREEMPT_DYNAMIC',
    '[    0.000000] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda2 ro quiet',
    '[    0.000000] BIOS-provided physical RAM map:',
    '[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable',
    '[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bffdbfff] usable',
    '[    0.004521] DMI: QEMU Standard PC (Q35 + ICH9), BIOS edk2-20240201 02/01/2024',
    '[    0.010824] tsc: Detected 3000.000 MHz processor',
    '[    0.018341] ACPI: RSDP 0x00000000000F0490 000024 (v02 BOCHS )',
    '[    0.024109] smpboot: CPU0: Intel Core Processor (Haswell) stepping 1',
    '[    0.031442] smp: Bringing up secondary CPUs ...',
    '[    0.038891] smpboot: Total of 4 processors activated',
    '[    0.045217] Memory: 4194304K/4194304K available (16384K kernel code)',
    '[    0.052884] pid_max: default: 32768 minimum: 301',
    '[    0.059123] Mount-cache hash table entries: 4096',
    '[    0.066410] RCU Tasks: Setting shift to 2 and lim to 1 rcu_task_cb_adjust=1',
    '[    0.073891] PCI: Using configuration type 1 for base access',
    '[    0.081234] NET: Registered PF_NETLINK/PF_ROUTE protocol family',
    '[    0.088109] usb 1-1: new high-speed USB device number 2 using ehci-pci',
    '[    0.095446] EXT4-fs (sda2): mounted filesystem with ordered data mode',
    '[    0.102887] systemd[1]: Detected virtualization qemu',
    '[    0.110234] systemd[1]: Set hostname to <ring0-vm>',
    '',
    '[    0.120000] ring0: kernel incident training ground initialized',
    '[    0.125000] ring0: 10 incidents loaded into training queue',
    '[    0.130000] ring0: kernel bug entities spawned in maze subsystem',
    '[    0.135000] ring0: operator tux session attached (uid=0 pid=1)',
    '',
    '  ** Press any key or wait to enter training ground **',
  ];

  bootLog.style.color = '#7fbfea';
  let i = 0;
  const timer = setInterval(() => {
    if (i < lines.length) {
      // Color for ASCII art and special lines
      const line = lines[i];
      if (line.includes('██') || line.includes('╗') || line.includes('╚')) {
        bootLog.innerHTML += `<span style="color:#57d7c8">${line}</span>\n`;
      } else if (line.includes('ring0:')) {
        bootLog.innerHTML += `<span style="color:#44ff44">${line}</span>\n`;
      } else if (line.includes('training ground v') || line.includes('---')) {
        bootLog.innerHTML += `<span style="color:#ffd37e">${line}</span>\n`;
      } else if (line.includes('Press any key')) {
        bootLog.innerHTML += `<span style="color:#ffffff;animation:blink 1s infinite">${line}</span>\n`;
      } else {
        bootLog.innerHTML += `<span style="color:#7fbfea">${line}</span>\n`;
      }
      bootLog.scrollTop = bootLog.scrollHeight;
      i += 1;
    } else {
      clearInterval(timer);
      // Press any key or wait 3 seconds
      const enter = () => {
        document.removeEventListener('keydown', enter);
        clearTimeout(autoStart);
        bootOverlay.classList.add('hidden');
        showModeSelect();
      };
      document.addEventListener('keydown', enter);
      const autoStart = setTimeout(enter, 3000);
    }
  }, 90);
}

/* ===============================================
   KERNEL PANIC SYSTEM
   Reference: real Linux kernel oops/panic format
   - kernel/panic.c, arch/x86/kernel/dumpstack.c
   ═══════════════════════════════════════════════ */

function hexAddr() { return 'ffff' + Math.floor(Math.random() * 0xffffffffffff).toString(16).padStart(12, '0'); }
function hexShort() { return Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, '0'); }
function hexWord() { return Math.floor(Math.random() * 0xffffffffffff).toString(16).padStart(16, '0'); }
function codeBytes() {
  let s = '';
  for (let i = 0; i < 20; i++) s += Math.floor(Math.random() * 256).toString(16).padStart(2, '0') + ' ';
  return s.trim();
}

function generateBugPanicTrace() {
  const level = LEVELS[state.levelIndex];
  const pid = Math.floor(Math.random() * 30000) + 1000;
  const cpu = Math.floor(Math.random() * 4);
  const up = (Math.random() * 86400).toFixed(6);
  const faultAddr = hexAddr();
  const ripOff = Math.floor(Math.random() * 0x3ff).toString(16);
  const lineNo = 300 + Math.floor(Math.random() * 500);

  const faults = [
    `BUG: unable to handle page fault at ${faultAddr}`,
    `BUG: kernel NULL pointer dereference, address: 0000000000000000`,
    `BUG: KASAN: slab-use-after-free in kmem_cache_alloc+0x${ripOff}`,
    `BUG: KASAN: slab-out-of-bounds in __kmalloc+0x${ripOff}/0x350`,
  ];
  const fault = faults[Math.floor(Math.random() * faults.length)];

  const funcs = [
    '__kmalloc', 'schedule', 'do_page_fault', 'alloc_skb',
    'netfilter_hook', 'ext4_readdir', 'vfs_read', 'sock_sendmsg',
  ];
  const faultFunc = funcs[Math.floor(Math.random() * funcs.length)];

  return [
    `[${up}] ${fault}`,
    `[${up}] PGD ${hexShort()} P4D ${hexShort()}`,
    `[${up}] Oops: 0000 [#1] PREEMPT SMP NOPTI`,
    `[${up}] CPU: ${cpu} PID: ${pid} Comm: tux_operator Tainted: G           OE     6.8.0-ring0 #1`,
    `[${up}] Hardware name: QEMU Standard PC (Q35 + ICH9), BIOS edk2-20240201`,
    `[${up}] RIP: 0010:${faultFunc}+0x${ripOff}/0x350`,
    `[${up}] Code: ${codeBytes()}`,
    `[${up}] RSP: 0018:ffffc900${hexShort()} EFLAGS: 00010246`,
    `[${up}] RAX: ${hexWord()} RBX: ${hexWord()} RCX: 0000000000000000`,
    `[${up}] RDX: ${hexWord()} RSI: 0000000000000dc0 RDI: 0000000000000dc0`,
    `[${up}] RBP: ffffc900${hexShort()} R08: 0000000000000001 R09: 0000000000000001`,
    `[${up}] R10: 0000000000000000 R11: ${hexWord()} R12: 0000000000000dc0`,
    `[${up}] R13: 0000000000000000 R14: ffff8881${hexShort()} R15: 0000000000000000`,
    `[${up}] FS:  00007f2a${hexShort()}(0000) GS:ffff8881${hexShort()}(0000)`,
    `[${up}] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033`,
    `[${up}] CR2: ${faultAddr} CR3: 00000001${hexShort()} CR4: 0000000000770ee0`,
    `[${up}] Call Trace:`,
    `[${up}]  <TASK>`,
    `[${up}]  ? show_regs+0x6c/0x80`,
    `[${up}]  ? __die+0x25/0x70`,
    `[${up}]  ? page_fault_oops+0x140/0x4f0`,
    `[${up}]  ? exc_page_fault+0x7a/0x160`,
    `[${up}]  ? asm_exc_page_fault+0x27/0x30`,
    `[${up}]  ? ${faultFunc}+0x${ripOff}/0x350`,
    `[${up}]  do_syscall_64+0x82/0x1b0`,
    `[${up}]  entry_SYSCALL_64_after_hwframe+0x6e/0x76`,
    `[${up}]  </TASK>`,
    `[${up}] Modules linked in: nf_conntrack nf_defrag_ipv6 br_netfilter overlay loop`,
    `[${up}] CR2: ${faultAddr}`,
    `[${up}] ---[ end trace ${hexWord()} ]---`,
    `[${up}] RIP: 0010:${faultFunc}+0x${ripOff}/0x350`,
    `[${up}] Kernel panic - not syncing: Fatal exception`,
    `[${up}] Kernel Offset: 0x${Math.floor(Math.random() * 0x3fffffff).toString(16).padStart(8, '0')} from 0xffffffff81000000`,
    ``,
    `[${up}] -- ring0: ${level.title} --`,
    `[${up}] Reason: Kernel Bug caught the operator (-30 XP)`,
    `[${up}] Enter a recovery command to save the system`,
  ].join('\n');
}

function generatePatchPanicTrace() {
  const level = LEVELS[state.levelIndex];
  const up = (Math.random() * 86400).toFixed(6);
  const pid = Math.floor(Math.random() * 1000) + 1;

  return [
    `[${up}] ------------[ cut here ]------------`,
    `[${up}] kernel BUG at kernel/module/main.c:${800 + Math.floor(Math.random() * 200)}!`,
    `[${up}] Oops: 0000 [#1] PREEMPT SMP`,
    `[${up}] CPU: 0 PID: ${pid} Comm: modprobe Not tainted 6.8.0-ring0 #1`,
    `[${up}] RIP: 0010:apply_relocate_add+0x${Math.floor(Math.random() * 0xff).toString(16)}/0x3a0`,
    `[${up}] Code: ${codeBytes()}`,
    `[${up}] RSP: 0018:ffffc900${hexShort()} EFLAGS: 00010246`,
    `[${up}] RAX: 0000000000000000 RBX: ${hexWord()}`,
    `[${up}] Call Trace:`,
    `[${up}]  <TASK>`,
    `[${up}]  ? load_module+0x1234/0x1a00`,
    `[${up}]  ? __do_sys_init_module+0x178/0x200`,
    `[${up}]  ? do_syscall_64+0x82/0x1b0`,
    `[${up}]  entry_SYSCALL_64_after_hwframe+0x6e/0x76`,
    `[${up}]  </TASK>`,
    `[${up}] ---[ end trace ${hexWord()} ]---`,
    `[${up}] Kernel panic - not syncing: Fatal exception`,
    ``,
    `[${up}] -- ring0: ${level.title} --`,
    `[${up}] Reason: Wrong patch applied, module is unstable`,
    `[${up}] Enter a recovery command to save the system`,
  ].join('\n');
}

function showPanicScreen(traceText) {
  const recoveryBox = document.getElementById('panic-recovery-box');
  const actionsBox = document.getElementById('panic-actions');

  // Reset
  panicLog.innerHTML = '';
  panicInput.value = '';
  panicFeedback.textContent = '';
  recoveryBox.style.display = 'none';
  actionsBox.style.display = 'none';
  panicOverlay.classList.remove('hidden');

  // Line by line animation (like a real crash)
  const lines = traceText.split('\n');
  let lineIdx = 0;

  function colorLine(text) {
    if (!text.trim()) return '<br>';
    const e = esc(text);
    // Critical errors - bright red, bold
    if (text.includes('Kernel panic') || text.includes('kernel BUG') || text.includes('BUG:') || text.includes('Fatal exception'))
      return `<span style="color:#ff2222;font-weight:bold">${e}</span>`;
    // Oops and cut/end trace lines
    if (text.includes('Oops:') || text.includes('cut here') || text.includes('end trace'))
      return `<span style="color:#ff6666">${e}</span>`;
    // Call Trace, TASK markers
    if (text.includes('Call Trace') || text.includes('<TASK>') || text.includes('</TASK>'))
      return `<span style="color:#ffcc00;font-weight:bold">${e}</span>`;
    // RIP - very important, the function where the error occurred
    if (text.includes('RIP:'))
      return `<span style="color:#ff8800;font-weight:bold">${e}</span>`;
    // Code hex dump
    if (text.includes('Code:'))
      return `<span style="color:#cc88ff">${e}</span>`;
    // Register dump lines
    if (text.includes('RSP:') || text.includes('RAX:') || text.includes('RBX:') || text.includes('RDX:') || text.includes('RBP:') || text.includes('R10:') || text.includes('R13:') || text.includes('EFLAGS'))
      return `<span style="color:#00cccc">${e}</span>`;
    // Segment and control registers
    if (text.includes('FS:') || text.includes('CS:') || text.includes('CR2:') || text.includes('CR0:') || text.includes('PGD'))
      return `<span style="color:#6699cc">${e}</span>`;
    // CPU/PID/Hardware info
    if (text.includes('CPU:') || text.includes('Hardware name'))
      return `<span style="color:#ffffff">${e}</span>`;
    // Modules linked in
    if (text.includes('Modules linked'))
      return `<span style="color:#999999">${e}</span>`;
    // Kernel Offset
    if (text.includes('Kernel Offset'))
      return `<span style="color:#666666">${e}</span>`;
    // Call trace function lines (starting with ?)
    if (text.trim().startsWith('?') || text.trim().startsWith('entry_') || text.trim().startsWith('do_') || text.trim().startsWith('load_module') || text.trim().startsWith('__do_sys'))
      return `<span style="color:#dddd77">${e}</span>`;
    // ring0 game messages
    if (text.includes('ring0:') || text.includes('-- ring0'))
      return `<span style="color:#57d7c8;font-weight:bold">${e}</span>`;
    // Reason/XP
    if (text.includes('Reason:') || text.includes('XP'))
      return `<span style="color:#ff8844">${e}</span>`;
    // Recovery mesaji
    if (text.includes('recovery command') || text.includes('save the system'))
      return `<span style="color:#44ff44">${e}</span>`;
    return `<span style="color:#aaaaaa">${e}</span>`;
  }

  function esc(t) {
    return t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  const typeTimer = setInterval(() => {
    if (lineIdx >= lines.length) {
      clearInterval(typeTimer);
      // Trace done, show recovery input
      recoveryBox.style.display = 'block';
      actionsBox.style.display = 'flex';
      setTimeout(() => panicInput.focus(), 100);
      return;
    }
    panicLog.innerHTML += colorLine(lines[lineIdx]) + '\n';
    panicLog.scrollTop = panicLog.scrollHeight;
    lineIdx++;
  }, 55);
}

function triggerBugPanic() {
  stopEnemyTimer();
  state.panicSource = 'bug';
  state.xp = Math.max(0, state.xp - 30);
  // 1.5 second invulnerability after panic (prevents instant re-collision)
  state.invulnerable = true;
  if (state.hitFlashTimer) clearTimeout(state.hitFlashTimer);
  state.hitFlashTimer = setTimeout(() => { state.invulnerable = false; }, 1500);
  showPanicScreen(generateBugPanicTrace());
  setStatus('KERNEL PANIC: Kernel Bug caught the operator! (-30 XP)');
}

function triggerPatchPanic() {
  state.panicSource = 'patch';
  showPanicScreen(generatePatchPanicTrace());
  setStatus('KERNEL PANIC: Level became unstable due to wrong patch.');
}

function submitPanicRecovery() {
  const cmd = panicInput.value.trim().toLowerCase();
  if (!cmd) {
    panicFeedback.textContent = 'waiting for command...';
    return;
  }
  const isValid = RECOVERY_COMMANDS.some(rc => cmd === rc || cmd.includes(rc));
  if (isValid) {
    // Successful recovery effect
    panicFeedback.style.color = '#44ff44';
    panicFeedback.textContent = `$ ${cmd}\n[OK] System is restarting...`;
    setTimeout(() => {
      panicFeedback.style.color = '';
      panicOverlay.classList.add('hidden');
      initLevel();
    }, 800);
  } else {
    panicFeedback.textContent = `-bash: ${cmd}: invalid command. try: reboot | echo b > /proc/sysrq-trigger`;
  }
}

/* ═══════════════════════════════════════════════
   ENEMY SYSTEM
   ═══════════════════════════════════════════════ */
function getEnemyCount() {
  // L1:2, L2:2, L3:3, L4:3, L5:4, L6:4, L7:4, L8:5, L9:5, L10:6
  return Math.min(2 + Math.floor(state.levelIndex / 2), 6);
}

function getEnemySpeed() {
  // L1=800ms, L2=740ms, ... L10=200ms (aggressive increase)
  return Math.max(180, 800 - state.levelIndex * 65);
}

function spawnEnemies() {
  const count = getEnemyCount();
  const enemies = [];
  const h = state.map.length;
  const w = state.map[0].length;

  for (let i = 0; i < count; i++) {
    let ex, ey, attempts = 0;
    do {
      ex = Math.floor(Math.random() * (w - 2)) + 1;
      ey = Math.floor(Math.random() * (h - 2)) + 1;
      attempts++;
    } while (
      attempts < 800 &&
      (state.map[ey][ex] !== TILE.FLOOR ||
        Math.abs(ex - state.player.x) + Math.abs(ey - state.player.y) < 8 ||
        enemies.some(e => Math.abs(e.x - ex) + Math.abs(e.y - ey) < 4))
    );

    if (attempts < 800) {
      const dirs = [[0, 1], [0, -1], [1, 0], [-1, 0]];
      const dir = dirs[Math.floor(Math.random() * dirs.length)];
      enemies.push({
        x: ex,
        y: ey,
        prevX: ex,
        prevY: ey,
        dx: dir[0],
        dy: dir[1],
        phase: Math.random() * Math.PI * 2,
      });
    }
  }

  return enemies;
}

function isEnemyWalkable(tile) {
  return tile !== undefined && tile !== TILE.WALL;
}

function moveEnemies() {
  if (state.dialogOpen || state.terminalOpen || state.completed) return;
  if (!panicOverlay.classList.contains('hidden')) return;

  state.enemies.forEach(enemy => {
    enemy.phase += 0.3;
    enemy.prevX = enemy.x;
    enemy.prevY = enemy.y;

    const nx = enemy.x + enemy.dx;
    const ny = enemy.y + enemy.dy;

    if (state.map[ny] && isEnemyWalkable(state.map[ny][nx])) {
      enemy.x = nx;
      enemy.y = ny;
      if (Math.random() < 0.15) {
        pickNewDirection(enemy);
      }
    } else {
      pickNewDirection(enemy);
      const mx = enemy.x + enemy.dx;
      const my = enemy.y + enemy.dy;
      if (state.map[my] && isEnemyWalkable(state.map[my][mx])) {
        enemy.x = mx;
        enemy.y = my;
      }
    }
  });

  checkEnemyCollision();
  draw();
}

function pickNewDirection(enemy) {
  const dirs = [[0, 1], [0, -1], [1, 0], [-1, 0]];
  const shuffled = dirs.sort(() => Math.random() - 0.5);
  for (const [dx, dy] of shuffled) {
    const nnx = enemy.x + dx;
    const nny = enemy.y + dy;
    if (state.map[nny] && isEnemyWalkable(state.map[nny][nnx])) {
      enemy.dx = dx;
      enemy.dy = dy;
      return;
    }
  }
}

function checkEnemyCollision(playerPrevPos = state.player) {
  if (state.invulnerable) return;

  const hit = state.enemies.some((enemy) => {
    const sameTileHit = enemy.x === state.player.x && enemy.y === state.player.y;
    const swappedTileHit =
      enemy.x === playerPrevPos.x &&
      enemy.y === playerPrevPos.y &&
      enemy.prevX === state.player.x &&
      enemy.prevY === state.player.y;

    return sameTileHit || swappedTileHit;
  });
  if (hit) {
    playSfx('panic');
    triggerBugPanic();
  }
}

function startEnemyTimer() {
  if (state.enemyTimer) clearInterval(state.enemyTimer);
  state.enemyTimer = setInterval(moveEnemies, getEnemySpeed());
}

function stopEnemyTimer() {
  if (state.enemyTimer) {
    clearInterval(state.enemyTimer);
    state.enemyTimer = null;
  }
}

/* ═══════════════════════════════════════════════
   LEVEL MANAGEMENT
   ═══════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════
   LEVEL MANAGEMENT & RESPONSIVE CANVAS
   ═══════════════════════════════════════════════ */
function calculateViewport() {
  // Dynamic canvas size
  const maxWidth = window.innerWidth > 1200 ? 1200 : window.innerWidth - 40;
  // Height based on width ratio or fixed
  const maxHeight = Math.min(window.innerHeight - 200, 720); // Space for header and footer

  canvas.width = maxWidth;
  canvas.height = maxHeight;

  const h = state.map.length;
  const w = state.map[0].length;

  // Calculate tile size based on new canvas (min 16, max 64)
  state.tileSize = Math.max(16, Math.min(64, Math.floor(Math.min(canvas.width / w, canvas.height / h))));

  // Center the map
  state.mapOffsetX = Math.floor((canvas.width - w * state.tileSize) / 2);
  state.mapOffsetY = Math.floor((canvas.height - h * state.tileSize) / 2);
}

// Rescale the game when window size changes
window.addEventListener('resize', () => {
  if (state.map) {
    calculateViewport();
    draw();
  }
});

function initLevel() {
  stopEnemyTimer();

  const level = LEVELS[state.levelIndex];
  const built = buildLevelMap(level);
  state.map = built.map;
  state.points = built.points;
  state.player = { x: built.points.mentor.x, y: built.points.mentor.y + 1 };
  state.mentorDone = false;
  state.diagnosisDone = false;
  state.patchDone = false;
  state.gateOpen = false;
  state.attemptsUsed = 0;
  state.terminalType = null;
  state.invulnerable = false;
  state.panicSource = null;
  state.bonusDone = false;
  state.levelXpGained = 0;
  particles.length = 0;
  state.mission = [
    { key: 'mentor', text: 'Get incident briefing from mentor', done: false },
    { key: 'diag', text: 'Solve the diagnosis terminal (root cause)', done: false },
    { key: 'patch', text: 'Apply the fix at the patch terminal', done: false },
    { key: 'gate', text: 'Move to the exit through the opened gate', done: false },
  ];

  calculateViewport();

  // Spawn enemies
  state.enemies = spawnEnemies();
  startEnemyTimer();

  const speed = getEnemySpeed();
  const bugCount = state.enemies.length;
  setStatus(`[ level:${level.id} ] ${level.title} started. ${bugCount} kernel bugs detected! (Speed: ${speed}ms)`);
  renderAll();
  draw();
}

function renderAll() {
  const level = LEVELS[state.levelIndex];
  hudLevel.innerHTML = `<span class="stat-icon">◈</span> Level: ${level.id} / ${LEVELS.length}`;
  hudXp.innerHTML = `<span class="stat-icon">⬡</span> XP: ${state.xp}`;
  hudAttempts.innerHTML = `<span class="stat-icon">⟳</span> Attempts: ${state.attemptsUsed}/${level.patch.attempts}`;

  const objective = state.gateOpen
    ? 'Gate is open, go to exit node'
    : !state.mentorDone
      ? 'Talk to the mentor'
      : !state.diagnosisDone
        ? 'Solve the diagnosis terminal'
        : 'Solve the patch terminal';

  operatorStatus.textContent = state.gateOpen ? 'Incident resolved' : 'Incident active';
  operatorPosition.textContent = `(${state.player.x}, ${state.player.y})`;
  operatorObjective.textContent = objective;

  incidentTitle.textContent = level.title;
  incidentDesc.textContent = level.incident;
  incidentTrace.textContent = level.trace;

  themePreview.textContent = `Active theme: ${THEMES[state.theme].name}`;
  themeSelect.value = state.theme;

  renderList(lessonList, level.lesson);

  missionList.innerHTML = '';
  state.mission.forEach((m) => {
    const li = document.createElement('li');
    li.textContent = `[${m.done ? '✓' : ' '}] ${m.text}`;
    missionList.appendChild(li);
  });

  conceptList.innerHTML = '';
  if (!state.concepts.size) {
    renderList(conceptList, ['No concepts unlocked yet.']);
  } else {
    renderList(conceptList, [...state.concepts]);
  }
}

function updateMission(key, done = true) {
  const found = state.mission.find((m) => m.key === key);
  if (found) found.done = done;
}

function isWalkable(tile) {
  if (tile === TILE.WALL) return false;
  if (tile === TILE.GATE && !state.gateOpen) return false;
  return true;
}

/* ═══════════════════════════════════════════════
   PIXEL SPRITE ENGINE
   ═══════════════════════════════════════════════ */
function drawPixelSprite(px, py, size, pixels, palette) {
  const rows = pixels.length;
  const cols = pixels[0].length;
  const step = Math.max(1, Math.floor(size / Math.max(rows, cols)));
  const startX = Math.floor(px + (size - cols * step) / 2);
  const startY = Math.floor(py + (size - rows * step) / 2);

  for (let y = 0; y < rows; y += 1) {
    for (let x = 0; x < cols; x += 1) {
      const key = pixels[y][x];
      if (key === '.') continue;
      ctx.fillStyle = palette[key] || '#fff';
      ctx.fillRect(startX + x * step, startY + y * step, step, step);
    }
  }
}

function drawDialogPortrait(kind = 'mentor') {
  const dctx = dialogPortrait.getContext('2d');
  dctx.clearRect(0, 0, dialogPortrait.width, dialogPortrait.height);
  dctx.imageSmoothingEnabled = false;

  const palettes = {
    mentor: { 1: '#111827', 2: '#f6d49b', 3: '#3aa2ff', 4: '#f59e0b', 5: '#94a3b8' },
    system: { 1: '#0f172a', 2: '#86efac', 3: '#22d3ee', 4: '#f43f5e', 5: '#cbd5e1' },
    terminal: { 1: '#111827', 2: '#fecaca', 3: '#fb7185', 4: '#334155', 5: '#e2e8f0' },
  };

  const pixels = {
    mentor: ['..1111..', '.122221.', '122222221', '123332221', '123332221', '.1222221.', '..1441..', '.455554..'],
    system: ['..1111..', '.122221.', '122222221', '123333221', '123333221', '.1222221.', '..1441..', '..5555..'],
    terminal: ['..1111..', '.122221.', '122222221', '123333221', '123333221', '.1222221.', '..1441..', '.5...5..'],
  };

  const matrix = pixels[kind] || pixels.mentor;
  const pal = palettes[kind] || palettes.mentor;
  const rows = matrix.length;
  const cols = matrix[0].length;
  const cell = 8;
  const sx = Math.floor((dialogPortrait.width - cols * cell) / 2);
  const sy = Math.floor((dialogPortrait.height - rows * cell) / 2);

  for (let y = 0; y < rows; y += 1) {
    for (let x = 0; x < cols; x += 1) {
      const k = matrix[y][x];
      if (k === '.' || k === ' ') continue;
      dctx.fillStyle = pal[k] || '#fff';
      dctx.fillRect(sx + x * cell, sy + y * cell, cell, cell);
    }
  }
}

/* ═══════════════════════════════════════════════
   TILE & ENTITY DRAWING
   ═══════════════════════════════════════════════ */
function drawTile(x, y, tile) {
  const theme = THEMES[state.theme];
  const size = state.tileSize;
  const px = state.mapOffsetX + x * size;
  const py = state.mapOffsetY + y * size;

  if (tile === TILE.WALL) {
    ctx.fillStyle = theme.wall;
    ctx.fillRect(px, py, size, size);
    ctx.strokeStyle = theme.wallStroke;
    ctx.strokeRect(px + 1, py + 1, size - 2, size - 2);
    return;
  }

  ctx.fillStyle = theme.floor;
  ctx.fillRect(px, py, size, size);

  if (tile === TILE.MENTOR) {
    drawPixelSprite(
      px, py, size,
      ['..111..', '.12221.', '1222221', '1233321', '1233321', '.12221.', '..444..'],
      { 1: '#1f2430', 2: '#ffd489', 3: '#2d7ecf', 4: '#c0833d' }
    );
  } else if (tile === TILE.DIAG) {
    drawPixelSprite(
      px, py, size,
      ['.11111.', '1222221', '1233321', '1233321', '1233321', '1222221', '.14441.'],
      { 1: '#203140', 2: '#65d4ff', 3: '#c2f0ff', 4: '#2a8fb8' }
    );
  } else if (tile === TILE.PATCH) {
    drawPixelSprite(
      px, py, size,
      ['..111..', '.12221.', '1222221', '1233321', '1233321', '.12221.', '..444..'],
      { 1: '#5a1f2a', 2: '#ff7c8c', 3: '#ffd9df', 4: '#c0485b' }
    );
  } else if (tile === TILE.CONCEPT) {
    drawPixelSprite(
      px, py, size,
      ['...1...', '..121..', '.12221.', '.12221.', '.12221.', '..121..', '...1...'],
      { 1: '#d8c5ff', 2: '#8c63ff' }
    );
  } else if (tile === TILE.GATE) {
    drawPixelSprite(
      px, py, size,
      ['1111111', '1222221', '1233321', '1233321', '1233321', '1222221', '1111111'],
      { 1: '#20242f', 2: state.gateOpen ? theme.gateOpen : theme.gateClosed, 3: '#101522' }
    );
  } else if (tile === TILE.EXIT) {
    drawPixelSprite(
      px, py, size,
      ['..111..', '.12221.', '1222221', '1233321', '1233321', '.12221.', '..111..'],
      { 1: '#1a2535', 2: '#78dbff', 3: '#d8f8ff' }
    );
  }
}

/* -- Tux Linux Penguin (Player) - Walk Animation -- */
const TUX_FRAMES = {
  idle: [
    '..111..', '.12221.', '1253521', '1224221', '1222221', '.11111.', '.6...6.',
  ],
  walk1: [
    '..111..', '.12221.', '1253521', '1224221', '1222221', '.11111.', '6.....6',
  ],
  walk2: [
    '..111..', '.12221.', '1253521', '1224221', '1222221', '.11111.', '..6.6..',
  ],
};
const TUX_PALETTE = { 1: '#0d0d1a', 2: '#f0f2f8', 3: '#f0f2f8', 4: '#ff9933', 5: '#111133', 6: '#ff8822' };

function drawLinuxCharacter() {
  const size = state.tileSize;
  // Smooth movement interpolation
  let drawX, drawY;
  if (state.animating) {
    drawX = state.mapOffsetX + state.animX * size;
    drawY = state.mapOffsetY + state.animY * size;
  } else {
    drawX = state.mapOffsetX + state.player.x * size;
    drawY = state.mapOffsetY + state.player.y * size;
  }

  // Invulnerability blink effect
  if (state.invulnerable && Math.floor(Date.now() / 150) % 2 === 0) return;

  // Walk frame selection
  const frame = state.animating
    ? (Math.floor(Date.now() / 100) % 2 === 0 ? TUX_FRAMES.walk1 : TUX_FRAMES.walk2)
    : TUX_FRAMES.idle;

  drawPixelSprite(drawX, drawY, size, frame, TUX_PALETTE);

  // Glow under Tux
  ctx.save();
  ctx.globalAlpha = 0.12;
  ctx.fillStyle = '#57d7c8';
  ctx.beginPath();
  ctx.ellipse(drawX + size / 2, drawY + size - 2, size * 0.4, size * 0.15, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}

/* -- Kernel Bug Enemies -- */
function drawEnemy(enemy) {
  const size = state.tileSize;
  const px = state.mapOffsetX + enemy.x * size;
  const py = state.mapOffsetY + enemy.y * size;

  // Pulsing red glow
  const pulse = 0.08 + Math.sin(enemy.phase + Date.now() * 0.005) * 0.04;
  ctx.save();
  ctx.globalAlpha = pulse;
  ctx.fillStyle = '#ff2244';
  ctx.beginPath();
  ctx.ellipse(px + size / 2, py + size / 2, size * 0.7, size * 0.7, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();

  drawPixelSprite(
    px, py, size,
    [
      '1..1..1',
      '.1.1.1.',
      '.12221.',
      '1233321',
      '.12221.',
      '.1.1.1.',
      '1..1..1',
    ],
    {
      1: '#cc2244',
      2: '#ff4466',
      3: '#ff8899',
    }
  );
}

/* ═══════════════════════════════════════════════
   FOG OF WAR
   ═══════════════════════════════════════════════ */
function drawFogOfWar() {
  const size = state.tileSize;
  const px = state.player.x;
  const py = state.player.y;
  const r = state.fogRadius;

  for (let y = 0; y < state.map.length; y++) {
    for (let x = 0; x < state.map[0].length; x++) {
      const dist = Math.sqrt((x - px) ** 2 + (y - py) ** 2);
      if (dist > r) {
        const sx = state.mapOffsetX + x * size;
        const sy = state.mapOffsetY + y * size;
        ctx.fillStyle = '#000000';
        ctx.globalAlpha = Math.min(0.85, (dist - r) * 0.2);
        ctx.fillRect(sx, sy, size, size);
      }
    }
  }
  ctx.globalAlpha = 1.0;
}

/* ═══════════════════════════════════════════════
   BONUS TILE DRAWING
   ═══════════════════════════════════════════════ */
function drawBonusTile(px, py, size) {
  const pulse = 0.6 + Math.sin(Date.now() * 0.004) * 0.3;
  ctx.save();
  ctx.globalAlpha = pulse;
  drawPixelSprite(px, py, size,
    ['..111..', '.12221.', '1233321', '1234321', '1233321', '.12221.', '..111..'],
    { 1: '#4a2800', 2: '#ff9900', 3: '#ffcc00', 4: '#ffffff' }
  );
  ctx.restore();
}

/* ═══════════════════════════════════════════════
   MAIN DRAW LOOP
   ═══════════════════════════════════════════════ */
function draw() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.imageSmoothingEnabled = false;
  const border = THEMES[state.theme].border;
  canvas.style.borderColor = border;

  for (let y = 0; y < state.map.length; y += 1) {
    for (let x = 0; x < state.map[0].length; x += 1) {
      const tile = state.map[y][x];
      if (tile === TILE.BONUS) {
        const theme = THEMES[state.theme];
        const sz = state.tileSize;
        const bpx = state.mapOffsetX + x * sz;
        const bpy = state.mapOffsetY + y * sz;
        ctx.fillStyle = theme.floor;
        ctx.fillRect(bpx, bpy, sz, sz);
        drawBonusTile(bpx, bpy, sz);
      } else {
        drawTile(x, y, tile);
      }
    }
  }

  // Fog of War
  drawFogOfWar();

  // Draw enemies (hide if inside fog)
  state.enemies.forEach(e => {
    const dist = Math.sqrt((e.x - state.player.x) ** 2 + (e.y - state.player.y) ** 2);
    if (dist <= state.fogRadius + 1) drawEnemy(e);
  });

  // Particle effects
  updateParticles();
  drawParticles();

  // Draw the player (Tux) on top
  drawLinuxCharacter();

  renderAll();
}

/* ===============================================
   MOVEMENT & INTERACTION
   =============================================== */
function move(dx, dy) {
  if (overlayLocked() || state.completed || state.animating) return;
  const nx = state.player.x + dx;
  const ny = state.player.y + dy;
  const tile = state.map[ny]?.[nx];
  if (tile == null || !isWalkable(tile)) return;

  playSfx('move');
  state.walkDir = dx > 0 ? 'right' : dx < 0 ? 'left' : dy > 0 ? 'down' : 'up';

  // Smooth movement animation
  const startX = state.player.x;
  const startY = state.player.y;
  state.player.x = nx;
  state.player.y = ny;

  // Immediate collision check (if walking towards an enemy)
  checkEnemyCollision({ x: startX, y: startY });
  if (!panicOverlay.classList.contains('hidden')) return; // No animation needed if panic screen is open

  state.animating = true;
  state.animX = startX;
  state.animY = startY;
  state.animTargetX = nx;
  state.animTargetY = ny;

  const steps = 6;
  let step = 0;
  function animStep() {
    step++;
    const t = step / steps;
    state.animX = startX + (nx - startX) * t;
    state.animY = startY + (ny - startY) * t;
    draw();
    if (step < steps) {
      requestAnimationFrame(animStep);
    } else {
      state.animating = false;
      state.animX = nx;
      state.animY = ny;
      checkEnemyCollision({ x: startX, y: startY });
      draw();
    }
  }
  animStep();
}

function openDialog(title, text, code, speaker = "mentor@ring0", portrait = "mentor") {
  dialogTitle.textContent = title;
  dialogSpeaker.textContent = speaker;
  drawDialogPortrait(portrait);
  dialogText.textContent = text;
  dialogCode.textContent = code;
  state.dialogOpen = true;
  dialogOverlay.classList.remove('hidden');
}

function closeDialog() {
  state.dialogOpen = false;
  dialogOverlay.classList.add('hidden');
}

function openTerminal(type) {
  const level = LEVELS[state.levelIndex];
  const payload = type === 'diag' ? level.diagnosis : level.patch;
  state.terminalType = type;
  terminalTitle.textContent = payload.title;
  terminalText.textContent = payload.question;
  terminalCode.textContent = payload.code;
  terminalInput.value = '';
  terminalInput.placeholder = 'Type a single answer...';
  terminalFeedback.textContent = '';
  state.terminalOpen = true;
  terminalOverlay.classList.remove('hidden');
  terminalInput.focus();
}

function closeTerminal() {
  state.terminalOpen = false;
  terminalOverlay.classList.add('hidden');
}

function checkAnswer(input, answers) {
  const normalizedInput = normalize(input);
  // 1) Exact match
  if (answers.some(a => normalize(a) === normalizedInput)) return true;
  // 2) Does any comma-separated part match?
  const parts = input.split(/[,;|]/).map(s => s.trim()).filter(Boolean);
  if (parts.some(part => answers.some(a => normalize(a) === normalize(part)))) return true;
  // 3) Does the input contain the correct answer? (contains)
  if (answers.some(a => normalizedInput.includes(normalize(a)))) return true;
  return false;
}

function submitTerminal() {
  const level = LEVELS[state.levelIndex];
  if (!state.terminalType) return;

  const payload = state.terminalType === 'diag' ? level.diagnosis : level.patch;
  const valid = checkAnswer(terminalInput.value, payload.answers);

  if (state.terminalType === 'patch') state.attemptsUsed += 1;

  if (!valid) {
    terminalFeedback.textContent = `Wrong answer. Hint: ${payload.hint}`;
    playSfx('wrong');
    draw();
    if (state.terminalType === 'patch' && state.attemptsUsed >= level.patch.attempts) {
      closeTerminal();
      triggerPatchPanic();
    }
    return;
  }

  state.xp += payload.xp;
  state.levelXpGained += payload.xp;
  playSfx('correct');
  // Particle effect
  const pcx = state.mapOffsetX + state.player.x * state.tileSize + state.tileSize / 2;
  const pcy = state.mapOffsetY + state.player.y * state.tileSize + state.tileSize / 2;
  spawnParticles(pcx, pcy, 15, '#57d7c8', 2);

  if (state.terminalType === 'diag') {
    state.diagnosisDone = true;
    updateMission('diag', true);
    setStatus('[+] Diagnosis complete. You can now go to the patch terminal.');
  } else {
    state.patchDone = true;
    state.gateOpen = true;
    updateMission('patch', true);
    playSfx('gate');
    const gpx = state.mapOffsetX + state.player.x * state.tileSize + state.tileSize / 2;
    const gpy = state.mapOffsetY + state.player.y * state.tileSize + state.tileSize / 2;
    spawnParticles(gpx, gpy, 25, '#5ce29d', 3);
    setStatus('[+] Patch applied successfully. Gate is open, head to the exit node.');
  }

  closeTerminal();
  draw();
}

/* ═══════════════════════════════════════════════
   LEVEL COMPLETE SCREEN
   ═══════════════════════════════════════════════ */
const lcOverlay = document.getElementById('level-complete-overlay');
const lcTitle = document.getElementById('lc-title');
const lcLevel = document.getElementById('lc-level');
const lcXp = document.getElementById('lc-xp');
const lcTotal = document.getElementById('lc-total');
const lcAttempts = document.getElementById('lc-attempts');
const lcNext = document.getElementById('lc-next');
const lcContinue = document.getElementById('lc-continue');

function showLevelComplete() {
  const level = LEVELS[state.levelIndex];
  stopEnemyTimer();
  playSfx('levelup');

  // Particle explosion
  const cx = state.mapOffsetX + state.player.x * state.tileSize + state.tileSize / 2;
  const cy = state.mapOffsetY + state.player.y * state.tileSize + state.tileSize / 2;
  spawnParticles(cx, cy, 30, '#ffd37e', 3);
  spawnParticles(cx, cy, 20, '#57d7c8', 2);

  const isLast = state.levelIndex >= LEVELS.length - 1;
  lcTitle.textContent = isLast ? 'ALL LEVELS COMPLETE!' : 'LEVEL COMPLETE';
  lcLevel.textContent = level.title;
  lcXp.textContent = `+${state.levelXpGained}`;
  lcTotal.textContent = state.xp;
  lcAttempts.textContent = state.attemptsUsed;
  lcNext.textContent = isLast
    ? 'Congratulations! You are now a Ring-0 expert.'
    : `Next: ${LEVELS[state.levelIndex + 1].title}`;
  lcContinue.textContent = isLast ? 'Finish' : 'Continue';
  lcOverlay.classList.remove('hidden');
}

lcContinue.addEventListener('click', () => {
  lcOverlay.classList.add('hidden');
  if (state.gameMode === 'ctf') {
    if (state.levelIndex < CTF_LEVELS.length - 1) {
      state.levelIndex += 1;
      ctfInitLevel();
    } else {
      ctfShowScoreboard();
    }
    return;
  }
  if (state.levelIndex < LEVELS.length - 1) {
    state.levelIndex += 1;
    initLevel();
  } else {
    state.completed = true;
    setStatus('[COMPLETE] Congratulations! You completed all 10 kernel incident scenarios!');
    draw();
  }
});

function nextLevelOrWin() {
  showLevelComplete();
}

function interact() {
  if (overlayLocked() || state.completed) return;
  const level = LEVELS[state.levelIndex];
  const { x, y } = state.player;
  const tile = state.map[y][x];

  if (tile === TILE.MENTOR && !state.mentorDone) {
    state.mentorDone = true;
    updateMission('mentor', true);
    openDialog('Mentor Briefing', level.mentorText, `Incident: ${level.incident}\n\n${level.trace}`, 'mentor@kernel', 'mentor');
    setStatus('[+] Briefing complete. Now go to the diagnosis terminal.');
    draw();
    return;
  }

  if (tile === TILE.DIAG && !state.diagnosisDone) {
    if (!state.mentorDone) {
      setStatus('[!] You need to talk to the mentor first.');
      return;
    }
    openTerminal('diag');
    return;
  }

  if (tile === TILE.PATCH && !state.patchDone) {
    if (!state.diagnosisDone) {
      setStatus('[!] Complete the diagnosis step first, then apply the patch.');
      return;
    }
    openTerminal('patch');
    return;
  }

  if (tile === TILE.CONCEPT) {
    level.concepts.forEach((c) => state.concepts.add(c));
    state.map[y][x] = TILE.FLOOR;
    playSfx('concept');
    const cpx = state.mapOffsetX + x * state.tileSize + state.tileSize / 2;
    const cpy = state.mapOffsetY + y * state.tileSize + state.tileSize / 2;
    spawnParticles(cpx, cpy, 12, '#8c63ff', 2);
    setStatus(`[*] Concept unlocked: ${level.concepts.join(', ')}`);
    draw();
    return;
  }

  if (tile === TILE.BONUS && !state.bonusDone) {
    openBonusTerminal();
    return;
  }

  if (tile === TILE.GATE && state.gateOpen) {
    updateMission('gate', true);
    nextLevelOrWin();
    return;
  }

  if (tile === TILE.EXIT && state.gateOpen) {
    state.completed = true;
    stopEnemyTimer();
    setStatus('[COMPLETE] Final exit complete! Kernel Academy operation finished successfully!');
    draw();
  }
}

/* ===============================================
   KEYBOARD HANDLER
   =============================================== */
function keyboardHandler(event) {
  const key = event.key.toLowerCase();

  if (key !== 'escape' && overlayLocked()) return;

  const moveMap = {
    arrowup: [0, -1],
    arrowdown: [0, 1],
    arrowleft: [-1, 0],
    arrowright: [1, 0],
    w: [0, -1],
    s: [0, 1],
    a: [-1, 0],
    d: [1, 0],
  };

  if (moveMap[key]) {
    event.preventDefault();
    move(moveMap[key][0], moveMap[key][1]);
    return;
  }

  if (key === 'e') { event.preventDefault(); interact(); }
  else if (key === 'i') { event.preventDefault(); setStatus('Roadmap: Mentor > Diagnosis > Patch > Gate > Exit'); }
  else if (key === 'h') {
    event.preventDefault();
    const level = state.gameMode === 'ctf' ? CTF_LEVELS[state.levelIndex] : LEVELS[state.levelIndex];
    setStatus(`Hint: ${state.diagnosisDone ? level.patch.hint : level.diagnosis.hint}`);
  } else if (key === 'r') { event.preventDefault(); initLevel(); }
  else if (key === 'escape') {
    event.preventDefault();
    closeDialog();
    closeTerminal();
  }
}

/* ===============================================
   EVENT LISTENERS
   =============================================== */
document.addEventListener('keydown', keyboardHandler);
dialogClose.addEventListener('click', closeDialog);
terminalClose.addEventListener('click', closeTerminal);
terminalSubmit.addEventListener('click', () => submitTerminal());
terminalInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') submitTerminal();
});
panicRetry.addEventListener('click', submitPanicRecovery);
panicInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') submitPanicRecovery();
});

themeSelect.addEventListener('change', (event) => {
  state.theme = event.target.value in THEMES ? event.target.value : 'deep';
  setStatus(`Maze theme updated: ${THEMES[state.theme].name}`);
  draw();
});

/* Main animation loop */
(function gameLoop() {
  if (state.invulnerable || particles.length > 0) draw();
  requestAnimationFrame(gameLoop);
})();

/* ═══════════════════════════════════════════════
   BONUS TERMINAL SYSTEM
   ═══════════════════════════════════════════════ */
const bonusOverlay = document.getElementById('bonus-overlay');
const bonusTitle = document.getElementById('bonus-title');
const bonusText = document.getElementById('bonus-text');
const bonusCode = document.getElementById('bonus-code');
const bonusInput = document.getElementById('bonus-input');
const bonusFeedback = document.getElementById('bonus-feedback');
const bonusSubmit = document.getElementById('bonus-submit');
const bonusClose = document.getElementById('bonus-close');

const BONUS_QUESTIONS = [
  { q: 'What is the main difference between kmalloc and vmalloc?', code: 'void *p1 = kmalloc(4096, GFP_KERNEL);\nvoid *p2 = vmalloc(4096);', answers: ['physical', 'contiguous', 'physically contiguous'], hint: 'One is contiguous in physical memory, the other is not', xp: 60 },
  { q: 'What is the command to load a kernel module?', code: 'ls *.ko\n??? my_module.ko', answers: ['insmod', 'modprobe'], hint: 'ins... or mod...', xp: 40 },
  { q: 'What sysctl setting is used for auto reboot after a Linux kernel panic?', code: 'sysctl -w ???=5', answers: ['kernel.panic', 'panic'], hint: 'kernel.pa...', xp: 50 },
  { q: 'What does copy_from_user return on failure?', code: 'ret = copy_from_user(kbuf, ubuf, len);\nif (ret ???) { ... }', answers: ['non-zero', 'nonzero', '!=0', '!= 0'], hint: 'Number of bytes that could not be copied (non-zero means error)', xp: 50 },
  { q: 'What command is used to list eBPF programs?', code: '??? prog list', answers: ['bpftool', 'bpftool prog list'], hint: 'bpf...', xp: 50 },
  { q: 'How do you read the cmdline of PID 1 through procfs?', code: 'cat /proc/???/cmdline', answers: ['1', '/proc/1/cmdline'], hint: 'Type the PID number', xp: 30 },
  { q: 'What does kernel taint flag G mean?', code: 'cat /proc/sys/kernel/tainted', answers: ['proprietary', 'proprietary module'], hint: 'A proprietary (closed source) module was loaded', xp: 60 },
  { q: 'What file starts syscall tracing for ftrace?', code: 'echo ??? > /sys/kernel/debug/tracing/current_tracer', answers: ['function', 'function_graph'], hint: 'func...', xp: 50 },
  { q: 'In cgroups v2, which file do you write to set a memory limit?', code: 'echo 100M > ???', answers: ['memory.max', 'memory.limit_in_bytes'], hint: 'memory.m...', xp: 60 },
  { q: 'What is the command to clear kernel ring buffer logs?', code: '??? -c', answers: ['dmesg', 'dmesg -c', 'dmesg -C'], hint: 'dme...', xp: 30 },
];

function openBonusTerminal() {
  const q = BONUS_QUESTIONS[state.levelIndex % BONUS_QUESTIONS.length];
  bonusTitle.textContent = `BONUS TERMINAL [+${q.xp} XP]`;
  bonusText.textContent = q.q;
  bonusCode.textContent = q.code;
  bonusInput.value = '';
  bonusFeedback.textContent = '';
  state.bonusOpen = true;
  bonusOverlay.classList.remove('hidden');
  bonusInput.focus();
  playSfx('interact');
}

function submitBonus() {
  const q = BONUS_QUESTIONS[state.levelIndex % BONUS_QUESTIONS.length];
  if (checkAnswer(bonusInput.value, q.answers)) {
    state.xp += q.xp;
    state.levelXpGained += q.xp;
    state.bonusDone = true;
    state.map[state.player.y][state.player.x] = TILE.FLOOR;
    playSfx('correct');
    const bpx = state.mapOffsetX + state.player.x * state.tileSize + state.tileSize / 2;
    const bpy = state.mapOffsetY + state.player.y * state.tileSize + state.tileSize / 2;
    spawnParticles(bpx, bpy, 20, '#ffcc00', 3);
    bonusFeedback.style.color = '#44ff44';
    bonusFeedback.textContent = `Correct! +${q.xp} XP earned!`;
    setTimeout(() => {
      bonusFeedback.style.color = '';
      bonusOverlay.classList.add('hidden');
      state.bonusOpen = false;
      draw();
    }, 800);
  } else {
    playSfx('wrong');
    bonusFeedback.textContent = `Wrong. Hint: ${q.hint}`;
  }
}

function closeBonus() {
  bonusOverlay.classList.add('hidden');
  state.bonusOpen = false;
}

bonusSubmit.addEventListener('click', submitBonus);
bonusClose.addEventListener('click', closeBonus);
bonusInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitBonus(); });

const menuToggle = document.getElementById('menu-toggle');
const backdrop = document.getElementById('backdrop');
const opsPanel = document.querySelector('.ops-panel');

function toggleMenu() {
  const isOpen = opsPanel.classList.contains('active');
  if (isOpen) {
    opsPanel.classList.remove('active');
    backdrop.classList.remove('active');
    menuToggle.innerHTML = '<span style="font-size:24px">☰</span>';
    setStatus('Operator console closed.');
  } else {
    opsPanel.classList.add('active');
    backdrop.classList.add('active');
    menuToggle.innerHTML = '<span style="font-size:24px">✕</span>';
    setStatus('Operator console active.');
  }
}

menuToggle.addEventListener('click', toggleMenu);
backdrop.addEventListener('click', toggleMenu);

/* ═══════════════════════════════════════════════
   MODE SELECTION SYSTEM
   ═══════════════════════════════════════════════ */
const modeOverlay = document.getElementById('mode-overlay');
const modeTraining = document.getElementById('mode-training');
const modeCtf = document.getElementById('mode-ctf');
const gameSubtitle = document.getElementById('game-subtitle');

/* CTF DOM refs */
const flagOverlay = document.getElementById('flag-overlay');
const flagTitle = document.getElementById('flag-title');
const flagValue = document.getElementById('flag-value');
const flagBonusEl = document.getElementById('flag-bonus');
const flagContinue = document.getElementById('flag-continue');

const ctfScoreOverlay = document.getElementById('ctf-scoreboard-overlay');
const ctfScoreTitle = document.getElementById('ctf-score-title');
const ctfTotalFlags = document.getElementById('ctf-total-flags');
const ctfTotalXp = document.getElementById('ctf-total-xp');
const ctfTotalTime = document.getElementById('ctf-total-time');
const ctfFlagsList = document.getElementById('ctf-flags-list');
const ctfScoreRank = document.getElementById('ctf-score-rank');
const ctfScoreClose = document.getElementById('ctf-score-close');

const ctfTimeupOverlay = document.getElementById('ctf-timeup-overlay');
const ctfTimeupLevel = document.getElementById('ctf-timeup-level');
const ctfTimeupRetry = document.getElementById('ctf-timeup-retry');
const ctfTimeupSkip = document.getElementById('ctf-timeup-skip');

const hudTimer = document.getElementById('hud-timer');
const hudFlags = document.getElementById('hud-flags');
const timerDisplay = document.getElementById('timer-display');
const flagsDisplay = document.getElementById('flags-display');

function showModeSelect() {
  modeOverlay.classList.remove('hidden');
}

const trainingInstrOverlay = document.getElementById('training-instructions-overlay');
const trainingInstrStart = document.getElementById('training-instr-start');

modeTraining.addEventListener('click', () => {
  modeOverlay.classList.add('hidden');
  trainingInstrOverlay.classList.remove('hidden');
});

trainingInstrStart.addEventListener('click', () => {
  trainingInstrOverlay.classList.add('hidden');
  state.gameMode = 'training';
  gameRoot.classList.remove('hidden');
  gameSubtitle.textContent = 'kernel incident training ground';
  hudTimer.classList.add('hidden');
  hudFlags.classList.add('hidden');
  state.levelIndex = 0;
  state.xp = 0;
  state.concepts.clear();
  initLevel();
});

const ctfInstrOverlay = document.getElementById('ctf-instructions-overlay');
const ctfInstrStart = document.getElementById('ctf-instr-start');

modeCtf.addEventListener('click', () => {
  modeOverlay.classList.add('hidden');
  ctfInstrOverlay.classList.remove('hidden');
});

ctfInstrStart.addEventListener('click', () => {
  ctfInstrOverlay.classList.add('hidden');
  state.gameMode = 'ctf';
  gameRoot.classList.remove('hidden');
  gameSubtitle.textContent = 'operation ring-zero // CTF mode';
  hudTimer.classList.remove('hidden');
  hudFlags.classList.remove('hidden');
  state.levelIndex = 0;
  state.xp = 0;
  state.concepts.clear();
  state.ctf.flagsCollected = [];
  state.ctf.totalStartTime = Date.now();
  ctfInitLevel();
});

/* ═══════════════════════════════════════════════
   CTF GAME ENGINE
   ═══════════════════════════════════════════════ */

function ctfGetLevels() { return CTF_LEVELS; }

function ctfCurrentLevel() { return CTF_LEVELS[state.levelIndex]; }

function ctfInitLevel() {
  stopEnemyTimer();
  ctfStopTimer();

  const level = ctfCurrentLevel();
  const built = buildLevelMap(level);
  state.map = built.map;
  state.points = built.points;
  state.player = { x: built.points.mentor.x, y: built.points.mentor.y + 1 };
  state.mentorDone = false;
  state.diagnosisDone = false;
  state.patchDone = false;
  state.gateOpen = false;
  state.attemptsUsed = 0;
  state.terminalType = null;
  state.invulnerable = false;
  state.panicSource = null;
  state.bonusDone = false;
  state.levelXpGained = 0;
  state.completed = false;
  particles.length = 0;

  /* CTF-specific resets */
  state.ctf.timer = level.timeLimit;
  state.ctf.levelStartTime = Date.now();

  state.mission = [
    { key: 'mentor', text: 'Read the CTF briefing from mentor', done: false },
    { key: 'diag', text: 'Diagnose the vulnerability', done: false },
    { key: 'patch', text: 'Fix the kernel code to earn the flag', done: false },
    { key: 'gate', text: 'Exit through the opened gate', done: false },
  ];

  calculateViewport();

  /* Spawn enemies */
  state.enemies = spawnEnemies();
  startEnemyTimer();

  /* Start CTF timer */
  ctfStartTimer();

  /* Update UI */
  ctfUpdateHud();
  setStatus(`[CTF ${level.id}] ${level.title} -- Time: ${formatTime(state.ctf.timer)} -- Fix the code to earn the flag!`);
  renderAll();
  draw();
}

function ctfStartTimer() {
  ctfStopTimer();
  state.ctf.timerInterval = setInterval(() => {
    if (overlayLocked()) return;
    state.ctf.timer--;
    ctfUpdateTimerDisplay();
    if (state.ctf.timer <= 0) {
      ctfStopTimer();
      ctfTimeUp();
    }
  }, 1000);
}

function ctfStopTimer() {
  if (state.ctf.timerInterval) {
    clearInterval(state.ctf.timerInterval);
    state.ctf.timerInterval = null;
  }
}

function ctfUpdateTimerDisplay() {
  timerDisplay.textContent = formatTime(state.ctf.timer);
  if (state.ctf.timer <= 30) {
    hudTimer.classList.add('timer-warning');
  } else {
    hudTimer.classList.remove('timer-warning');
  }
}

function ctfUpdateHud() {
  const total = CTF_LEVELS.length;
  const captured = state.ctf.flagsCollected.length;
  flagsDisplay.textContent = `${captured}/${total}`;
  ctfUpdateTimerDisplay();

  const level = ctfCurrentLevel();
  hudLevel.innerHTML = `<span class="stat-icon">⚑</span> CTF: ${level.id} / ${total}`;
  hudXp.innerHTML = `<span class="stat-icon">⬡</span> XP: ${state.xp}`;
  hudAttempts.innerHTML = `<span class="stat-icon">⟳</span> Attempts: ${state.attemptsUsed}/${level.patch.attempts}`;
}

function formatTime(seconds) {
  const m = Math.floor(Math.max(0, seconds) / 60);
  const s = Math.max(0, seconds) % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

/* CTF Flag Capture - called after successful patch */
function ctfCaptureFlag() {
  const level = ctfCurrentLevel();
  updateMission('patch', true);

  const xpBonus = Math.max(50, Math.floor(state.ctf.timer * 2));
  state.xp += xpBonus;
  state.levelXpGained += xpBonus;

  state.patchDone = true;
  state.gateOpen = true;

  playSfx('correct');
  playSfx('gate');
  const fpx = state.mapOffsetX + state.player.x * state.tileSize + state.tileSize / 2;
  const fpy = state.mapOffsetY + state.player.y * state.tileSize + state.tileSize / 2;
  spawnParticles(fpx, fpy, 25, '#ff4466', 3);
  spawnParticles(fpx, fpy, 15, '#44ff44', 2);
  spawnParticles(fpx, fpy, 20, '#5ce29d', 3);

  /* Show flag overlay */
  flagTitle.textContent = `FLAG ${level.id} EARNED`;
  flagValue.textContent = level.flag;
  flagBonusEl.textContent = `+${xpBonus} XP (time bonus: ${state.ctf.timer}s remaining)`;
  flagOverlay.classList.remove('hidden');

  state.ctf.flagsCollected.push({
    id: level.id,
    flag: level.flag,
    title: level.title,
    time: Math.floor((Date.now() - state.ctf.levelStartTime) / 1000),
    xp: xpBonus,
  });

  ctfUpdateHud();
  setStatus(`[FLAG] ${level.flag} -- Code fixed! Gate is open -- proceed to the exit.`);
  draw();
}

flagContinue.addEventListener('click', () => {
  flagOverlay.classList.add('hidden');
});

/* CTF Level Transition */
function ctfNextLevelOrWin() {
  ctfStopTimer();
  stopEnemyTimer();
  updateMission('gate', true);

  const isLast = state.levelIndex >= CTF_LEVELS.length - 1;
  if (isLast) {
    ctfShowScoreboard();
  } else {
    playSfx('levelup');
    const cx = state.mapOffsetX + state.player.x * state.tileSize + state.tileSize / 2;
    const cy = state.mapOffsetY + state.player.y * state.tileSize + state.tileSize / 2;
    spawnParticles(cx, cy, 30, '#ffd37e', 3);

    const level = ctfCurrentLevel();
    lcTitle.textContent = 'CTF LEVEL COMPLETE';
    lcLevel.textContent = level.title;
    lcXp.textContent = `+${state.levelXpGained}`;
    lcTotal.textContent = state.xp;
    lcAttempts.textContent = state.attemptsUsed;
    lcNext.textContent = `Next: ${CTF_LEVELS[state.levelIndex + 1].title}`;
    lcContinue.textContent = 'Continue';
    lcOverlay.classList.remove('hidden');
  }
}

/* Level complete continue is handled in the main lcContinue handler above */

/* CTF Time Up */
function ctfTimeUp() {
  stopEnemyTimer();
  playSfx('panic');
  const level = ctfCurrentLevel();
  ctfTimeupLevel.textContent = level.title;
  ctfTimeupOverlay.classList.remove('hidden');
}

ctfTimeupRetry.addEventListener('click', () => {
  ctfTimeupOverlay.classList.add('hidden');
  ctfInitLevel();
});

ctfTimeupSkip.addEventListener('click', () => {
  ctfTimeupOverlay.classList.add('hidden');
  if (state.levelIndex < CTF_LEVELS.length - 1) {
    state.levelIndex += 1;
    ctfInitLevel();
  } else {
    ctfShowScoreboard();
  }
});

/* CTF Scoreboard */
function ctfShowScoreboard() {
  ctfStopTimer();
  stopEnemyTimer();
  playSfx('levelup');

  const totalTime = Math.floor((Date.now() - state.ctf.totalStartTime) / 1000);
  const captured = state.ctf.flagsCollected.length;
  const total = CTF_LEVELS.length;

  ctfScoreTitle.textContent = captured === total ? 'ALL FLAGS CAPTURED!' : 'CTF COMPLETE';
  ctfTotalFlags.textContent = `${captured}/${total}`;
  ctfTotalXp.textContent = state.xp;
  ctfTotalTime.textContent = formatTime(totalTime);

  /* Build flags list */
  ctfFlagsList.innerHTML = '';
  CTF_LEVELS.forEach((level) => {
    const entry = state.ctf.flagsCollected.find(f => f.id === level.id);
    const div = document.createElement('div');
    if (entry) {
      div.className = 'ctf-flag-entry captured';
      div.innerHTML = `<span class="ctf-flag-status">✓</span><span class="ctf-flag-name">${level.title}</span><span class="ctf-flag-time">${formatTime(entry.time)}</span>`;
    } else {
      div.className = 'ctf-flag-entry missed';
      div.innerHTML = `<span class="ctf-flag-status">✗</span><span class="ctf-flag-name">${level.title}</span><span class="ctf-flag-time">--:--</span>`;
    }
    ctfFlagsList.appendChild(div);
  });

  /* Rank */
  let rank = 'Novice';
  if (captured === total && totalTime < 600) rank = 'Elite Kernel Hacker';
  else if (captured === total) rank = 'Kernel Security Expert';
  else if (captured >= 3) rank = 'CTF Operator';
  else if (captured >= 1) rank = 'Script Kiddie';
  ctfScoreRank.textContent = `Rank: ${rank}`;

  ctfScoreOverlay.classList.remove('hidden');
}

ctfScoreClose.addEventListener('click', () => {
  ctfScoreOverlay.classList.add('hidden');
  gameRoot.classList.add('hidden');
  hudTimer.classList.add('hidden');
  hudFlags.classList.add('hidden');
  state.gameMode = null;
  state.completed = false;
  showModeSelect();
});

/* ═══════════════════════════════════════════════
   CTF RENDER OVERRIDES
   ═══════════════════════════════════════════════ */

/* Patch renderAll function to support CTF mode */
const origRenderAllFn = renderAll;
renderAll = function ctfRenderAll() {
  if (state.gameMode === 'ctf') {
    const level = ctfCurrentLevel();
    if (!level) return;

    hudLevel.innerHTML = `<span class="stat-icon">⚑</span> CTF: ${level.id} / ${CTF_LEVELS.length}`;
    hudXp.innerHTML = `<span class="stat-icon">⬡</span> XP: ${state.xp}`;
    hudAttempts.innerHTML = `<span class="stat-icon">⟳</span> Attempts: ${state.attemptsUsed}/${level.patch.attempts}`;

    const objective = state.gateOpen
      ? 'Flag earned! Go to exit node'
      : !state.mentorDone
        ? 'Read the CTF briefing'
        : !state.diagnosisDone
          ? 'Diagnose the vulnerability'
          : !state.patchDone
            ? 'Fix the kernel code at the patch terminal'
            : 'Proceed to exit';

    operatorStatus.textContent = state.gateOpen ? 'Flag earned' : 'CTF active';
    operatorPosition.textContent = `(${state.player.x}, ${state.player.y})`;
    operatorObjective.textContent = objective;

    incidentTitle.textContent = `${level.title} [${level.difficulty}/5]`;
    incidentDesc.textContent = level.incident;
    incidentTrace.textContent = level.trace;

    themePreview.textContent = `Active theme: ${THEMES[state.theme].name}`;
    themeSelect.value = state.theme;

    renderList(lessonList, level.lesson);

    missionList.innerHTML = '';
    state.mission.forEach((m) => {
      const li = document.createElement('li');
      li.textContent = `[${m.done ? '✓' : ' '}] ${m.text}`;
      missionList.appendChild(li);
    });

    conceptList.innerHTML = '';
    if (!state.concepts.size) {
      renderList(conceptList, ['No concepts unlocked yet.']);
    } else {
      renderList(conceptList, [...state.concepts]);
    }
    return;
  }
  origRenderAllFn();
};

/* ═══════════════════════════════════════════════
   CTF INIT LEVEL OVERRIDE
   ═══════════════════════════════════════════════ */

/* Override initLevel to use correct level set based on mode */
const origInitLevel = initLevel;
initLevel = function modeAwareInitLevel() {
  if (state.gameMode === 'ctf') {
    ctfInitLevel();
    return;
  }
  origInitLevel();
};

/* Override for CTF: same flow as training (M→D→P→G) but flag earned on patch success */
const origInteract = interact;
interact = function modeAwareInteract() {
  if (state.gameMode === 'ctf') {
    if (overlayLocked() || state.completed) return;
    const level = ctfCurrentLevel();
    const { x, y } = state.player;
    const tile = state.map[y][x];

    if (tile === TILE.MENTOR && !state.mentorDone) {
      state.mentorDone = true;
      updateMission('mentor', true);
      state.xp += 18;
      state.levelXpGained += 18;
      openDialog('CTF Briefing', level.mentorText, `Target: ${level.title}\nDifficulty: ${level.difficulty}/5\nTime Limit: ${level.timeLimit}s\nFlag Format: flag{...}`, 'ctf@ring0', 'system');
      setStatus('[+] CTF briefing received. Go to the diagnosis terminal next.');
      draw();
      return;
    }

    if (tile === TILE.DIAG && !state.diagnosisDone) {
      if (!state.mentorDone) {
        setStatus('[!] Read the CTF briefing first.');
        return;
      }
      const payload = level.diagnosis;
      state.terminalType = 'diag';
      terminalTitle.textContent = payload.title;
      terminalText.textContent = payload.question;
      terminalCode.textContent = payload.code;
      terminalInput.value = '';
      terminalInput.placeholder = 'Type your answer...';
      terminalFeedback.textContent = '';
      state.terminalOpen = true;
      terminalOverlay.classList.remove('hidden');
      terminalInput.focus();
      return;
    }

    if (tile === TILE.PATCH && !state.patchDone) {
      if (!state.diagnosisDone) {
        setStatus('[!] Complete the diagnosis step first, then fix the code.');
        return;
      }
      const payload = level.patch;
      state.terminalType = 'patch';
      terminalTitle.textContent = payload.title;
      terminalText.textContent = payload.question;
      terminalCode.textContent = payload.code;
      terminalInput.value = '';
      terminalInput.placeholder = 'Type your answer...';
      terminalFeedback.textContent = '';
      state.terminalOpen = true;
      terminalOverlay.classList.remove('hidden');
      terminalInput.focus();
      return;
    }

    if (tile === TILE.CONCEPT) {
      level.concepts.forEach((c) => state.concepts.add(c));
      state.map[y][x] = TILE.FLOOR;
      playSfx('concept');
      const cpx = state.mapOffsetX + x * state.tileSize + state.tileSize / 2;
      const cpy = state.mapOffsetY + y * state.tileSize + state.tileSize / 2;
      spawnParticles(cpx, cpy, 12, '#8c63ff', 2);
      setStatus(`[*] Concept unlocked: ${level.concepts.join(', ')}`);
      draw();
      return;
    }

    if (tile === TILE.BONUS && !state.bonusDone) {
      openBonusTerminal();
      return;
    }

    if ((tile === TILE.GATE || tile === TILE.EXIT) && state.gateOpen) {
      ctfNextLevelOrWin();
      return;
    }
    return;
  }
  origInteract();
};

/* Override CTF terminal submit for diagnosis and patch answers */
const origSubmitTerminal = submitTerminal;
submitTerminal = function modeAwareSubmitTerminal() {
  if (state.gameMode === 'ctf') {
    const level = ctfCurrentLevel();
    if (!state.terminalType) return;

    if (state.terminalType === 'diag') {
      const payload = level.diagnosis;
      const valid = checkAnswer(terminalInput.value, payload.answers);

      if (!valid) {
        terminalFeedback.textContent = `Wrong answer. Hint: ${payload.hint}`;
        playSfx('wrong');
        return;
      }

      state.xp += payload.xp;
      state.levelXpGained += payload.xp;
      playSfx('correct');
      const pcx = state.mapOffsetX + state.player.x * state.tileSize + state.tileSize / 2;
      const pcy = state.mapOffsetY + state.player.y * state.tileSize + state.tileSize / 2;
      spawnParticles(pcx, pcy, 15, '#57d7c8', 2);

      state.diagnosisDone = true;
      updateMission('diag', true);
      setStatus('[+] Diagnosis complete! Now go to the patch terminal and fix the code.');
      closeTerminal();
      ctfUpdateHud();
      draw();
      return;
    }

    if (state.terminalType === 'patch') {
      const payload = level.patch;
      const valid = checkAnswer(terminalInput.value, payload.answers);
      state.attemptsUsed += 1;

      if (!valid) {
        terminalFeedback.textContent = `Wrong answer. Hint: ${payload.hint}`;
        playSfx('wrong');
        if (state.attemptsUsed >= payload.attempts) {
          closeTerminal();
          triggerPatchPanic();
        }
        ctfUpdateHud();
        return;
      }

      /* Patch successful - earn the flag! */
      state.xp += payload.xp;
      state.levelXpGained += payload.xp;
      closeTerminal();
      ctfCaptureFlag();
      return;
    }
    return;
  }
  origSubmitTerminal();
};

/* Escape key handler for CTF overlays */
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    if (!flagOverlay.classList.contains('hidden')) {
      flagOverlay.classList.add('hidden');
    }
  }
});

/* ===============================================
   START
   =============================================== */
bootSequence();
