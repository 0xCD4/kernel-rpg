const canvas = document.getElementById("gameCanvas");
const ctx = canvas.getContext("2d");

const dialogueNameEl = document.getElementById("dialogueName");
const dialogueTextEl = document.getElementById("dialogueText");
const choicesEl = document.getElementById("choices");

const xpEl = document.getElementById("xp");
const levelCounterEl = document.getElementById("levelCounter");
const progressFillEl = document.getElementById("progressFill");
const questStateEl = document.getElementById("questState");
const stageNameEl = document.getElementById("stageName");
const stageObjectiveEl = document.getElementById("stageObjective");
const incidentTitleEl = document.getElementById("incidentTitle");
const incidentSymptomEl = document.getElementById("incidentSymptom");
const incidentFixEl = document.getElementById("incidentFix");
const runbookListEl = document.getElementById("runbookList");
const conceptListEl = document.getElementById("conceptList");
const missionLogEl = document.getElementById("missionLog");
const codeLabEl = document.getElementById("codeLab");
const codeLabTitleEl = document.getElementById("codeLabTitle");
const codeLabBriefEl = document.getElementById("codeLabBrief");
const codeReferenceEl = document.getElementById("codeReference");
const codeInputEl = document.getElementById("codeInput");
const codeOutputEl = document.getElementById("codeOutput");
const runCodeBtnEl = document.getElementById("runCodeBtn");
const closeCodeBtnEl = document.getElementById("closeCodeBtn");
const instructionModalEl = document.getElementById("instructionModal");
const openInstructionsBtnEl = document.getElementById("openInstructionsBtn");
const closeInstructionsBtnEl = document.getElementById("closeInstructionsBtn");
const closeInstructionsFooterBtnEl = document.getElementById("closeInstructionsFooterBtn");
const instructionBackdropEl = document.querySelector('[data-instruction-close="backdrop"]');
const panicOverlayEl = document.getElementById("panicOverlay");
const panicTextEl = document.getElementById("panicText");
const panicRetryBtnEl = document.getElementById("panicRetryBtn");

const TILE = 40;
const MOVE_DURATION = 0.11;
const MAP_W = 61;
const MAP_H = 29;
const MAX_QUIZ_WRONG = 6;
const MAX_CODE_WRONG = 4;

const DIRECTIONS = {
  up: { dx: 0, dy: -1 },
  down: { dx: 0, dy: 1 },
  left: { dx: -1, dy: 0 },
  right: { dx: 1, dy: 0 }
};

const KEY_TO_DIR = {
  ArrowUp: "up",
  ArrowDown: "down",
  ArrowLeft: "left",
  ArrowRight: "right",
  w: "up",
  W: "up",
  s: "down",
  S: "down",
  a: "left",
  A: "left",
  d: "right",
  D: "right"
};

const REGION_THEMES = [",", ":", "~", ";", "^", "*"];

const CODE_TASKS = {
  boot: {
    title: "Boot Sequencer",
    brief:
      "Complete TODO blocks: firmware handoff, boot stages, and the init chain.",
    reference:
      "Goal: firmware and stages must be in the correct order\n" +
      "Expected output: uefi -> bootloader -> kernel -> init",
    starter:
      "function boot_pipeline(state) {\n" +
      "  // state = { firmware: null, steps: [] }\n" +
      "  // TODO 1: set firmware to uefi\n" +
      "  // TODO 2: push bootloader, kernel, init in order\n" +
      "  // TODO 3: return joined steps with ' -> '\n" +
      "}\n",
    checks: [
      {
        test: /state\.firmware\s*=\s*["'`]uefi["'`]/i,
        pass: "[PASS] Firmware handoff line found.",
        fail: "[FAIL] Set state.firmware to 'uefi'."
      },
      {
        test: /state\.steps\.push\(\s*["'`]bootloader["'`]\s*\)/i,
        pass: "[PASS] Bootloader stage found.",
        fail: "[FAIL] Add bootloader to state.steps."
      },
      {
        test: /state\.steps\.push\(\s*["'`]kernel["'`]\s*\)/i,
        pass: "[PASS] Kernel stage found.",
        fail: "[FAIL] Add kernel to state.steps."
      },
      {
        test: /state\.steps\.push\(\s*["'`]init["'`]\s*\)/i,
        pass: "[PASS] Init stage found.",
        fail: "[FAIL] Add init to state.steps."
      },
      {
        test: /return\s+state\.steps\.join\(\s*["'`]\s*->\s*["'`]\s*\)/i,
        pass: "[PASS] Joined return statement found.",
        fail: "[FAIL] Add return state.steps.join(' -> ')."
      }
    ],
    passSummary: "Boot pipeline coding task passed."
  },
  sched: {
    title: "CFS Picker",
    brief:
      "Sort runnable tasks by vruntime and pick the fairest next task.",
    reference:
      "Goal: filter runnable tasks from rq and select the lowest vruntime\n" +
      "Expected behavior: sort by vruntime and return first runnable entry",
    starter:
      "function pick_next_task(rq) {\n" +
      "  // rq: [{ pid, vruntime, runnable }]\n" +
      "  const runnable = rq.filter((task) => task.runnable);\n" +
      "  // TODO 1: sort runnable by ascending vruntime\n" +
      "  // TODO 2: return first entry or null\n" +
      "}\n",
    checks: [
      {
        test: /rq\.filter\(\s*\(task\)\s*=>\s*task\.runnable\s*\)/i,
        pass: "[PASS] Runnable filter found.",
        fail: "[FAIL] Use rq.filter((task) => task.runnable)."
      },
      {
        test: /runnable\.sort\(\s*\(a,\s*b\)\s*=>\s*a\.vruntime\s*-\s*b\.vruntime\s*\)/i,
        pass: "[PASS] vruntime sort line found.",
        fail: "[FAIL] Add runnable.sort((a, b) => a.vruntime - b.vruntime)."
      },
      {
        test: /return\s+runnable\[0\]\s*\|\|\s*null/i,
        pass: "[PASS] Fallback return line found.",
        fail: "[FAIL] Add return runnable[0] || null."
      }
    ],
    passSummary: "Scheduler coding task passed."
  },
  memory: {
    title: "Page Fault Handler",
    brief:
      "Allocate a frame on missing mapping, count minor faults, and return mapping.",
    reference:
      "Goal: if vm.page_table[addr] is missing, assign vm.alloc_frame()\n" +
      "Also increment vm.stats.minor_faults and return mapped frame",
    starter:
      "function handle_page_fault(vm, addr) {\n" +
      "  // vm.page_table: map, vm.alloc_frame(): frame no,\n" +
      "  // vm.stats.minor_faults: counter\n" +
      "  if (!vm.page_table[addr]) {\n" +
      "    // TODO 1: vm.page_table[addr] = vm.alloc_frame();\n" +
      "  }\n" +
      "  // TODO 2: increment vm.stats.minor_faults\n" +
      "  // TODO 3: return vm.page_table[addr]\n" +
      "}\n",
    checks: [
      {
        test: /if\s*\(\s*!vm\.page_table\[addr\]\s*\)/i,
        pass: "[PASS] Missing-page guard found.",
        fail: "[FAIL] Add if (!vm.page_table[addr]) guard."
      },
      {
        test: /vm\.page_table\[addr\]\s*=\s*vm\.alloc_frame\(\s*\)/i,
        pass: "[PASS] Frame allocation line found.",
        fail: "[FAIL] Add vm.page_table[addr] = vm.alloc_frame();"
      },
      {
        test: /vm\.stats\.minor_faults\s*(\+\+|\+=\s*1)/i,
        pass: "[PASS] Minor fault counter update found.",
        fail: "[FAIL] Add vm.stats.minor_faults++ or += 1."
      },
      {
        test: /return\s+vm\.page_table\[addr\]/i,
        pass: "[PASS] Mapping return line found.",
        fail: "[FAIL] Add return vm.page_table[addr];"
      }
    ],
    passSummary: "Memory coding task passed."
  },
  syscall: {
    title: "Safe Syscall Edge",
    brief:
      "Read path with copy_from_user, validate errors, and safely hand off to VFS.",
    reference:
      "Goal: return -EFAULT on null pointer, -EINVAL on relative path,\n" +
      "and return vfs_open(path, ctx->flags) for valid absolute paths",
    starter:
      "long sys_safe_open(struct ctx *ctx, const char __user *user_ptr) {\n" +
      "  char *path = copy_from_user(user_ptr);\n" +
      "  // TODO 1: if path is null return -EFAULT\n" +
      "  // TODO 2: if path[0] != '/' return -EINVAL\n" +
      "  // TODO 3: return vfs_open(path, ctx->flags)\n" +
      "}\n",
    checks: [
      {
        test: /copy_from_user\s*\(\s*user_ptr\s*\)/i,
        pass: "[PASS] copy_from_user usage found.",
        fail: "[FAIL] Keep char *path = copy_from_user(user_ptr);"
      },
      {
        test: /if\s*\(\s*!path\s*\)\s*{\s*return\s*-EFAULT\s*;\s*}/i,
        pass: "[PASS] -EFAULT guard found.",
        fail: "[FAIL] Add if (!path) { return -EFAULT; }"
      },
      {
        test: /if\s*\(\s*path\s*\[\s*0\s*]\s*!=\s*["'`]\/["'`]\s*\)\s*{\s*return\s*-EINVAL\s*;\s*}/i,
        pass: "[PASS] Path boundary check found.",
        fail: "[FAIL] Add if (path[0] != '/') { return -EINVAL; }"
      },
      {
        test: /return\s+vfs_open\s*\(\s*path\s*,\s*ctx->flags\s*\)\s*;/i,
        pass: "[PASS] vfs_open return found.",
        fail: "[FAIL] Add return vfs_open(path, ctx->flags);"
      }
    ],
    passSummary: "Syscall/VFS coding task passed."
  },
  driver: {
    title: "IRQ Driver Patch",
    brief:
      "Complete interrupt acknowledge, deferred work scheduling, and return code.",
    reference:
      "Goal: IRQ status must be acknowledged and napi_schedule must be called,\n" +
      "handler should return IRQ_HANDLED",
    starter:
      "irqreturn_t net_irq_handler(int irq, void *dev_id) {\n" +
      "  struct netdev *dev = dev_id;\n" +
      "  // TODO 1: writel(IRQ_ACK, dev->mmio + IRQ_STATUS);\n" +
      "  // TODO 2: napi_schedule(&dev->napi);\n" +
      "  // TODO 3: return IRQ_HANDLED;\n" +
      "}\n",
    checks: [
      {
        test: /writel\s*\(\s*IRQ_ACK\s*,\s*dev->mmio\s*\+\s*IRQ_STATUS\s*\)\s*;/i,
        pass: "[PASS] IRQ acknowledge line found.",
        fail: "[FAIL] Add writel(IRQ_ACK, dev->mmio + IRQ_STATUS);"
      },
      {
        test: /napi_schedule\s*\(\s*&dev->napi\s*\)\s*;/i,
        pass: "[PASS] Deferred scheduling line found.",
        fail: "[FAIL] Add napi_schedule(&dev->napi);"
      },
      {
        test: /return\s+IRQ_HANDLED\s*;/i,
        pass: "[PASS] IRQ return line found.",
        fail: "[FAIL] Add return IRQ_HANDLED;"
      }
    ],
    passSummary: "Driver coding task passed."
  },
  sync: {
    title: "Locking and Capability",
    brief:
      "Protect critical section with spinlock and add capability check.",
    reference:
      "Goal: spin_lock -> update -> spin_unlock sequence,\n" +
      "and return capable(CAP_SYS_ADMIN) for mount permission checks",
    starter:
      "void update_stats(struct stats *s, int delta) {\n" +
      "  // TODO 1: spin_lock(&s->lock);\n" +
      "  // TODO 2: s->packets += delta;\n" +
      "  // TODO 3: spin_unlock(&s->lock);\n" +
      "}\n" +
      "\n" +
      "int can_mount(struct cred *c) {\n" +
      "  // TODO 4: return capable(CAP_SYS_ADMIN);\n" +
      "}\n",
    checks: [
      {
        test: /spin_lock\s*\(\s*&s->lock\s*\)\s*;/i,
        pass: "[PASS] spin_lock line found.",
        fail: "[FAIL] Add spin_lock(&s->lock);"
      },
      {
        test: /s->packets\s*\+=\s*delta\s*;/i,
        pass: "[PASS] Critical update line found.",
        fail: "[FAIL] Add s->packets += delta;"
      },
      {
        test: /spin_unlock\s*\(\s*&s->lock\s*\)\s*;/i,
        pass: "[PASS] spin_unlock line found.",
        fail: "[FAIL] Add spin_unlock(&s->lock);"
      },
      {
        test: /return\s+capable\s*\(\s*CAP_SYS_ADMIN\s*\)\s*;/i,
        pass: "[PASS] Capability check found.",
        fail: "[FAIL] Add return capable(CAP_SYS_ADMIN);"
      }
    ],
    passSummary: "Concurrency/security coding task passed."
  }
};

const LEVELS = [
  {
    id: "boot",
    codeTaskId: "boot",
    title: "L1: Boot Pipeline",
    objective: "Production incident: boot panic after update. Restore the full firmware-to-init startup chain.",
    incident: {
      title: "Boot panic: no init process",
      symptom: "dmesg reports 'Kernel panic - not syncing: No working init found'.",
      fix: "Repair UEFI -> bootloader -> kernel -> init flow and verify cmdline assumptions."
    },
    mentorName: "Chief Mentor Ceren",
    mentorColor: "#ffd166",
    mentor: { x: 5, y: 5 },
    terminal: { x: 5, y: 23 },
    briefing: [
      "Incident report: servers are stuck before userspace starts.",
      "Boot handoff is broken between firmware, bootloader, kernel, and PID1.",
      "Your task is to restore a clean startup path."
    ],
    quizSuccess: [
      "You mapped the boot sequence correctly.",
      "Move to the terminal and deploy the Level 1 patch."
    ],
    conceptUnlocks: [
      "UEFI handoff",
      "initramfs role",
      "kernel cmdline"
    ],
    questions: [
      {
        prompt: "Which order correctly describes Linux boot startup?",
        options: [
          "UEFI -> bootloader -> kernel decompress -> PID1",
          "Kernel -> UEFI -> bootloader -> PID1",
          "Bootloader -> userspace shell -> kernel"
        ],
        correct: 0,
        hint: "Firmware starts first and userspace starts last.",
        explain: "Correct. Firmware hands off to bootloader, then kernel, then PID1."
      },
      {
        prompt: "What is initramfs primarily used for?",
        options: [
          "Provide temporary root userspace before real root filesystem mount",
          "Enable GPU acceleration",
          "Increase swap space only"
        ],
        correct: 0,
        hint: "Early boot drivers and scripts are typically loaded here.",
        explain: "Correct. initramfs provides critical tools before root filesystem handoff."
      },
      {
        prompt: "What does init=/bin/bash change on kernel cmdline?",
        options: [
          "It changes which binary is launched as first userspace process",
          "It disables CPU scheduler",
          "It disables MMU"
        ],
        correct: 0,
        hint: "init parameter influences PID1 selection.",
        explain: "Correct. init= defines the first userspace process launched by kernel."
      }
    ]
  },
  {
    id: "sched",
    codeTaskId: "sched",
    title: "L2: Scheduler Arena",
    objective: "Production incident: CPU latency spike. Rebalance CFS fairness and context-switch behavior.",
    incident: {
      title: "Latency spike under CPU load",
      symptom: "Interactive tasks freeze while one CPU-bound process dominates runtime.",
      fix: "Reestablish vruntime fairness and safe context-switch state handling."
    },
    mentorName: "Scheduler Master Deniz",
    mentorColor: "#6ecbff",
    mentor: { x: 15, y: 5 },
    terminal: { x: 15, y: 23 },
    briefing: [
      "Incident report: users complain about major latency spikes.",
      "Scheduler fairness drift causes starvation on the run queue.",
      "Diagnose and patch the CFS selection logic."
    ],
    quizSuccess: [
      "You passed the scheduler diagnostics.",
      "Use the Level 2 terminal patch to unlock the next gate."
    ],
    conceptUnlocks: [
      "CFS vruntime",
      "context switch",
      "nice weight"
    ],
    questions: [
      {
        prompt: "Which metric does CFS use to choose the next task?",
        options: [
          "Task with the smallest vruntime",
          "Largest process ID",
          "Task using most RAM"
        ],
        correct: 0,
        hint: "CFS tracks virtual runtime for fairness.",
        explain: "Correct. CFS scheduling decisions are based on vruntime ordering."
      },
      {
        prompt: "What is required during a context switch?",
        options: [
          "Save and restore task register/context state",
          "Format disk",
          "Reset TCP connections"
        ],
        correct: 0,
        hint: "Without CPU state preservation, switch is unsafe.",
        explain: "Correct. Context switching requires preserving and restoring execution state."
      },
      {
        prompt: "What does nice value generally affect in CFS?",
        options: [
          "Task scheduling weight",
          "Kernel image size",
          "Only GPU frequency"
        ],
        correct: 0,
        hint: "Do not confuse this with real-time policy priorities.",
        explain: "Correct. nice impacts CFS weight and CPU time share."
      }
    ]
  },
  {
    id: "memory",
    codeTaskId: "memory",
    title: "L3: Memory Citadel",
    objective: "Production incident: memory pressure and fault storm. Stabilize page-fault handling path.",
    incident: {
      title: "Page-fault storm in userspace service",
      symptom: "Service pauses and logs repeated minor faults with rising memory pressure.",
      fix: "Apply correct mapping logic, respect COW behavior, and keep allocation path efficient."
    },
    mentorName: "Memory Warden Ekin",
    mentorColor: "#89f3c4",
    mentor: { x: 25, y: 5 },
    terminal: { x: 25, y: 23 },
    briefing: [
      "Incident report: service throughput collapses under memory pressure.",
      "Fault handling and allocator behavior look inconsistent.",
      "You need to recover a stable memory path."
    ],
    quizSuccess: [
      "Memory checks are clean.",
      "Deploy from the Level 3 terminal to open the next sector."
    ],
    conceptUnlocks: [
      "page fault path",
      "copy-on-write",
      "slab allocator"
    ],
    questions: [
      {
        prompt: "When a userspace page fault occurs, what does kernel usually do?",
        options: [
          "Map or swap in the needed page and continue execution",
          "Always reset the system",
          "Close all file descriptors"
        ],
        correct: 0,
        hint: "A page fault is not always fatal.",
        explain: "Correct. Valid faults are handled and execution continues."
      },
      {
        prompt: "What is copy-on-write behavior after fork()?",
        options: [
          "Pages are shared until write, then copied on modification",
          "All memory is duplicated immediately",
          "MMU is disabled"
        ],
        correct: 0,
        hint: "Initial memory-copy overhead is minimized.",
        explain: "Correct. COW delays copying until a write operation occurs."
      },
      {
        prompt: "What does slab allocator improve?",
        options: [
          "Fast reuse allocation for frequently used kernel objects",
          "Only network packet encryption",
          "UEFI firmware update flow"
        ],
        correct: 0,
        hint: "It optimizes alloc/free cost for repeated kernel object shapes.",
        explain: "Correct. Slab caches object types for faster allocation paths."
      }
    ]
  },
  {
    id: "syscall",
    codeTaskId: "syscall",
    title: "L4: Syscall District",
    objective: "Production incident: syscall boundary crash. Harden user-pointer and VFS validation path.",
    incident: {
      title: "Unsafe user pointer crashes syscall path",
      symptom: "Invalid userspace pointer causes faults during open-style syscall handling.",
      fix: "Validate pointers, enforce path checks, and return safe kernel errors."
    },
    mentorName: "VFS Scribe Lale",
    mentorColor: "#ffe59a",
    mentor: { x: 35, y: 5 },
    terminal: { x: 35, y: 23 },
    briefing: [
      "Incident report: malformed userspace input is crashing file-open flow.",
      "Boundary checks are incomplete around syscall and VFS layers.",
      "Patch the edge safely without breaking valid requests."
    ],
    quizSuccess: [
      "You cleared syscall and VFS checks.",
      "Activate the Level 4 terminal to open the forge sector."
    ],
    conceptUnlocks: [
      "syscall dispatch",
      "VFS inode",
      "copy_from_user"
    ],
    questions: [
      {
        prompt: "Which best describes a typical syscall flow?",
        options: [
          "libc wrapper -> syscall instruction -> kernel dispatch",
          "Kernel thread -> BIOS -> user process",
          "initramfs -> GPU driver -> shell"
        ],
        correct: 0,
        hint: "A controlled transition from user mode to kernel mode occurs.",
        explain: "Correct. Syscall instruction transfers control to kernel dispatch tables."
      },
      {
        prompt: "In VFS, what does an inode mostly represent?",
        options: [
          "Filesystem-independent file metadata object",
          "Only a physical disk sector address",
          "Only a network packet header"
        ],
        correct: 0,
        hint: "inode carries object metadata rather than filename itself.",
        explain: "Correct. inode is metadata-centric; directory entries map names to inodes."
      },
      {
        prompt: "Why is copy_from_user used in kernel code?",
        options: [
          "To safely validate and copy user pointers into kernel space",
          "To speed up scheduler",
          "To perform interrupt masking"
        ],
        correct: 0,
        hint: "Direct user pointer dereference is unsafe in kernel mode.",
        explain: "Correct. User memory is isolated from kernel memory; safe copy APIs are required."
      }
    ]
  },
  {
    id: "driver",
    codeTaskId: "driver",
    title: "L5: Driver Forge",
    objective: "Production incident: NIC driver regression. Stop interrupt storm and restore stable packet path.",
    incident: {
      title: "NIC interrupt storm after driver update",
      symptom: "IRQ rate spikes, softirq backlog grows, and packet loss increases.",
      fix: "Acknowledge IRQ fast, defer heavy work, and keep DMA mapping correct."
    },
    mentorName: "Driver Smith Aras",
    mentorColor: "#ff9d62",
    mentor: { x: 45, y: 5 },
    terminal: { x: 45, y: 23 },
    briefing: [
      "Incident report: latest driver build caused packet drops in production.",
      "Top-half handler is doing too much and ACK path is unstable.",
      "Repair the IRQ/DMA flow before rollout resumes."
    ],
    quizSuccess: [
      "Driver stage is stable.",
      "Use Level 5 terminal deployment to unlock the final vault gate."
    ],
    conceptUnlocks: [
      "irq top-half",
      "dma mapping",
      "file_operations"
    ],
    questions: [
      {
        prompt: "What is a good practice for IRQ top-half handlers?",
        options: [
          "Keep handler short and defer heavy work",
          "Run long blocking operations",
          "Sleep repeatedly inside handler"
        ],
        correct: 0,
        hint: "Interrupt context should perform minimum immediate work.",
        explain: "Correct. Long operations should move to workqueues or threaded IRQ paths."
      },
      {
        prompt: "Why are dma_map_* APIs needed during DMA setup?",
        options: [
          "To establish correct and safe device-visible memory mapping",
          "To change terminal color",
          "To reset syscall table"
        ],
        correct: 0,
        hint: "CPU virtual addresses are not always directly valid for devices.",
        explain: "Correct. DMA mapping APIs provide proper translation for device access."
      },
      {
        prompt: "In a basic char driver, API surface is usually defined by what?",
        options: [
          "file_operations callback structure",
          "A single /etc/fstab line",
          "Only initramfs script"
        ],
        correct: 0,
        hint: "Think about open/read/write/ioctl callbacks.",
        explain: "Correct. file_operations exposes character device behavior to userspace."
      }
    ]
  },
  {
    id: "sync",
    codeTaskId: "sync",
    title: "L6: Concurrency Vault",
    objective: "Production incident: race + privilege bug. Secure concurrent updates and capability checks.",
    incident: {
      title: "Race condition corrupts shared stats",
      symptom: "Parallel traffic corrupts counters; privileged mount path lacks strict gating.",
      fix: "Use correct lock discipline and enforce capability-based authorization."
    },
    mentorName: "Lockmaster Bora",
    mentorColor: "#9ce6ff",
    mentor: { x: 55, y: 5 },
    terminal: { x: 55, y: 23 },
    briefing: [
      "Incident report: shared stats drift under concurrency load.",
      "Security review also found weak privilege boundaries.",
      "Finalize with a lock-safe, least-privilege patch."
    ],
    quizSuccess: [
      "You passed concurrency and security validation.",
      "After final terminal deployment, synchronize with Kernel Core."
    ],
    conceptUnlocks: [
      "spinlock vs mutex",
      "RCU grace period",
      "Linux capabilities"
    ],
    questions: [
      {
        prompt: "In which context is spinlock generally the right choice?",
        options: [
          "Short critical sections in atomic non-sleep context",
          "Long blocking disk I/O",
          "Only userspace threads"
        ],
        correct: 0,
        hint: "Sleeping while holding spinlock is dangerous.",
        explain: "Correct. Spinlocks are for short non-sleep critical regions."
      },
      {
        prompt: "What is the core advantage of RCU?",
        options: [
          "Reduce read-side locking cost and defer reclamation",
          "Remove all locks entirely",
          "Only update BIOS tables"
        ],
        correct: 0,
        hint: "Readers stay fast; reclamation occurs after grace period.",
        explain: "Correct. RCU keeps reads cheap and defers destruction safely."
      },
      {
        prompt: "What does Linux capabilities model provide?",
        options: [
          "Split root privilege into fine-grained least-privilege units",
          "Automatically run all processes as root",
          "Disable scheduler"
        ],
        correct: 0,
        hint: "Think least-privilege instead of monolithic superuser power.",
        explain: "Correct. Capabilities support least-privilege security design."
      }
    ]
  }
];

const world = buildWorld();
const finalCore = { x: 58, y: 14 };

const state = {
  time: 0,
  pressed: new Set(),
  lastDir: "right",
  xp: 0,
  knowledge: [],
  logs: ["Start: speak with the Level 1 mentor."],
  finalSync: false,
  levelStates: LEVELS.map(() => ({
    started: false,
    quizPassed: false,
    codingPassed: false,
    terminalActivated: false,
    quizWrong: 0,
    codeWrong: 0
  })),
  codeDrafts: {},
  codeLab: {
    active: false,
    levelIndex: -1
  },
  panicActive: false,
  instructionsOpen: false,
  player: {
    x: 3,
    y: 14,
    dir: "right",
    moving: false,
    moveProgress: 0,
    startX: 3,
    startY: 14,
    targetX: 3,
    targetY: 14,
    renderX: 3 * TILE + TILE / 2,
    renderY: 14 * TILE + TILE / 2
  },
  dialogue: {
    active: false,
    mode: "none",
    speaker: "",
    lines: [],
    index: 0,
    choices: [],
    onClose: null,
    quizLevelIndex: -1,
    quizQuestionIndex: -1
  }
};

function buildWorld() {
  const grid = Array.from({ length: MAP_H }, () =>
    Array.from({ length: MAP_W }, () => "#")
  );

  const yMin = 1;
  const yMax = MAP_H - 2;

  for (let i = 0; i < LEVELS.length; i += 1) {
    const level = LEVELS[i];
    const xMin = 1 + i * 10;
    const xMax = xMin + 8;
    const theme = REGION_THEMES[i] ?? ".";

    carveRegionMaze(grid, xMin, xMax, yMin, yMax, theme, 7001 + i * 311);

    const entry = { x: xMin, y: 14 };
    const exit = { x: xMax, y: 14 };
    const mentorNode = { x: level.mentor.x, y: level.mentor.y };
    const terminalNode = { x: level.terminal.x, y: level.terminal.y };

    carveRoute(grid, entry, mentorNode, theme, i % 2 === 0 ? "x" : "y");
    carveRoute(grid, mentorNode, terminalNode, theme, i % 2 === 0 ? "y" : "x");
    carveRoute(grid, terminalNode, exit, theme, i % 2 === 0 ? "x" : "y");

    grid[entry.y][entry.x] = theme;
    grid[exit.y][exit.x] = theme;
  }

  const gateColumns = [10, 20, 30, 40, 50];
  gateColumns.forEach((gateX, gateIdx) => {
    for (let y = 1; y < MAP_H - 1; y += 1) {
      grid[y][gateX] = "#";
    }
    grid[14][gateX] = String(gateIdx + 1);
  });

  fillRect(grid, 56, 12, 3, 5, "*");
  grid[14][59] = "*";
  grid[14][3] = REGION_THEMES[0];
  grid[13][3] = REGION_THEMES[0];
  grid[15][3] = REGION_THEMES[0];

  return grid;
}

function createRng(seed) {
  let value = seed >>> 0;
  return () => {
    value = (value * 1664525 + 1013904223) >>> 0;
    return value / 4294967296;
  };
}

function carveRegionMaze(grid, xMin, xMax, yMin, yMax, theme, seed) {
  const rng = createRng(seed);
  const startX = xMin % 2 === 1 ? xMin : xMin + 1;
  const startY = yMin % 2 === 1 ? yMin : yMin + 1;
  const stack = [{ x: startX, y: startY }];
  grid[startY][startX] = theme;

  while (stack.length > 0) {
    const current = stack[stack.length - 1];
    const options = [];

    const candidates = [
      { dx: 0, dy: -2 },
      { dx: 2, dy: 0 },
      { dx: 0, dy: 2 },
      { dx: -2, dy: 0 }
    ];

    for (const candidate of candidates) {
      const nx = current.x + candidate.dx;
      const ny = current.y + candidate.dy;
      if (nx < xMin || nx > xMax || ny < yMin || ny > yMax) {
        continue;
      }
      if (grid[ny][nx] === "#") {
        options.push(candidate);
      }
    }

    if (options.length === 0) {
      stack.pop();
      continue;
    }

    const pick = options[Math.floor(rng() * options.length)];
    const nx = current.x + pick.dx;
    const ny = current.y + pick.dy;
    const mx = current.x + pick.dx / 2;
    const my = current.y + pick.dy / 2;

    grid[my][mx] = theme;
    grid[ny][nx] = theme;
    stack.push({ x: nx, y: ny });
  }
}

function carveRoute(grid, from, to, theme, firstAxis = "x") {
  let x = from.x;
  let y = from.y;
  grid[y][x] = theme;

  const walkAxis = (axis) => {
    if (axis === "x") {
      const direction = to.x >= x ? 1 : -1;
      while (x !== to.x) {
        x += direction;
        grid[y][x] = theme;
      }
      return;
    }

    const direction = to.y >= y ? 1 : -1;
    while (y !== to.y) {
      y += direction;
      grid[y][x] = theme;
    }
  };

  walkAxis(firstAxis);
  walkAxis(firstAxis === "x" ? "y" : "x");
}

function fillRect(grid, x0, y0, width, height, tile) {
  for (let y = y0; y < y0 + height; y += 1) {
    for (let x = x0; x < x0 + width; x += 1) {
      if (x > 0 && x < MAP_W - 1 && y > 0 && y < MAP_H - 1) {
        grid[y][x] = tile;
      }
    }
  }
}

function getCurrentLevelIndex() {
  for (let i = 0; i < state.levelStates.length; i += 1) {
    if (!state.levelStates[i].terminalActivated) {
      return i;
    }
  }
  return LEVELS.length;
}

function allLevelsCompleted() {
  return getCurrentLevelIndex() >= LEVELS.length;
}

function pushLog(text) {
  state.logs.unshift(text);
  if (state.logs.length > 8) {
    state.logs.length = 8;
  }
  renderLogs();
}

function unlockConcept(concept) {
  if (!state.knowledge.includes(concept)) {
    state.knowledge.push(concept);
    renderConcepts();
  }
}

function getCodeTaskForLevel(levelIndex) {
  const level = LEVELS[levelIndex];
  if (!level) {
    return null;
  }
  return CODE_TASKS[level.codeTaskId] ?? null;
}

function openCodeLab(levelIndex) {
  const level = LEVELS[levelIndex];
  const task = getCodeTaskForLevel(levelIndex);
  if (!level || !task) {
    return;
  }

  state.codeLab.active = true;
  state.codeLab.levelIndex = levelIndex;
  state.pressed.clear();

  codeLabTitleEl.textContent = `${level.title} - ${task.title}`;
  codeLabBriefEl.textContent = task.brief;
  codeReferenceEl.textContent = task.reference;
  codeInputEl.value = state.codeDrafts[levelIndex] ?? task.starter;
  codeOutputEl.textContent =
    "Compiler idle. Use Run Tests to validate TODO sections.";

  codeLabEl.hidden = false;
  codeInputEl.focus();
}

function closeCodeLab() {
  if (!state.codeLab.active) {
    return;
  }

  const levelIndex = state.codeLab.levelIndex;
  if (levelIndex >= 0) {
    state.codeDrafts[levelIndex] = codeInputEl.value;
  }

  state.codeLab.active = false;
  state.codeLab.levelIndex = -1;
  codeLabEl.hidden = true;
  setAmbientDialogue();
}

function openInstructions(shouldFocusClose = true) {
  if (!instructionModalEl || state.instructionsOpen || state.codeLab.active) {
    return;
  }

  state.instructionsOpen = true;
  state.pressed.clear();
  instructionModalEl.hidden = false;
  document.body.classList.add("modal-open");

  if (shouldFocusClose) {
    closeInstructionsBtnEl?.focus();
  }
}

function closeInstructions(shouldFocusOpen = true) {
  if (!instructionModalEl || !state.instructionsOpen) {
    return;
  }

  state.instructionsOpen = false;
  state.pressed.clear();
  instructionModalEl.hidden = true;
  document.body.classList.remove("modal-open");

  if (shouldFocusOpen) {
    openInstructionsBtnEl?.focus();
  }
}

function triggerKernelPanic(levelIndex, reason) {
  const level = LEVELS[levelIndex];
  state.panicActive = true;
  state.pressed.clear();

  const panicLines = [
    "---[ Kernel panic - not syncing ]---",
    "",
    `Level: ${level.title}`,
    `Reason: ${reason}`,
    "",
    "Call Trace:",
    "  patch_apply+0x42/0x80",
    `  ${level.id}_handler+0x1a/0x30`,
    "  do_level_check+0x6f/0xb0",
    "  entry_ACADEMY_64+0x11a/0x120",
    "",
    `RIP: 0010:${level.id}_patch_validate+0x29/0x50`,
    "RSP: 0018:ffffa32c00013e80 EFLAGS: 00010246",
    "",
    "---[ end Kernel panic - not syncing ]---",
    "",
    "Too many failed attempts. The kernel cannot continue.",
    "Press [ Retry Level ] to reboot and try again."
  ];

  panicTextEl.textContent = panicLines.join("\n");
  panicOverlayEl.hidden = false;
  panicRetryBtnEl.focus();
}

function retryFromPanic() {
  if (!state.panicActive) {
    return;
  }

  const current = getCurrentLevelIndex();
  if (current < LEVELS.length) {
    const ls = state.levelStates[current];
    ls.quizWrong = 0;
    ls.codeWrong = 0;
    ls.started = false;
    ls.quizPassed = false;
    ls.codingPassed = false;
    delete state.codeDrafts[current];
  }

  state.panicActive = false;
  panicOverlayEl.hidden = true;

  closeDialogue();
  closeCodeLab();
  updateHud();
  pushLog("System rebooted. Level reset for retry.");
}

function toggleInstructions() {
  if (state.instructionsOpen) {
    closeInstructions();
    return;
  }
  openInstructions();
}

function runCodeLabTests() {
  if (!state.codeLab.active) {
    return;
  }

  const levelIndex = state.codeLab.levelIndex;
  const level = LEVELS[levelIndex];
  const levelState = state.levelStates[levelIndex];
  const task = getCodeTaskForLevel(levelIndex);
  if (!level || !levelState || !task) {
    return;
  }

  const source = codeInputEl.value;
  state.codeDrafts[levelIndex] = source;

  const outputLines = [`Compiling ${level.title}...`];
  let passedAll = true;

  task.checks.forEach((check) => {
    const passed = check.test.test(source);
    outputLines.push(passed ? check.pass : check.fail);
    if (!passed) {
      passedAll = false;
    }
  });

  if (passedAll) {
    if (!levelState.codingPassed) {
      levelState.codingPassed = true;
      state.xp += 100;
      pushLog(`${level.title}: coding lab tests passed.`);
      updateHud();
    }
    outputLines.push(`[OK] ${task.passSummary}`);
    outputLines.push("Terminal deployment permission unlocked. Press E on terminal again.");
  } else {
    levelState.codeWrong += 1;
    const remaining = MAX_CODE_WRONG - levelState.codeWrong;

    if (levelState.codeWrong >= MAX_CODE_WRONG) {
      closeCodeLab();
      triggerKernelPanic(levelIndex, "coding patch failed too many times");
      return;
    }

    outputLines.push(`[WARN] Missing steps detected. Attempts remaining: ${remaining}. Complete TODO lines and retry.`);
  }

  codeOutputEl.textContent = outputLines.join("\n");
}

function updateHud() {
  const current = getCurrentLevelIndex();
  const completed = state.levelStates.filter((level) => level.terminalActivated).length;

  xpEl.textContent = `XP: ${state.xp}`;
  levelCounterEl.textContent =
    current < LEVELS.length
      ? `Level: ${current + 1} / ${LEVELS.length}`
      : `Level: ${LEVELS.length} / ${LEVELS.length} (Done)`;

  progressFillEl.style.width = `${(completed / LEVELS.length) * 100}%`;

  if (current < LEVELS.length) {
    const level = LEVELS[current];
    const levelState = state.levelStates[current];
    stageNameEl.textContent = level.title;
    stageObjectiveEl.textContent = level.objective;
    incidentTitleEl.textContent = level.incident?.title ?? "Kernel incident in progress";
    incidentSymptomEl.textContent = `Symptom: ${level.incident?.symptom ?? "Investigate logs and mentor clues."}`;
    incidentFixEl.textContent = `Fix target: ${level.incident?.fix ?? "Apply safe kernel patch and validate behavior."}`;

    if (!levelState.started) {
      questStateEl.textContent = `Status: Talk to mentor for ${level.title}`;
    } else if (!levelState.quizPassed) {
      questStateEl.textContent = `Status: Complete quiz for ${level.title}`;
    } else if (!levelState.codingPassed) {
      questStateEl.textContent = `Status: Complete coding lab for ${level.title}`;
    } else {
      questStateEl.textContent = `Status: Activate terminal for ${level.title}`;
    }

    renderRunbook([
      {
        done: levelState.started,
        text: "Meet mentor and read incident brief"
      },
      {
        done: levelState.quizPassed,
        text: "Pass diagnosis quiz"
      },
      {
        done: levelState.codingPassed,
        text: "Patch terminal coding task"
      },
      {
        done: levelState.terminalActivated,
        text: "Deploy patch to unlock gate"
      }
    ]);
  } else if (!state.finalSync) {
    stageNameEl.textContent = "Final: Kernel Core";
    stageObjectiveEl.textContent =
      "All levels are complete. Synchronize with the final Kernel Core.";
    incidentTitleEl.textContent = "Final synchronization";
    incidentSymptomEl.textContent = "Symptom: all gates open, awaiting core synchronization.";
    incidentFixEl.textContent = "Fix target: interact with Kernel Core to finalize graduation.";
    questStateEl.textContent = "Status: Waiting for final core synchronization";
    renderRunbook([
      { done: true, text: "All six kernel incidents resolved" },
      { done: state.finalSync, text: "Complete final core synchronization" }
    ]);
  } else {
    stageNameEl.textContent = "Program Complete";
    stageObjectiveEl.textContent =
      "Congratulations. You completed all Ring-0 Academy stages.";
    incidentTitleEl.textContent = "No active incident";
    incidentSymptomEl.textContent = "Symptom: system stable across all kernel layers.";
    incidentFixEl.textContent = "Fix target: none. Review logs or replay levels for practice.";
    questStateEl.textContent = "Status: Graduated";
    renderRunbook([{ done: true, text: "Graduated from Ring-0 Academy" }]);
  }
}

function renderRunbook(steps) {
  if (!runbookListEl) {
    return;
  }

  runbookListEl.innerHTML = "";
  steps.forEach((step) => {
    const li = document.createElement("li");
    li.className = step.done ? "runbook-done" : "runbook-pending";
    li.textContent = `${step.done ? "[x]" : "[ ]"} ${step.text}`;
    runbookListEl.appendChild(li);
  });
}

function renderConcepts() {
  conceptListEl.innerHTML = "";
  if (state.knowledge.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No concepts unlocked yet.";
    conceptListEl.appendChild(li);
    return;
  }

  state.knowledge.forEach((concept) => {
    const li = document.createElement("li");
    li.textContent = concept;
    conceptListEl.appendChild(li);
  });
}

function renderLogs() {
  missionLogEl.innerHTML = "";
  state.logs.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    missionLogEl.appendChild(li);
  });
}

function setAmbientDialogue() {
  if (state.dialogue.active) {
    return;
  }

  if (state.finalSync) {
    dialogueNameEl.textContent = "Kernel Core";
    dialogueTextEl.textContent =
      "All level terminals validated. You are ready for advanced kernel labs.";
    choicesEl.hidden = true;
    return;
  }

  if (allLevelsCompleted()) {
    dialogueNameEl.textContent = "Kernel Core";
    dialogueTextEl.textContent =
      "All gates are open. Enter the core chamber and complete final sync.";
    choicesEl.hidden = true;
    return;
  }

  const current = getCurrentLevelIndex();
  const level = LEVELS[current];
  const levelState = state.levelStates[current];
  dialogueNameEl.textContent = level.mentorName;
  if (!levelState.started) {
    dialogueTextEl.textContent = `Press E to start incident triage: ${level.incident?.title ?? level.title}.`;
  } else if (!levelState.quizPassed) {
    dialogueTextEl.textContent = "Step 2/4: finish diagnosis quiz, then continue to terminal patch lab.";
  } else if (!levelState.codingPassed) {
    dialogueTextEl.textContent = "Step 3/4: pass coding lab tests at terminal.";
  } else {
    dialogueTextEl.textContent = "Step 4/4: deploy the validated patch at terminal to open the gate.";
  }
  choicesEl.hidden = true;
}

function openMessage(speaker, lines, onClose = null) {
  state.pressed.clear();
  state.dialogue.active = true;
  state.dialogue.mode = "message";
  state.dialogue.speaker = speaker;
  state.dialogue.lines = lines;
  state.dialogue.index = 0;
  state.dialogue.choices = [];
  state.dialogue.onClose = onClose;
  state.dialogue.quizLevelIndex = -1;
  state.dialogue.quizQuestionIndex = -1;
  renderDialogue();
}

function openQuiz(levelIndex, questionIndex) {
  const level = LEVELS[levelIndex];
  const question = level.questions[questionIndex];
  if (!level || !question) return;

  state.pressed.clear();
  state.dialogue.active = true;
  state.dialogue.mode = "quiz";
  state.dialogue.speaker = `${level.mentorName} (${level.title})`;
  state.dialogue.lines = [question.prompt];
  state.dialogue.index = 0;
  state.dialogue.choices = question.options;
  state.dialogue.onClose = null;
  state.dialogue.quizLevelIndex = levelIndex;
  state.dialogue.quizQuestionIndex = questionIndex;
  renderDialogue();
}

function closeDialogue() {
  state.dialogue.active = false;
  state.dialogue.mode = "none";
  state.dialogue.speaker = "";
  state.dialogue.lines = [];
  state.dialogue.index = 0;
  state.dialogue.choices = [];
  state.dialogue.onClose = null;
  state.dialogue.quizLevelIndex = -1;
  state.dialogue.quizQuestionIndex = -1;
  setAmbientDialogue();
}

function renderDialogue() {
  if (!state.dialogue.active) {
    setAmbientDialogue();
    return;
  }

  dialogueNameEl.textContent = state.dialogue.speaker;
  dialogueTextEl.textContent = state.dialogue.lines[state.dialogue.index] ?? "";

  if (state.dialogue.mode !== "quiz") {
    choicesEl.hidden = true;
    choicesEl.innerHTML = "";
    return;
  }

  choicesEl.hidden = false;
  choicesEl.innerHTML = "";

  state.dialogue.choices.forEach((choice, idx) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "choice";
    button.textContent = `${idx + 1}. ${choice}`;
    button.addEventListener("click", () => answerQuiz(idx + 1));
    choicesEl.appendChild(button);
  });
}

function advanceDialogue() {
  if (!state.dialogue.active || state.dialogue.mode !== "message") {
    return;
  }

  if (state.dialogue.index < state.dialogue.lines.length - 1) {
    state.dialogue.index += 1;
    renderDialogue();
    return;
  }

  const callback = state.dialogue.onClose;
  closeDialogue();
  if (typeof callback === "function") {
    callback();
  }
}

function answerQuiz(choiceNumber) {
  if (!state.dialogue.active || state.dialogue.mode !== "quiz") {
    return;
  }

  const levelIndex = state.dialogue.quizLevelIndex;
  const questionIndex = state.dialogue.quizQuestionIndex;
  if (levelIndex < 0 || questionIndex < 0) {
    return;
  }

  const level = LEVELS[levelIndex];
  const question = level.questions[questionIndex];
  if (!question) {
    return;
  }

  if (choiceNumber - 1 === question.correct) {
    state.xp += 35;
    updateHud();

    const lastQuestion = questionIndex >= level.questions.length - 1;
    if (!lastQuestion) {
      openMessage(level.mentorName, [
        question.explain,
        `Good. Moving to next question (${questionIndex + 2}/${level.questions.length}).`
      ], () => {
        openQuiz(levelIndex, questionIndex + 1);
      });
      return;
    }

    state.levelStates[levelIndex].quizPassed = true;
    state.xp += 55;
    pushLog(`${level.title}: quiz package completed.`);
    updateHud();

    openMessage(level.mentorName, [
      question.explain,
      ...level.quizSuccess,
      "Next step: pass coding lab tests at the terminal."
    ]);
    return;
  }

  state.xp = Math.max(0, state.xp - 8);
  state.levelStates[levelIndex].quizWrong += 1;
  updateHud();

  if (state.levelStates[levelIndex].quizWrong >= MAX_QUIZ_WRONG) {
    closeDialogue();
    triggerKernelPanic(levelIndex, "quiz validation exceeded maximum attempts");
    return;
  }

  const remaining = MAX_QUIZ_WRONG - state.levelStates[levelIndex].quizWrong;
  openMessage(level.mentorName, [
    `Incorrect answer. Hint: ${question.hint}`,
    `Attempts remaining: ${remaining}. Press E when ready to retry.`
  ]);
}

function getNearbyMentor() {
  let nearest = null;
  let best = Number.POSITIVE_INFINITY;

  LEVELS.forEach((level, idx) => {
    const dist =
      Math.abs(level.mentor.x - state.player.x) +
      Math.abs(level.mentor.y - state.player.y);
    if (dist <= 1 && dist < best) {
      nearest = { levelIndex: idx, level };
      best = dist;
    }
  });

  return nearest;
}

function getNearbyTerminal() {
  let nearest = null;
  let best = Number.POSITIVE_INFINITY;

  LEVELS.forEach((level, idx) => {
    const dist =
      Math.abs(level.terminal.x - state.player.x) +
      Math.abs(level.terminal.y - state.player.y);
    if (dist <= 1 && dist < best) {
      nearest = { levelIndex: idx, level };
      best = dist;
    }
  });

  return nearest;
}

function isNearFinalCore() {
  return (
    Math.abs(finalCore.x - state.player.x) +
      Math.abs(finalCore.y - state.player.y) <=
    1
  );
}

function handleMentorInteract(levelIndex) {
  const current = getCurrentLevelIndex();
  const level = LEVELS[levelIndex];
  const levelState = state.levelStates[levelIndex];

  if (levelIndex > current) {
    openMessage(level.mentorName, [
      "This region is still locked.",
      `Complete terminal deployment for ${LEVELS[current].title} first.`
    ]);
    return;
  }

  if (levelState.terminalActivated) {
    openMessage(level.mentorName, [
      `${level.title} is already complete.`,
      "You can reopen questions anytime to refresh your notes."
    ]);
    return;
  }

  if (!levelState.started) {
    levelState.started = true;
    state.xp += 18;
    pushLog(`${level.title}: mentor briefing received.`);
    updateHud();

    openMessage(
      level.mentorName,
      [
        `Incident: ${level.incident?.title ?? "Kernel regression detected"}`,
        `Observed symptom: ${level.incident?.symptom ?? "Review logs and traces."}`,
        `Fix target: ${level.incident?.fix ?? "Apply validated patch safely."}`,
        ...level.briefing,
        "If you are ready, starting assessment now."
      ],
      () => {
        openQuiz(levelIndex, 0);
      }
    );
    return;
  }

  if (!levelState.quizPassed) {
    openQuiz(levelIndex, 0);
    return;
  }

  if (!levelState.codingPassed) {
    openMessage(level.mentorName, [
      "Quiz is complete.",
      "Now open coding lab at terminal and finish TODO lines."
    ]);
    return;
  }

  openMessage(level.mentorName, [
    "Quiz and coding lab are complete.",
    "Move to the terminal below and deploy."
  ]);
}

function handleTerminalInteract(levelIndex) {
  const current = getCurrentLevelIndex();
  const level = LEVELS[levelIndex];
  const levelState = state.levelStates[levelIndex];

  if (levelIndex > current) {
    openMessage("Gate Terminal", [
      "Access denied.",
      `You must complete ${LEVELS[current].title} first for this terminal.`
    ]);
    return;
  }

  if (levelState.terminalActivated) {
    openMessage("Gate Terminal", [
      `${level.title} deployment already completed.`
    ]);
    return;
  }

  if (!levelState.quizPassed) {
    openMessage("Gate Terminal", [
      "This terminal is waiting for patch prerequisites.",
      "Complete mentor quiz steps first."
    ]);
    return;
  }

  if (!levelState.codingPassed) {
    openCodeLab(levelIndex);
    return;
  }

  levelState.terminalActivated = true;
  state.xp += 120;
  level.conceptUnlocks.forEach(unlockConcept);
  pushLog(`${level.title}: terminal activated and gate opened.`);
  updateHud();

  if (levelIndex === LEVELS.length - 1) {
    openMessage("Kernel Control", [
      "All level terminals are online.",
      "Move to the far-right sector and synchronize with Kernel Core."
    ]);
    return;
  }

  openMessage("Gate Terminal", [
    `${level.title} deployment complete.`,
    `Gate ${levelIndex + 1} opened. Proceed to the next mentor region.`
  ]);
}

function handleCoreInteract() {
  if (!isNearFinalCore()) {
    return false;
  }

  if (!allLevelsCompleted()) {
    openMessage("Kernel Core", [
      "Synchronization blocked.",
      "Final access requires all level terminals to be active."
    ]);
    return true;
  }

  if (!state.finalSync) {
    state.finalSync = true;
    state.xp += 220;
    pushLog("Final Core: ring-0 synchronization completed.");
    updateHud();
    openMessage("Kernel Core", [
      "Synchronization successful.",
      "You completed boot, scheduler, memory, syscall, driver, and concurrency layers.",
      "Kernel Academy graduation rank unlocked."
    ]);
    return true;
  }

  openMessage("Kernel Core", [
    "System stable. All stage checkpoints are recorded."
  ]);
  return true;
}

function handleInteract() {
  if (state.panicActive || state.codeLab.active || state.instructionsOpen) {
    return;
  }

  if (state.dialogue.active) {
    if (state.dialogue.mode === "message") {
      advanceDialogue();
    }
    return;
  }

  if (handleCoreInteract()) {
    return;
  }

  const mentor = getNearbyMentor();
  if (mentor) {
    handleMentorInteract(mentor.levelIndex);
    return;
  }

  const terminal = getNearbyTerminal();
  if (terminal) {
    handleTerminalInteract(terminal.levelIndex);
  }
}

function isGateTile(tile) {
  return tile >= "1" && tile <= "5";
}

function isGateOpen(tile) {
  if (!isGateTile(tile)) return true;
  const requiredLevel = Number(tile) - 1;
  return state.levelStates[requiredLevel]?.terminalActivated ?? false;
}

function isBlockingTile(x, y) {
  if (x < 0 || y < 0 || x >= MAP_W || y >= MAP_H) {
    return true;
  }

  const tile = world[y][x];
  if (tile === "#") {
    return true;
  }

  if (isGateTile(tile) && !isGateOpen(tile)) {
    return true;
  }

  for (const level of LEVELS) {
    if (level.mentor.x === x && level.mentor.y === y) {
      return true;
    }
    if (level.terminal.x === x && level.terminal.y === y) {
      return true;
    }
  }

  if (finalCore.x === x && finalCore.y === y) {
    return true;
  }

  return false;
}

function directionFromInput() {
  if (state.pressed.size === 0) {
    return null;
  }

  if (state.pressed.has(state.lastDir)) {
    return state.lastDir;
  }

  const order = ["up", "down", "left", "right"];
  for (const dir of order) {
    if (state.pressed.has(dir)) {
      return dir;
    }
  }

  return null;
}

function startMove(direction) {
  const d = DIRECTIONS[direction];
  if (!d || state.player.moving) {
    return;
  }

  const nextX = state.player.x + d.dx;
  const nextY = state.player.y + d.dy;

  if (isBlockingTile(nextX, nextY)) {
    return;
  }

  state.player.dir = direction;
  state.player.moving = true;
  state.player.moveProgress = 0;
  state.player.startX = state.player.x;
  state.player.startY = state.player.y;
  state.player.targetX = nextX;
  state.player.targetY = nextY;
}

function updatePlayer(dt) {
  if (state.panicActive || state.codeLab.active || state.instructionsOpen || state.dialogue.active) {
    state.pressed.clear();
    return;
  }

  if (state.player.moving) {
    state.player.moveProgress += dt / MOVE_DURATION;
    const t = Math.min(1, state.player.moveProgress);

    const startX = state.player.startX * TILE + TILE / 2;
    const startY = state.player.startY * TILE + TILE / 2;
    const targetX = state.player.targetX * TILE + TILE / 2;
    const targetY = state.player.targetY * TILE + TILE / 2;

    state.player.renderX = lerp(startX, targetX, t);
    state.player.renderY = lerp(startY, targetY, t);

    if (state.player.moveProgress >= 1) {
      state.player.x = state.player.targetX;
      state.player.y = state.player.targetY;
      state.player.renderX = targetX;
      state.player.renderY = targetY;
      state.player.moving = false;
    }
    return;
  }

  const dir = directionFromInput();
  if (dir) {
    startMove(dir);
  }
}

function getCamera() {
  const worldW = MAP_W * TILE;
  const worldH = MAP_H * TILE;
  const halfW = canvas.width / 2;
  const halfH = canvas.height / 2;

  const x = clamp(state.player.renderX - halfW, 0, Math.max(0, worldW - canvas.width));
  const y = clamp(state.player.renderY - halfH, 0, Math.max(0, worldH - canvas.height));

  return { x, y };
}

function drawWorld(camera) {
  const startX = Math.max(0, Math.floor(camera.x / TILE) - 1);
  const startY = Math.max(0, Math.floor(camera.y / TILE) - 1);
  const endX = Math.min(MAP_W - 1, Math.ceil((camera.x + canvas.width) / TILE) + 1);
  const endY = Math.min(MAP_H - 1, Math.ceil((camera.y + canvas.height) / TILE) + 1);

  for (let y = startY; y <= endY; y += 1) {
    for (let x = startX; x <= endX; x += 1) {
      const tile = world[y][x];
      const sx = x * TILE - camera.x;
      const sy = y * TILE - camera.y;
      drawTile(tile, sx, sy);
    }
  }
}

function drawTile(tile, sx, sy) {
  if (tile === "#") {
    ctx.fillStyle = "#1a2437";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.fillStyle = "rgba(118, 170, 230, 0.22)";
    ctx.fillRect(sx + 2, sy + 2, TILE - 4, 5);
    ctx.fillStyle = "rgba(205, 233, 255, 0.06)";
    ctx.fillRect(sx + 6, sy + 12, TILE - 12, TILE - 18);
    return;
  }

  if (isGateTile(tile)) {
    const open = isGateOpen(tile);
    ctx.fillStyle = open ? "#2aa98d" : "#a33847";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.fillStyle = "rgba(8, 14, 24, 0.4)";
    ctx.fillRect(sx + 4, sy + 4, TILE - 8, TILE - 8);
    ctx.fillStyle = open ? "#cbfff2" : "#ffd1d9";
    ctx.font = '13px "Azeret Mono", sans-serif';
    ctx.fillText(tile, sx + TILE / 2 - 4, sy + TILE / 2 + 5);
    return;
  }

  if (tile === ",") {
    ctx.fillStyle = "#1f3b34";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.fillStyle = "rgba(169, 251, 210, 0.13)";
    ctx.fillRect(sx + 6, sy + 7, TILE - 12, 3);
    ctx.fillRect(sx + 10, sy + 20, TILE - 16, 3);
    return;
  }

  if (tile === ":") {
    ctx.fillStyle = "#203650";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.fillStyle = "rgba(168, 212, 255, 0.12)";
    ctx.fillRect(sx + 6, sy + 6, 4, TILE - 12);
    ctx.fillRect(sx + 16, sy + 6, 4, TILE - 12);
    ctx.fillRect(sx + 26, sy + 6, 4, TILE - 12);
    return;
  }

  if (tile === "~") {
    ctx.fillStyle = "#193954";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.strokeStyle = "rgba(132, 220, 255, 0.24)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(sx + 6, sy + 14 + Math.sin((sx + sy) * 0.02) * 2);
    ctx.lineTo(sx + TILE - 6, sy + 14 - Math.sin((sx + sy) * 0.02) * 2);
    ctx.moveTo(sx + 6, sy + 24 + Math.sin((sx + sy) * 0.015) * 2);
    ctx.lineTo(sx + TILE - 6, sy + 24 - Math.sin((sx + sy) * 0.015) * 2);
    ctx.stroke();
    return;
  }

  if (tile === ";") {
    ctx.fillStyle = "#39412b";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.fillStyle = "rgba(255, 238, 173, 0.14)";
    ctx.fillRect(sx + 5, sy + 5, TILE - 10, TILE - 10);
    ctx.fillStyle = "rgba(30, 35, 24, 0.2)";
    ctx.fillRect(sx + 12, sy + 12, TILE - 24, TILE - 24);
    return;
  }

  if (tile === "^") {
    ctx.fillStyle = "#472f22";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.fillStyle = "rgba(255, 174, 132, 0.2)";
    ctx.fillRect(sx + 8, sy + 8, TILE - 16, 5);
    ctx.fillRect(sx + 10, sy + 20, TILE - 20, 5);
    return;
  }

  if (tile === "*") {
    ctx.fillStyle = "#152634";
    ctx.fillRect(sx, sy, TILE, TILE);
    ctx.fillStyle = "rgba(140, 255, 231, 0.17)";
    ctx.beginPath();
    ctx.arc(sx + TILE / 2, sy + TILE / 2, 8, 0, Math.PI * 2);
    ctx.fill();
    return;
  }

  ctx.fillStyle = "#20334b";
  ctx.fillRect(sx, sy, TILE, TILE);
}

function drawMentors(camera) {
  const current = getCurrentLevelIndex();

  LEVELS.forEach((level, idx) => {
    const cx = level.mentor.x * TILE + TILE / 2 - camera.x;
    const cy = level.mentor.y * TILE + TILE / 2 - camera.y;

    ctx.fillStyle = level.mentorColor;
    ctx.beginPath();
    ctx.arc(cx, cy - 2, 12, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = "rgba(5, 12, 20, 0.72)";
    ctx.lineWidth = 2;
    ctx.stroke();

    if (idx === current && !state.levelStates[idx].terminalActivated) {
      const pulse = Math.sin(state.time * 4 + idx) * 2;
      ctx.fillStyle = "#fff2bd";
      ctx.beginPath();
      ctx.arc(cx, cy - 19 + pulse, 4, 0, Math.PI * 2);
      ctx.fill();
    }
  });
}

function drawTerminals(camera) {
  LEVELS.forEach((level, idx) => {
    const cx = level.terminal.x * TILE + TILE / 2 - camera.x;
    const cy = level.terminal.y * TILE + TILE / 2 - camera.y;
    const stage = state.levelStates[idx];

    ctx.fillStyle = stage.terminalActivated ? "#3fd7b5" : "#3f5f8a";
    ctx.fillRect(cx - 12, cy - 12, 24, 24);

    if (stage.codingPassed) {
      ctx.fillStyle = "#ffd166";
    } else if (stage.quizPassed) {
      ctx.fillStyle = "#7ad1ff";
    } else {
      ctx.fillStyle = "#9cb9dc";
    }
    ctx.fillRect(cx - 6, cy - 6, 12, 12);

    if (stage.quizPassed && !stage.codingPassed && !stage.terminalActivated) {
      const pulse = 0.45 + Math.sin(state.time * 5 + idx) * 0.2;
      ctx.strokeStyle = `rgba(122, 209, 255, ${pulse})`;
      ctx.lineWidth = 2;
      ctx.strokeRect(cx - 15, cy - 15, 30, 30);
    }

    if (stage.codingPassed && !stage.terminalActivated) {
      const pulse = 0.45 + Math.sin(state.time * 5 + idx) * 0.2;
      ctx.strokeStyle = `rgba(255, 209, 102, ${pulse})`;
      ctx.lineWidth = 2;
      ctx.strokeRect(cx - 15, cy - 15, 30, 30);
    }
  });
}

function drawFinalCore(camera) {
  const cx = finalCore.x * TILE + TILE / 2 - camera.x;
  const cy = finalCore.y * TILE + TILE / 2 - camera.y;
  const pulse = 0.65 + Math.sin(state.time * 3.6) * 0.2;

  ctx.fillStyle = state.finalSync ? "rgba(80, 227, 194, 0.95)" : `rgba(255, 209, 102, ${pulse})`;
  ctx.beginPath();
  ctx.arc(cx, cy, 11, 0, Math.PI * 2);
  ctx.fill();

  ctx.strokeStyle = state.finalSync ? "#d2fff2" : "#ffd166";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(cx, cy, 18 + Math.sin(state.time * 2.7) * 1.7, 0, Math.PI * 2);
  ctx.stroke();
}

function drawPlayer(camera) {
  const x = state.player.renderX - camera.x;
  const y = state.player.renderY - camera.y;
  const moving = state.player.moving || state.pressed.size > 0;
  const bob = moving ? Math.sin(state.time * 17) * 1.4 : Math.sin(state.time * 3.4) * 0.4;
  const flipX = state.player.dir === "left" ? -1 : 1;
  const waddle = moving ? Math.sin(state.time * 14) * 0.12 : 0;
  const px = x;
  const py = y + bob;

  ctx.save();
  ctx.translate(px, py);
  ctx.scale(flipX, 1);
  ctx.rotate(waddle);

  ctx.fillStyle = "rgba(8, 14, 24, 0.32)";
  ctx.beginPath();
  ctx.ellipse(0, 16, 10, 4, 0, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#e8960c";
  ctx.beginPath();
  ctx.ellipse(-4, 14, 4.5, 2.2, -0.2, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.ellipse(4, 14, 4.5, 2.2, 0.2, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#1a1a2e";
  ctx.beginPath();
  ctx.ellipse(0, 2, 11, 14, 0, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#1a1a2e";
  ctx.beginPath();
  ctx.moveTo(-12, -2);
  ctx.quadraticCurveTo(-17, 4, -13, 10);
  ctx.lineTo(-9, 6);
  ctx.quadraticCurveTo(-11, 2, -9, -2);
  ctx.closePath();
  ctx.fill();
  ctx.beginPath();
  ctx.moveTo(12, -2);
  ctx.quadraticCurveTo(17, 4, 13, 10);
  ctx.lineTo(9, 6);
  ctx.quadraticCurveTo(11, 2, 9, -2);
  ctx.closePath();
  ctx.fill();

  ctx.fillStyle = "#f0f0f0";
  ctx.beginPath();
  ctx.ellipse(0, 5, 7.5, 10, 0, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#f0f0f0";
  ctx.beginPath();
  ctx.ellipse(-4.5, -8.5, 4.5, 4, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.ellipse(4.5, -8.5, 4.5, 4, 0, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#101020";
  ctx.beginPath();
  ctx.arc(-4.5, -8.5, 2.2, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.arc(4.5, -8.5, 2.2, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#ffffff";
  ctx.beginPath();
  ctx.arc(-3.8, -9.2, 0.8, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.arc(5.2, -9.2, 0.8, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#e8960c";
  ctx.beginPath();
  ctx.moveTo(-4, -5);
  ctx.lineTo(0, -3);
  ctx.lineTo(4, -5);
  ctx.lineTo(0, -1.5);
  ctx.closePath();
  ctx.fill();

  ctx.restore();

  if (moving) {
    const pulse = 0.22 + Math.abs(Math.sin(state.time * 10)) * 0.18;
    ctx.strokeStyle = `rgba(102, 225, 196, ${pulse})`;
    ctx.lineWidth = 1.3;
    ctx.beginPath();
    ctx.arc(px, py, 18, 0, Math.PI * 2);
    ctx.stroke();
  }
}

function drawHintBanner() {
  let text = "Explore the maze with WASD or Arrow Keys. Press I for instructions.";
  const mentor = getNearbyMentor();
  const terminal = getNearbyTerminal();

  if (state.instructionsOpen) {
    text = "Instructions open: press I or Esc to close this window";
  } else if (state.codeLab.active) {
    text = "Coding Lab open: Ctrl+Enter to run tests, Esc to close";
  } else if (state.dialogue.active && state.dialogue.mode === "quiz") {
    text = "Answer with 1 / 2 / 3 or click options";
  } else if (state.dialogue.active) {
    text = "Press Space or E to continue dialogue";
  } else if (isNearFinalCore()) {
    text = "Press E to interact with Kernel Core";
  } else if (mentor) {
    text = `Press E to talk to ${mentor.level.mentorName}`;
  } else if (terminal) {
    const stage = state.levelStates[terminal.levelIndex];
    if (!stage.quizPassed) {
      text = `Press E to check ${terminal.level.title} terminal prerequisites`;
    } else if (!stage.codingPassed) {
      text = `Press E to start ${terminal.level.title} coding lab`;
    } else if (!stage.terminalActivated) {
      text = `Press E to deploy ${terminal.level.title}`;
    } else {
      text = `${terminal.level.title} deployment complete`;
    }
  }

  ctx.fillStyle = "rgba(7, 16, 28, 0.82)";
  ctx.fillRect(15, canvas.height - 48, canvas.width - 30, 33);
  ctx.strokeStyle = "rgba(122, 182, 244, 0.5)";
  ctx.strokeRect(15, canvas.height - 48, canvas.width - 30, 33);

  ctx.fillStyle = "#e7f4ff";
  ctx.font = '15px "Azeret Mono", sans-serif';
  ctx.fillText(text, 28, canvas.height - 27);
}

function render() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const camera = getCamera();
  drawWorld(camera);
  drawTerminals(camera);
  drawMentors(camera);
  drawFinalCore(camera);
  drawPlayer(camera);
  drawHintBanner();
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function update(dt) {
  state.time += dt;
  updatePlayer(dt);
}

function onKeyDown(event) {
  if (state.panicActive) {
    if (event.key === "Enter" || event.key === "Escape" || event.key === " ") {
      event.preventDefault();
      retryFromPanic();
    }
    return;
  }

  if ((event.key === "i" || event.key === "I") && !state.codeLab.active) {
    event.preventDefault();
    toggleInstructions();
    return;
  }

  if (state.instructionsOpen) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeInstructions();
      return;
    }

    const direction = KEY_TO_DIR[event.key];
    if (direction || event.key === " " || event.key === "e" || event.key === "E") {
      event.preventDefault();
    }
    return;
  }

  if (state.codeLab.active) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeCodeLab();
      return;
    }

    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      runCodeLabTests();
    }
    return;
  }

  const direction = KEY_TO_DIR[event.key];
  if (direction) {
    event.preventDefault();
    state.pressed.add(direction);
    state.lastDir = direction;
    return;
  }

  if (event.key === "e" || event.key === "E") {
    event.preventDefault();
    handleInteract();
    return;
  }

  if (event.key === " ") {
    event.preventDefault();
    if (state.dialogue.active && state.dialogue.mode === "message") {
      advanceDialogue();
    }
    return;
  }

  if (event.key === "1" || event.key === "2" || event.key === "3") {
    answerQuiz(Number(event.key));
  }
}

function onKeyUp(event) {
  if (state.codeLab.active || state.instructionsOpen) {
    return;
  }

  const direction = KEY_TO_DIR[event.key];
  if (direction) {
    state.pressed.delete(direction);
  }
}

function bindTouchControls() {
  const dirButtons = document.querySelectorAll("[data-touch-dir]");

  dirButtons.forEach((button) => {
    const dir = button.getAttribute("data-touch-dir");
    if (!dir) return;

    const press = (event) => {
      event.preventDefault();
      state.pressed.add(dir);
      state.lastDir = dir;
    };

    const release = (event) => {
      event.preventDefault();
      state.pressed.delete(dir);
    };

    button.addEventListener("pointerdown", press);
    button.addEventListener("pointerup", release);
    button.addEventListener("pointerleave", release);
    button.addEventListener("pointercancel", release);
  });

  document
    .querySelector('[data-touch-action="interact"]')
    ?.addEventListener("click", handleInteract);

  document
    .querySelector('[data-touch-action="advance"]')
    ?.addEventListener("click", () => {
      if (state.dialogue.active && state.dialogue.mode === "message") {
        advanceDialogue();
      }
    });
}

function bindCodeLab() {
  runCodeBtnEl.addEventListener("click", runCodeLabTests);
  closeCodeBtnEl.addEventListener("click", closeCodeLab);
  codeInputEl.addEventListener("input", () => {
    if (!state.codeLab.active) {
      return;
    }
    const idx = state.codeLab.levelIndex;
    if (idx >= 0) {
      state.codeDrafts[idx] = codeInputEl.value;
    }
  });
}

function bindInstructions() {
  openInstructionsBtnEl?.addEventListener("click", () => openInstructions(false));
  closeInstructionsBtnEl?.addEventListener("click", () => closeInstructions());
  closeInstructionsFooterBtnEl?.addEventListener("click", () => closeInstructions());
  instructionBackdropEl?.addEventListener("click", () => closeInstructions());
}

function gameLoop(timestamp) {
  if (!gameLoop.lastTime) {
    gameLoop.lastTime = timestamp;
  }

  const dt = Math.min((timestamp - gameLoop.lastTime) / 1000, 0.05);
  gameLoop.lastTime = timestamp;

  update(dt);
  render();
  requestAnimationFrame(gameLoop);
}

window.addEventListener("keydown", onKeyDown);
window.addEventListener("keyup", onKeyUp);

bindTouchControls();
bindCodeLab();
bindInstructions();
panicRetryBtnEl?.addEventListener("click", retryFromPanic);
renderConcepts();
renderLogs();
updateHud();
setAmbientDialogue();
requestAnimationFrame(gameLoop);
