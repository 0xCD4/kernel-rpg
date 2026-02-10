const TILE = {
  FLOOR: 0,
  WALL: 1,
  MENTOR: 2,
  DIAG: 3,
  PATCH: 4,
  CONCEPT: 5,
  GATE: 6,
  EXIT: 7,
  BONUS: 8,
};

const CHAR_TO_TILE = {
  '#': TILE.WALL,
  '.': TILE.FLOOR,
  M: TILE.MENTOR,
  D: TILE.DIAG,
  P: TILE.PATCH,
  K: TILE.CONCEPT,
  G: TILE.GATE,
  E: TILE.EXIT,
  B: TILE.BONUS,
};

const LEVELS = [
  /* ===============================================
     LEVEL 1: Boot Pipeline Recovery
     =============================================== */
  {
    id: 1,
    title: 'L1 Boot Pipeline Recovery',
    incident: 'Server does not start the init process after reboot.',
    trace: '[ 0.078445 ] Kernel panic: No working init found',
    mentorText:
      'Hey operator! Your first task is a classic scenario. ' +
      'The server got rebooted but the init process cannot start. ' +
      'Trust me, you don\'t want to deal with this in production. I once got called at 3 AM for this exact thing... ' +
      'Anyway, first find the root cause in the diagnosis terminal, then fix the boot argument in the patch terminal. ' +
      'Good luck out there!',
    lesson: [
      'Boot order: UEFI, bootloader, kernel, initramfs, /sbin/init',
      'A bad cmdline can completely break the init process.',
      'First diagnose, then patch. This is critical for incident response.',
    ],
    diagnosis: {
      title: 'Diagnosis: init failure source',
      question: 'What is the first parameter to check when you see "No working init found"?',
      code: 'cat /proc/cmdline\nls /sbin/init\ndmesg | tail -n 40',
      answers: ['kernel cmdline', 'cmdline', 'boot parameter', '/proc/cmdline', 'cmdline parameter'],
      hint: 'If /proc/cmdline content is corrupted, the init path could be wrong.',
      xp: 80,
    },
    patch: {
      title: 'Patch: register init process',
      question: 'Complete the function call that starts the kernel init process.',
      code: 'static int __init start_kernel(void) {\n    // Start init process as PID 1\n    return ___("/sbin/init", argv, envp);\n}',
      answers: ['kernel_execve', 'call_usermodehelper'],
      hint: 'The exec function that starts a user space program from kernel space.',
      xp: 140,
      attempts: 3,
    },
    concepts: ['initramfs', 'kernel cmdline', 'PID 1 init'],
    maze: [
      '###########################',
      '#M......#........#........#',
      '#.......#........#........#',
      '#..###..#..####..#..###...#',
      '#..#.......#........#.....#',
      '#..#.......#........#.....#',
      '#..####.......####..#..##.#',
      '#..........D..............#',
      '#..........#..............#',
      '#..####....#...####..####.#',
      '#..#.......#.......#......#',
      '#..#..K....#.......#......#',
      '#..#.......#..####.#..###.#',
      '#..####....#..#........P..#',
      '#..........#..#...........#',
      '#..###..####..#..####..##.#',
      '#..........#.....#........#',
      '#..........#.....#..G.....#',
      '#..####....#..####........#',
      '#..............#.......B..#',
      '#..............#......E...#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 2: Scheduler Starvation
     =============================================== */
  {
    id: 2,
    title: 'L2 Scheduler Starvation',
    incident: 'User tasks are starving under the realtime queue.',
    trace: 'sched: RT throttling active, CFS latency spike > 400ms',
    mentorText:
      'Welcome back! This time we have a scheduler problem. ' +
      'CFS (Completely Fair Scheduler) is like the heart of Linux. If it doesn\'t work right, everything slows down. ' +
      'A friend of mine once set the nice value wrong and crashed the database server. When the customer SLA got violated, they called a meeting... ' +
      'Long story short: first understand the vruntime concept, then patch the correct priority. ' +
      'After you solve this scenario, you will have solid knowledge about schedulers.',
    lesson: [
      'CFS runs the task with the lowest vruntime.',
      'Nice value -20 gives the highest priority.',
      'Wrong tuning leads to starvation and SLA violations.',
    ],
    diagnosis: {
      title: 'Diagnosis: starvation clue',
      question: 'What metric does CFS use to pick the next task?',
      code: 'cat /proc/sched_debug\nps -eo pid,ni,comm | head',
      answers: ['vruntime', 'virtual runtime'],
      hint: 'The smallest value on the left side of the red-black tree.',
      xp: 100,
    },
    patch: {
      title: 'Patch: fix scheduler policy',
      question: 'Complete the sched_setscheduler call to prevent CFS starvation.',
      code: 'struct sched_param param = { .sched_priority = 0 };\n___(task, SCHED_OTHER, &param);',
      answers: ['sched_setscheduler'],
      hint: 'The kernel function that changes a task\'s scheduler policy.',
      xp: 170,
      attempts: 3,
    },
    concepts: ['CFS', 'vruntime', 'nice -20'],
    maze: [
      '###########################',
      '#M.........#..............#',
      '#..........#..............#',
      '#..####....#....####......#',
      '#.....#....#....#.........#',
      '#.....#.........#.........#',
      '####..#..####...#...#####.#',
      '#.........#..D..#.........#',
      '#.........#.....#.........#',
      '#..####...#.....####..###.#',
      '#..#......#..........#....#',
      '#..#......#....K.....#....#',
      '#..#...####..........#....#',
      '#..#......#...####...#....#',
      '#.........#...#...........#',
      '#..####...#...#..P........#',
      '#..#..........#...........#',
      '#..#..........#...####....#',
      '#..####..####.#......#....#',
      '#............G#......#....#',
      '#.............#...B..#..E.#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 3: Syscall Safety Breach
     =============================================== */
  {
    id: 3,
    title: 'L3 Syscall Safety Breach',
    incident: 'Custom syscall directly dereferences a user pointer.',
    trace: 'BUG: KASAN out-of-bounds read in sys_custom()',
    mentorText:
      'This level is a bit dangerous, be careful! ' +
      'Someone wrote a custom syscall but directly dereferences the user pointer. ' +
      'This is a classic mistake, but the consequences can be terrible. Trusting user space in kernel mode ' +
      'is like giving your root password to a stranger. ' +
      'Any syscall written without copy_from_user is a security hole. ' +
      'Let\'s go! First diagnose the problem, then fix the code!',
    lesson: [
      'The kernel cannot read user pointers directly.',
      'copy_from_user / copy_to_user is the security boundary.',
      'On copy errors, -EFAULT must be returned.',
    ],
    diagnosis: {
      title: 'Diagnosis: unsafe API',
      question: 'Why is memcpy risky for user pointers in the kernel?',
      code: 'char __user *uptr = arg;\nmemcpy(kbuf, uptr, len);',
      answers: ['user pointer not validated', 'security', 'no validation'],
      hint: 'A user space address can point to kernel memory. No validation is done.',
      xp: 120,
    },
    patch: {
      title: 'Patch: safe copy API',
      question: 'Complete the missing function.',
      code: '___(kbuf, ubuf, len);',
      answers: ['copy_from_user'],
      hint: 'The safe copy function for user to kernel direction.',
      xp: 210,
      attempts: 2,
    },
    concepts: ['copy_from_user', '-EFAULT', 'syscall hardening'],
    maze: [
      '###########################',
      '#M.....#..................#',
      '#......#..................#',
      '#......#...####..####.....#',
      '#..#####...#........#.....#',
      '#..........#........#.....#',
      '#..........#...####.#..##.#',
      '#..####....#.......D#.....#',
      '#..#.......#.........#....#',
      '#..#....####..####...#....#',
      '#..#.......#..#......#....#',
      '#..........#..#..K...#....#',
      '#..####....#..#......#....#',
      '#..........#..####...#....#',
      '#..........#..............#',
      '#..####..###...####.......#',
      '#..#.......#...#..P.......#',
      '#..#.......#...#..........#',
      '#..#.......#...####...###.#',
      '#..........#..........G...#',
      '#..........#......B..#..E.#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 4: Memory Pressure in IRQ
     =============================================== */
  {
    id: 4,
    title: 'L4 Memory Pressure in IRQ',
    incident: 'IRQ context allocation was done with GFP_KERNEL.',
    trace: 'BUG: sleeping function called from invalid context',
    mentorText:
      'This is a great trap! Someone tried to allocate memory with GFP_KERNEL inside an interrupt handler. ' +
      'Sleeping in IRQ context is forbidden because the scheduler cannot step in. ' +
      'Think about it: if the CPU says "let me sleep" while handling an interrupt, ' +
      'the whole system freezes. I experienced this myself. We pushed a bad driver to 200 servers and they all froze... ' +
      'The correct flag is GFP_ATOMIC. It does not sleep and returns immediately. Let\'s fix it!',
    lesson: [
      'You cannot sleep in atomic / IRQ context.',
      'GFP_ATOMIC is safe for this scenario.',
      'Wrong memory flags can cause kernel stalls and panics.',
    ],
    diagnosis: {
      title: 'Diagnosis: context rule',
      question: 'Why can\'t you use GFP_KERNEL inside an IRQ?',
      code: 'irq_handler() {\n    kmalloc(sz, GFP_KERNEL);\n}',
      answers: ['it can sleep', 'cannot sleep', 'may sleep', 'sleep'],
      hint: 'Blocking with the scheduler is not possible in IRQ context.',
      xp: 140,
    },
    patch: {
      title: 'Patch: atomic allocation',
      question: 'What is the correct IRQ-safe allocation flag?',
      code: 'kmalloc(256, ___);',
      answers: ['GFP_ATOMIC'],
      hint: 'IRQ-safe allocation flag that does not sleep.',
      xp: 260,
      attempts: 2,
    },
    concepts: ['GFP_ATOMIC', 'atomic context', 'allocator behavior'],
    maze: [
      '###########################',
      '#M........#...............#',
      '#.........#...............#',
      '#..####...#...####..###...#',
      '#..#..........#...........#',
      '#..#..........#...........#',
      '#..#...####...#..####.....#',
      '#......#..D...#..#........#',
      '#......#......#..#........#',
      '#..#####......#..#..####..#',
      '#.........#...#...........#',
      '#.........#...#...........#',
      '#..####...#...#..####.....#',
      '#..#......#......#..K.....#',
      '#..#......#......#........#',
      '#..#...####...####..####..#',
      '#..........#..........P...#',
      '#..........#..............#',
      '#..####....#....####......#',
      '#..........#........G.....#',
      '#..........#....B....#..E.#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 5: Driver Interrupt Race
     =============================================== */
  {
    id: 5,
    title: 'L5 Driver Interrupt Race',
    incident: 'Network driver ISR writes to shared state without a lock.',
    trace: 'lockdep: possible recursive locking / corrupted state',
    mentorText:
      'Race condition! Every kernel developer\'s nightmare. ' +
      'The network driver\'s ISR (Interrupt Service Routine) writes to shared state without taking a lock. ' +
      'These kinds of bugs are the sneakiest. They can run fine for weeks, then ' +
      'blow up at midnight right when you\'re taking a backup. ' +
      'spin_lock_irqsave is your lifesaver here. A normal spinlock is not enough ' +
      'because you are coming from interrupt context and you must save the flags. ' +
      'Time to become a kernel race hunter!',
    lesson: [
      'Critical sections inside an ISR must be protected with locks.',
      'spin_lock_irqsave reduces race conditions.',
      'Top-half should only do short work. Heavy work goes to a workqueue.',
    ],
    diagnosis: {
      title: 'Diagnosis: race cause',
      question: 'What is the basic approach to fix an ISR race?',
      code: 'handler() {\n  dev->shared++;\n}',
      answers: ['lock the critical section', 'lock', 'spinlock', 'spin_lock', 'mutex'],
      hint: 'First make sure you have mutual exclusion, then tune for performance.',
      xp: 160,
    },
    patch: {
      title: 'Patch: irq-safe lock',
      question: 'Write the missing function name.',
      code: 'unsigned long flags; ___(&dev->lock, flags);',
      answers: ['spin_lock_irqsave'],
      hint: 'It starts with spin_lock and takes a flags parameter.',
      xp: 330,
      attempts: 2,
    },
    concepts: ['spin_lock_irqsave', 'ISR top-half', 'workqueue handoff'],
    maze: [
      '###########################',
      '#M........#...............#',
      '#.........#...............#',
      '#..####...#...####........#',
      '#.....#.......#...........#',
      '#.....#.......#...........#',
      '#..####..####.#..####..##.#',
      '#........#....#........D..#',
      '#........#....#...........#',
      '#..####..#....####..#####.#',
      '#..#.....#...........#....#',
      '#..#..K..#...........#....#',
      '#..#.....#...####....#....#',
      '#..####..#...#.......#....#',
      '#........#...#............#',
      '#..####..#...#...####..##.#',
      '#........#.......#..P.....#',
      '#........#.......#........#',
      '#..####..####....#..####..#',
      '#................#.....G..#',
      '#..........B.....#......E.#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 6: Rootkit Hunt & Integrity
     =============================================== */
  {
    id: 6,
    title: 'L6 Rootkit Hunt & Integrity',
    incident: 'sys_call_table hook and suspicious module behavior detected.',
    trace: 'SECURITY: syscall pointer mismatch (__x64_sys_openat)',
    mentorText:
      'Operator, this is serious. The system might be infected with a rootkit. ' +
      'We detected a hook on sys_call_table. The __x64_sys_openat pointer ' +
      'does not match the original address. Someone is trying to hijack syscalls. ' +
      'Kernel rootkits are very dangerous because they run at Ring-0, ' +
      'the deepest layer of the operating system. ' +
      'This is your mission: verify the anomaly with ftrace and enforce the module signing policy. ' +
      'After you pass these levels, you will count as a real kernel security expert!',
    lesson: [
      'Signed module policy is critical for kernel integrity.',
      'ftrace / bpftrace can be used to observe syscall behavior.',
      'Defense is a cycle: prevention + detection + recovery.',
    ],
    diagnosis: {
      title: 'Diagnosis: first forensic action',
      question: 'What is the first observation tool for syscall anomalies?',
      code: 'trace __x64_sys_openat events',
      answers: ['ftrace', 'bpftrace'],
      hint: 'One of the kernel tracing tools is enough.',
      xp: 200,
    },
    patch: {
      title: 'Patch: verify syscall table integrity',
      question: 'Complete the comparison code that checks the syscall table pointer.',
      code: 'void check_syscall_integrity(void) {\n    void *current_ptr = sys_call_table[__NR_openat];\n    if (current_ptr != original_openat) {\n        ___(\'Syscall table tampered!\\n\');\n    }\n}',
      answers: ['printk', 'pr_err', 'pr_warn', 'pr_alert'],
      hint: 'The basic log function used to print messages in the kernel.',
      xp: 500,
      attempts: 2,
    },
    concepts: ['module signing', 'ftrace', 'incident forensics'],
    maze: [
      '###########################',
      '#M.......#................#',
      '#........#................#',
      '#..####..#....####..###...#',
      '#..#..........#...........#',
      '#..#..........#...........#',
      '#..#...####...#..####.....#',
      '#......#......#......D....#',
      '#......#......#...........#',
      '#..#####......####..####..#',
      '#..........#..............#',
      '#..........#......K.......#',
      '#..####....#..............#',
      '#..#.......#...####..###..#',
      '#..#.......#...#..........#',
      '#..#...........#..P.......#',
      '#..####..####..#..........#',
      '#..........#...####..####.#',
      '#..........#............G.#',
      '#..####....#..............#',
      '#..........#.....B....#.E.#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 7: SLAB Use-After-Free
     =============================================== */
  {
    id: 7,
    title: 'L7 SLAB Use-After-Free',
    incident: 'The same pointer is used again after kfree.',
    trace: 'BUG: KASAN: use-after-free in kmem_cache_alloc+0x42',
    mentorText:
      'Wow, you made it this far, nice work! Now we are moving into advanced kernel bugs. ' +
      'Use-After-Free (UAF) is one of the most classic types of heap exploitation. ' +
      'Someone freed memory with kfree() but forgot to set the pointer to NULL, ' +
      'and then kept writing through the same pointer. ' +
      'UAF in the SLAB allocator is very dangerous because the freed area can be assigned to another object. ' +
      'This can lead to type confusion or even privilege escalation. ' +
      'Kernel exploit researchers report these kinds of bugs as CVEs. Let\'s fix it!',
    lesson: [
      'After kfree(), the pointer must always be set to NULL.',
      'The SLAB/SLUB allocator reuses freed areas.',
      'UAF bugs can lead to privilege escalation.',
    ],
    diagnosis: {
      title: 'Diagnosis: UAF root cause',
      question: 'Why should the pointer be set to NULL after kfree?',
      code: 'kfree(obj);\n// obj still points to the old address!\nobj->data = 0x41414141;',
      answers: ['use after free', 'uaf', 'dangling pointer', 'freed memory access'],
      hint: 'Accessing freed memory causes undefined behavior.',
      xp: 220,
    },
    patch: {
      title: 'Patch: null after free',
      question: 'What should be assigned to the pointer after kfree?',
      code: 'kfree(obj);\nobj = ___;',
      answers: ['NULL', 'null', '0'],
      hint: 'The standard value that marks a pointer as invalid.',
      xp: 380,
      attempts: 2,
    },
    concepts: ['Use-After-Free', 'SLAB allocator', 'dangling pointer'],
    maze: [
      '###########################',
      '#M.......#................#',
      '#........#................#',
      '#..####..#....####........#',
      '#..#..........#...........#',
      '#..#..........#...........#',
      '#..#...####...#...####....#',
      '#......#..D...#...#.......#',
      '#......#......#...#.......#',
      '#..#####......#...#..####.#',
      '#..........#..#...........#',
      '#..........#..#..K........#',
      '#..####....#..#...........#',
      '#..#.......#..####..####..#',
      '#..#.......#..............#',
      '#..#...####....####.......#',
      '#..........#...#..P.......#',
      '#..........#...#..........#',
      '#..####....#...####..###..#',
      '#..........#.........G....#',
      '#..........#.....B....#E..#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 8: eBPF Verifier Bypass
     =============================================== */
  {
    id: 8,
    title: 'L8 eBPF Verifier Bypass',
    incident: 'A malicious eBPF program is trying to bypass the verifier.',
    trace: 'SECURITY: eBPF verifier rejected: invalid mem access',
    mentorText:
      'eBPF! One of the most powerful tools in the modern Linux kernel. ' +
      'Network monitoring, tracing, security policies... It is used everywhere. ' +
      'But with great power comes great responsibility! Since eBPF programs run in the kernel, ' +
      'there is a verifier that checks every program before it is loaded: ' +
      'Are there infinite loops? Invalid memory access? Stack overflow risk? ' +
      'If the verifier is bypassed, an attacker can access kernel memory. ' +
      'This scenario showed up in the real world with cases like CVE-2021-31440. ' +
      'Let\'s learn how the verifier works!',
    lesson: [
      'eBPF programs are checked by the verifier before loading.',
      'The verifier checks for: infinite loops, invalid memory access, stack overflow.',
      'CAP_BPF or CAP_SYS_ADMIN permission is required.',
    ],
    diagnosis: {
      title: 'Diagnosis: eBPF safety',
      question: 'What checks eBPF programs before they are loaded into the kernel?',
      code: 'bpf(BPF_PROG_LOAD, &attr, sizeof(attr));\n// EACCES: program rejected by verifier',
      answers: ['verifier', 'ebpf verifier', 'bpf verifier'],
      hint: 'The most critical component of the eBPF security system. It does static analysis before loading.',
      xp: 250,
    },
    patch: {
      title: 'Patch: eBPF program capability check',
      question: 'Complete the function that checks permissions before loading an eBPF program.',
      code: 'int bpf_prog_load(union bpf_attr *attr) {\n    if (!___(CAP_BPF))\n        return -EPERM;\n    return __bpf_prog_load(attr);\n}',
      answers: ['capable', 'ns_capable'],
      hint: 'The kernel function that checks if a process has a specific capability.',
      xp: 420,
      attempts: 2,
    },
    concepts: ['eBPF verifier', 'CAP_BPF', 'kernel sandboxing'],
    maze: [
      '###########################',
      '#M........#...............#',
      '#.........#...............#',
      '#..####...#...####..###...#',
      '#.....#.......#...........#',
      '#.....#.......#...........#',
      '#..####..####.#..####.....#',
      '#........#....#.......D...#',
      '#........#....#...........#',
      '#..####..#.......####..#..#',
      '#..#.....#...........#....#',
      '#..#..K..#...........#....#',
      '#..#.....#...####....#....#',
      '#..####..#...#......#.....#',
      '#........#...#............#',
      '#..####..#...#...####..#..#',
      '#........#.......#..P.....#',
      '#........#.......#........#',
      '#..####..####....####..#..#',
      '#................#....G...#',
      '#.........B......#.....E..#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 9: DKOM Process Hiding
     =============================================== */
  {
    id: 9,
    title: 'L9 DKOM Process Hiding',
    incident: 'A rootkit is hiding a process from the task_struct list.',
    trace: 'ANOMALY: PID 31337 is active in the scheduler but missing from /proc',
    mentorText:
      'Operator, we have reached a very advanced topic: Direct Kernel Object Manipulation! ' +
      'This is one of the most elegant techniques used by kernel rootkits. ' +
      'The attacker removes a process from the task_struct tasks list (list_del), ' +
      'so tools like ps, top, and /proc cannot see the process, but the CPU is still running it. ' +
      'The interesting part is: because the scheduler has its own separate list, ' +
      'the process keeps running. This is a feature of Linux\'s doubly linked circular list. ' +
      'On the defense side, you compare Volatility or /proc with the scheduler. ' +
      'This knowledge will make you a serious kernel security expert!',
    lesson: [
      'task_struct represents every process in Linux.',
      'A process removed from the tasks list with list_del() becomes invisible.',
      'A mismatch between the scheduler and /proc is a rootkit indicator.',
    ],
    diagnosis: {
      title: 'Diagnosis: hidden process detection',
      question: 'To find a hidden process, which source do you compare with the scheduler?',
      code: '// ps and top don\'t show the process\n// but CPU usage is unexplained\n// cross-reference: scheduler vs ???',
      answers: ['/proc', 'proc', 'procfs', 'proc filesystem'],
      hint: 'The virtual filesystem where the kernel provides process information to user space.',
      xp: 280,
    },
    patch: {
      title: 'Patch: restore process visibility',
      question: 'What kernel function adds the hidden process back to the list?',
      code: '___(task, &init_task.tasks);',
      answers: ['list_add', 'list_add_tail'],
      hint: 'The function that reverses list_del() and adds back to the list.',
      xp: 480,
      attempts: 2,
    },
    concepts: ['DKOM', 'task_struct', 'doubly-linked list'],
    maze: [
      '###########################',
      '#M.......#................#',
      '#........#................#',
      '#..####..#....####..###...#',
      '#..#..........#...........#',
      '#..#..........#...........#',
      '#..#...####...#..####.....#',
      '#......#......#......D....#',
      '#......#......#...........#',
      '#..#####......####..####..#',
      '#..........#..............#',
      '#..........#......K.......#',
      '#..####....#..............#',
      '#..#.......#...####..###..#',
      '#..#.......#...#..........#',
      '#..#...........#..P.......#',
      '#..####..####..#..........#',
      '#..........#...####..####.#',
      '#..........#............G.#',
      '#..####....#..............#',
      '#..........#......B...#.E.#',
      '###########################',
    ],
  },

  /* ===============================================
     LEVEL 10: Container Namespace Escape
     =============================================== */
  {
    id: 10,
    title: 'L10 Container Namespace Escape',
    incident: 'An escape from container to host namespace was detected.',
    trace: 'SECURITY: unshare(CLONE_NEWUSER) from unprivileged context',
    mentorText:
      'Welcome to the final level, operator! This is the hardest one in the whole series. ' +
      'Containers provide isolation using kernel namespaces and cgroups, ' +
      'but this isolation can be broken. ' +
      'PID namespace, network namespace, mount namespace... ' +
      'Each one creates a separate world, but they all share the same kernel. ' +
      'If someone can switch from inside a container to the host namespace, it is game over. ' +
      'Docker breakouts, Kubernetes CVEs... they all revolve around this topic. ' +
      'When you finish these levels, you will have seen the depths of kernel security. ' +
      'Last step, let\'s finish this!',
    lesson: [
      'Linux namespaces: PID, Net, Mnt, UTS, User, IPC, Cgroup.',
      'Container isolation is made of namespace + cgroup + seccomp layers.',
      'A namespace escape puts all container security at risk.',
    ],
    diagnosis: {
      title: 'Diagnosis: isolation layer',
      question: 'Which namespace provides network isolation inside a container?',
      code: 'lsns -t net\nip netns list\nnsenter --target 1 --net',
      answers: ['network namespace', 'net namespace', 'net', 'network'],
      hint: 'The namespace type that isolates network interfaces, IP addresses, and routing tables.',
      xp: 300,
    },
    patch: {
      title: 'Patch: block namespace escape',
      question: 'Complete the seccomp filter code that blocks namespace escape from a container.',
      code: 'struct sock_filter filter[] = {\n    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),\n    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 0, 1),\n    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),\n    BPF_STMT(BPF_RET | BPF_K, ___),\n};',
      answers: ['SECCOMP_RET_ALLOW'],
      hint: 'The seccomp return value that allows unmatched syscalls to run.',
      xp: 600,
      attempts: 2,
    },
    concepts: ['namespaces', 'container escape', 'seccomp-bpf'],
    maze: [
      '###########################',
      '#M........#...............#',
      '#.........#...............#',
      '#..####...#....####.......#',
      '#..#..........#...........#',
      '#..#..........#...........#',
      '#..#...####...#...####....#',
      '#......#..D...#...#.......#',
      '#......#......#...#.......#',
      '#..#####......#...#..###..#',
      '#.........#...#...........#',
      '#.........#...#....K......#',
      '#..####...#...#...........#',
      '#..#......#......####.....#',
      '#..#......#......#........#',
      '#..#...####...####..####..#',
      '#..........#..........P...#',
      '#..........#..............#',
      '#..####....#....####......#',
      '#..........#........G.....#',
      '#..........#....B....#..E.#',
      '###########################',
    ],
  },
];

/* ═══════════════════════════════════════════════
   CTF MODE - "OPERATION RING-ZERO"
   A coordinated kernel attack investigation.
   Each level represents a stage of a real APT attack.
   Based on real CVEs and kernel security incidents.
   Same tiles as training: M D P K G E B
   ═══════════════════════════════════════════════ */

const CTF_LEVELS = [
  /* ===============================================
     CTF 1: Heap Overflow - Initial Access
     Real-world: CVE-2021-22555 (Netfilter)
     Difficulty: 1/5
     =============================================== */
  {
    id: 1,
    title: 'CTF-01: Heap Overflow [CVE-2021-22555]',
    incident: 'Heap buffer overflow in Netfilter setsockopt handler allows arbitrary kernel write.',
    trace: 'BUG: KASAN: slab-out-of-bounds in xt_compat_target_from_user+0x4f/0x350 [nf_tables]',
    flag: 'flag{k3rn3l_h34p_0verfl0w_pwn3d}',
    timeLimit: 180,
    difficulty: 1,
    mentorText:
      'Welcome to Operation Ring-Zero! You are investigating a real kernel attack chain. ' +
      'Stage 1: Initial Access. This is based on CVE-2021-22555, a Netfilter heap overflow. ' +
      'In July 2021, a researcher earned $10,000 from Google\'s kCTF bounty program by exploiting this bug. ' +
      'The vulnerability was in the Netfilter compat setsockopt handler: user-supplied data was copied ' +
      'into a kernel heap buffer with memcpy, without checking the size parameter. This let an unprivileged ' +
      'user overflow the heap buffer and achieve arbitrary code execution in Ring-0. ' +
      'The fix is fundamental: never use memcpy for user pointers. The kernel has copy_from_user ' +
      'which validates the source address and handles page faults safely. ' +
      'Diagnose the root cause, then patch the code to earn your first flag!',
    lesson: [
      'CVE-2021-22555: Netfilter heap overflow, $10,000 kCTF bounty.',
      'memcpy on __user pointers = no bounds check, no access validation.',
      'copy_from_user verifies the pointer and returns -EFAULT on failure.',
      'This bug class still accounts for ~30% of all kernel CVEs.',
    ],
    diagnosis: {
      title: 'CVE Analysis: Heap Overflow Root Cause',
      question: 'Examine the vulnerable Netfilter handler. What critical validation is missing before the memcpy?',
      code: '/* net/netfilter/x_tables.c - VULNERABLE */\nint xt_compat_target_from_user(\n    struct xt_entry_target *t,\n    void __user *src, unsigned int size)\n{\n    char buf[XT_ALIGN(sizeof(*t))];\n    /* BUG: size from user, no bounds check! */\n    memcpy(buf, src, size);\n    return xt_check_target(t, buf, size);\n}',
      answers: ['bounds check', 'size check', 'length check', 'validation', 'input validation', 'size validation', 'length validation', 'buffer size'],
      hint: 'The user controls the "size" parameter but the kernel buffer has a fixed size. What check is needed?',
      xp: 80,
    },
    patch: {
      title: 'Patch: Safe User-to-Kernel Copy [kernel/nf_tables]',
      question: 'Replace the unsafe memcpy with the kernel\'s safe copy function for user-to-kernel transfers.',
      code: '/* net/netfilter/x_tables.c - PATCHED */\nint xt_compat_target_from_user(\n    struct xt_entry_target *t,\n    void __user *src, unsigned int size)\n{\n    char buf[XT_ALIGN(sizeof(*t))];\n    if (size > sizeof(buf))\n        return -EINVAL;\n    if (___(buf, src, size))\n        return -EFAULT;\n    return xt_check_target(t, buf, size);\n}',
      answers: ['copy_from_user'],
      hint: 'The kernel function that safely copies data FROM user space. It validates the source pointer and handles faults.',
      xp: 150,
      attempts: 3,
    },
    concepts: ['copy_from_user', 'heap overflow', 'KASAN', 'CVE-2021-22555'],
    maze: [
      '###########################',
      '#M......#........#........#',
      '#.......#........#........#',
      '#..###..#..####..#..###...#',
      '#..#.......#........#.....#',
      '#..#.......#........#.....#',
      '#..####.......####..#..##.#',
      '#..........D..............#',
      '#..........#..............#',
      '#..####....#...####..####.#',
      '#..#.......#.......#......#',
      '#..#..K....#.......#......#',
      '#..#.......#..####.#..###.#',
      '#..####....#..#........P..#',
      '#..........#..#...........#',
      '#..###..####..#..####..##.#',
      '#..........#.....#........#',
      '#..........#.....#..G.....#',
      '#..####....#..####........#',
      '#..............#.......B..#',
      '#..............#......E...#',
      '###########################',
    ],
  },

  /* ===============================================
     CTF 2: Use-After-Free - Persistence
     Real-world: CVE-2023-0266 (ALSA)
     Difficulty: 2/5
     =============================================== */
  {
    id: 2,
    title: 'CTF-02: Use-After-Free [CVE-2023-0266]',
    incident: 'Use-after-free in ALSA PCM driver allows persistent kernel-level access.',
    trace: 'BUG: KASAN: use-after-free in snd_pcm_hw_params+0xa8/0x4e0 [snd_pcm]',
    flag: 'flag{null_p0inter_k1lls_uaf}',
    timeLimit: 200,
    difficulty: 2,
    mentorText:
      'Stage 2: Persistence. The attacker now uses a Use-After-Free to maintain kernel access. ' +
      'This is based on CVE-2023-0266 in the ALSA sound subsystem, disclosed in January 2023. ' +
      'The bug was actively exploited in the wild as part of a Samsung Android exploit chain. ' +
      'The pattern is classic: a driver frees a struct with kfree_skb() but does not NULL the pointer. ' +
      'Later code dereferences the stale pointer, which now points to recycled SLAB memory. ' +
      'Since the SLUB allocator reuses freed areas for new objects, the attacker can perform ' +
      'a heap spray to control what data occupies that memory -- leading to type confusion ' +
      'and arbitrary code execution. The fix is one of the oldest rules in kernel programming: ' +
      'always NULL your pointers after free. This prevents the stale pointer from being usable.',
    lesson: [
      'CVE-2023-0266: ALSA UAF, exploited in-the-wild on Android.',
      'SLAB/SLUB allocator reuses freed memory for new objects.',
      'Dangling pointer + heap spray = type confusion attack.',
      'Rule: always set pointer = NULL immediately after kfree().',
    ],
    diagnosis: {
      title: 'CVE Analysis: UAF Exploitation Pattern',
      question: 'The driver frees skb->head with kfree_skb, but later code still reads through it. What vulnerability class is this?',
      code: '/* sound/core/pcm_native.c - VULNERABLE */\nstatic void snd_pcm_release_substream(\n    struct snd_pcm_substream *sub)\n{\n    kfree_skb(sub->runtime->dma_buf);\n    /* BUG: pointer not cleared! */\n    /* ... later in another thread ... */\n    memcpy(dest, sub->runtime->dma_buf->data,\n        sub->runtime->frame_bytes);  /* UAF! */\n}',
      answers: ['use after free', 'uaf', 'use-after-free', 'dangling pointer'],
      hint: 'The memory at dma_buf was freed, but the pointer still holds the old address. Accessing freed memory is...',
      xp: 100,
    },
    patch: {
      title: 'Patch: Prevent Dangling Pointer [sound/core/pcm]',
      question: 'After freeing the DMA buffer, what must the pointer be set to in order to prevent reuse?',
      code: '/* sound/core/pcm_native.c - PATCHED */\nstatic void snd_pcm_release_substream(\n    struct snd_pcm_substream *sub)\n{\n    kfree_skb(sub->runtime->dma_buf);\n    sub->runtime->dma_buf = ___;\n    /* Now any later access will trigger\n       a clean NULL-deref instead of UAF */\n}',
      answers: ['NULL', 'null', '0'],
      hint: 'The universal sentinel value that marks a pointer as "no longer valid".',
      xp: 200,
      attempts: 3,
    },
    concepts: ['use-after-free', 'SLAB recycling', 'heap spray', 'CVE-2023-0266'],
    maze: [
      '###########################',
      '#M.........#..............#',
      '#..........#..............#',
      '#..####....#....####......#',
      '#.....#....#....#.........#',
      '#.....#.........#.........#',
      '####..#..####...#...#####.#',
      '#.........#..D..#.........#',
      '#.........#.....#.........#',
      '#..####...#.....####..###.#',
      '#..#......#..........#....#',
      '#..#......#....K.....#....#',
      '#..#...####..........#....#',
      '#..#......#...####...#....#',
      '#.........#...#...........#',
      '#..####...#...#..P........#',
      '#..#..........#...........#',
      '#..#..........#...####....#',
      '#..####..####.#......#....#',
      '#............G#......#....#',
      '#.............#...B..#..E.#',
      '###########################',
    ],
  },

  /* ===============================================
     CTF 3: Race Condition - Lateral Movement
     Real-world: CVE-2016-5195 (Dirty COW)
     Difficulty: 3/5
     =============================================== */
  {
    id: 3,
    title: 'CTF-03: Race Condition [Dirty COW]',
    incident: 'IRQ-level race condition corrupts block device ring buffer data.',
    trace: 'lockdep: possible recursive lock in blk_mq_dispatch_rq+0x2c0 [nvme]\nWARNING: lock held when returning to user space!',
    flag: 'flag{sp1n_l0ck_1rqsav3_r4c3}',
    timeLimit: 240,
    difficulty: 3,
    mentorText:
      'Stage 3: Lateral Movement. The attacker exploits a race condition. ' +
      'This is inspired by the legendary Dirty COW bug (CVE-2016-5195) -- a race condition ' +
      'in the Linux memory subsystem that existed for NINE YEARS before being found in 2016. ' +
      'Two threads racing between a Copy-On-Write fault and madvise(MADV_DONTNEED) could ' +
      'overwrite ANY read-only file on the system, including /etc/passwd. ' +
      'In this challenge, you have a block device driver where the IRQ handler and the ' +
      'process context both touch the same ring buffer. The critical question: ' +
      'why can\'t you use a mutex in interrupt context? Because mutexes can sleep! ' +
      'In IRQ context, calling schedule() would deadlock the entire CPU. ' +
      'You need spin_lock_irqsave -- it disables local IRQs and saves the flags register, ' +
      'so the critical section cannot be interrupted by the same IRQ on the same CPU.',
    lesson: [
      'CVE-2016-5195 (Dirty COW): 9-year-old race, overwrites read-only files.',
      'In IRQ context: no sleeping, no schedule(), no mutex_lock().',
      'spin_lock_irqsave: disables IRQs + saves flags + acquires lock.',
      'spin_unlock_irqrestore: releases lock + restores saved IRQ state.',
    ],
    diagnosis: {
      title: 'CVE Analysis: Why Mutex Fails in IRQ',
      question: 'The block driver IRQ handler uses mutex_lock to protect shared state. Why does this cause a kernel hang?',
      code: '/* drivers/block/nvme-ring.c - VULNERABLE */\nstatic irqreturn_t nvme_irq_handler(\n    int irq, void *data)\n{\n    struct nvme_dev *dev = data;\n    /* BUG: mutex can sleep! */\n    mutex_lock(&dev->ring_lock);\n    dev->ring[dev->head++ % RING_SIZE] = readl(\n        dev->mmio + NVME_CQ_HEAD);\n    mutex_unlock(&dev->ring_lock);\n    return IRQ_HANDLED;\n}',
      answers: ['mutex can sleep', 'sleep', 'cannot sleep in irq', 'sleeping in irq', 'scheduling', 'schedule'],
      hint: 'mutex_lock may internally call schedule(). What is forbidden in interrupt/atomic context?',
      xp: 130,
    },
    patch: {
      title: 'Patch: IRQ-Safe Locking [drivers/block/nvme]',
      question: 'Replace the mutex with the correct IRQ-safe spinlock that saves and restores interrupt flags.',
      code: '/* drivers/block/nvme-ring.c - PATCHED */\nstatic irqreturn_t nvme_irq_handler(\n    int irq, void *data)\n{\n    struct nvme_dev *dev = data;\n    unsigned long flags;\n    ___(&dev->ring_lock, flags);\n    dev->ring[dev->head++ % RING_SIZE] = readl(\n        dev->mmio + NVME_CQ_HEAD);\n    spin_unlock_irqrestore(\n        &dev->ring_lock, flags);\n    return IRQ_HANDLED;\n}',
      answers: ['spin_lock_irqsave'],
      hint: 'The spinlock variant that takes a flags parameter and disables local interrupts.',
      xp: 300,
      attempts: 2,
    },
    concepts: ['spin_lock_irqsave', 'Dirty COW', 'IRQ context', 'race condition'],
    maze: [
      '###########################',
      '#M.....#..................#',
      '#......#..................#',
      '#......#...####..####.....#',
      '#..#####...#........#.....#',
      '#..........#........#.....#',
      '#..........#...####.#..##.#',
      '#..####....#.......D#.....#',
      '#..#.......#.........#....#',
      '#..#....####..####...#....#',
      '#..#.......#..#......#....#',
      '#..........#..#..K...#....#',
      '#..####....#..#......#....#',
      '#..........#..####...#....#',
      '#..........#..............#',
      '#..####..###...####.......#',
      '#..#.......#...#..P.......#',
      '#..#.......#...#..........#',
      '#..#.......#...####...###.#',
      '#..........#..........G...#',
      '#..........#......B..#..E.#',
      '###########################',
    ],
  },

  /* ===============================================
     CTF 4: eBPF Privilege Escalation
     Real-world: CVE-2021-3490
     Difficulty: 4/5
     =============================================== */
  {
    id: 4,
    title: 'CTF-04: eBPF Exploit [CVE-2021-3490]',
    incident: 'eBPF ALU32 bounds tracking bypass leads to kernel memory read/write.',
    trace: 'SECURITY: bpf_prog_load: verifier bypass detected (CVE-2021-3490)\nEACCES: R0 unbounded after ALU32 bitwise op',
    flag: 'flag{ebpf_c4p_bpf_g4tek33per}',
    timeLimit: 270,
    difficulty: 4,
    mentorText:
      'Stage 4: Privilege Escalation. The attacker uses eBPF to gain root. ' +
      'This is based on CVE-2021-3490 -- a critical bug in the eBPF verifier\'s ALU32 bounds tracking. ' +
      'The eBPF verifier is supposed to be the ultimate gatekeeper: it statically analyzes every ' +
      'instruction of a BPF program BEFORE it runs in the kernel. It checks for infinite loops, ' +
      'invalid memory access, and stack overflow. But CVE-2021-3490 found a blind spot: after certain ' +
      'ALU32 bitwise operations (AND, OR, XOR), the verifier lost track of register value bounds. ' +
      'An attacker could craft a BPF program that the verifier THOUGHT was safe, ' +
      'but at runtime could read and write arbitrary kernel memory. ' +
      'Google Project Zero and ZDI rated this critical. Multiple exploit chains were published. ' +
      'The defense in depth fix: ensure only privileged users (with CAP_BPF or CAP_SYS_ADMIN) ' +
      'can load BPF programs at all. This is the capability gate that limits the attack surface.',
    lesson: [
      'CVE-2021-3490: eBPF verifier ALU32 bounds bypass (Critical).',
      'The verifier does static analysis of every BPF instruction pre-load.',
      'CAP_BPF (since Linux 5.8) limits who can load BPF programs.',
      'Defense in depth: capability check + verifier + JIT hardening.',
    ],
    diagnosis: {
      title: 'CVE Analysis: eBPF Verifier Bypass',
      question: 'What kernel component performs static analysis on eBPF programs before allowing them to run?',
      code: '/* kernel/bpf/syscall.c */\nstatic int bpf_prog_load(union bpf_attr *attr)\n{\n    struct bpf_prog *prog;\n    prog = bpf_prog_alloc(bpf_prog_size(\n        attr->insn_cnt), GFP_USER);\n    /* This component checks every insn */\n    err = bpf_check(&prog, attr, uattr);\n    if (err < 0)\n        goto free_prog;  /* REJECTED */\n    /* ... JIT compile and attach ... */\n}',
      answers: ['verifier', 'ebpf verifier', 'bpf verifier', 'bpf_check'],
      hint: 'It runs at load time doing static analysis. The function name bpf_check is a hint.',
      xp: 160,
    },
    patch: {
      title: 'Patch: BPF Capability Gate [kernel/bpf/syscall.c]',
      question: 'Complete the capability check that prevents unprivileged users from loading eBPF programs.',
      code: '/* kernel/bpf/syscall.c - PATCHED */\nstatic int bpf_prog_load(\n    union bpf_attr *attr, bpfptr_t uattr)\n{\n    if (!___(CAP_BPF) &&\n        !capable(CAP_SYS_ADMIN))\n        return -EPERM;\n\n    if (attr->insn_cnt > BPF_MAXINSNS)\n        return -E2BIG;\n\n    return __bpf_prog_load(attr, uattr);\n}',
      answers: ['capable', 'ns_capable'],
      hint: 'The kernel function that checks if the current task has a specific Linux capability (CAP_*).',
      xp: 400,
      attempts: 2,
    },
    concepts: ['eBPF verifier', 'CAP_BPF', 'ALU32 bounds', 'CVE-2021-3490'],
    maze: [
      '###########################',
      '#M........#...............#',
      '#.........#...............#',
      '#..####...#...####..###...#',
      '#..#..........#...........#',
      '#..#..........#...........#',
      '#..#...####...#..####.....#',
      '#......#..D...#..#........#',
      '#......#......#..#........#',
      '#..#####......#..#..####..#',
      '#.........#...#...........#',
      '#.........#...#...........#',
      '#..####...#...#..####.....#',
      '#..#......#......#..K.....#',
      '#..#......#......#........#',
      '#..#...####...####..####..#',
      '#..........#..........P...#',
      '#..........#..............#',
      '#..####....#....####......#',
      '#..........#........G.....#',
      '#..........#....B....#..E.#',
      '###########################',
    ],
  },

  /* ===============================================
     CTF 5: Container Escape via cgroups
     Real-world: CVE-2022-0492
     Difficulty: 5/5
     =============================================== */
  {
    id: 5,
    title: 'CTF-05: Container Escape [CVE-2022-0492]',
    incident: 'Container escape via cgroups release_agent allows host-level code execution.',
    trace: 'SECURITY: cgroup_release_agent write from non-init namespace (CVE-2022-0492)\nALERT: unshare(CLONE_NEWUSER) from container PID 1',
    flag: 'flag{s3ccomp_c0nta1ner_br34k0ut}',
    timeLimit: 300,
    difficulty: 5,
    mentorText:
      'Final stage: Container Escape! The attacker breaks out to the host. ' +
      'This is based on CVE-2022-0492 -- disclosed in February 2022. ' +
      'The bug was elegant: cgroups v1 has a feature called release_agent that executes a binary ' +
      'on the HOST when a cgroup becomes empty. An attacker inside a container could write to ' +
      'the release_agent file and trigger code execution as root on the host system. ' +
      'Docker, Kubernetes, LXC -- over 75% of cloud containers were vulnerable. ' +
      'The first step of most container escape chains is calling unshare(CLONE_NEWUSER) to create ' +
      'a new user namespace and gain fake root capabilities inside it. ' +
      'Your mission: write a seccomp-BPF filter that blocks the unshare syscall. ' +
      'Seccomp filters run in the kernel and intercept syscalls BEFORE they execute. ' +
      'The BPF filter program loads the syscall number, compares it to __NR_unshare, ' +
      'and returns SECCOMP_RET_KILL to block it. All other syscalls must pass through. ' +
      'Complete the filter. This is what real-world container hardening looks like.',
    lesson: [
      'CVE-2022-0492: cgroups release_agent container escape.',
      'unshare(CLONE_NEWUSER) is the first step in most container escapes.',
      'Seccomp-BPF filters block syscalls at the kernel level.',
      'SECCOMP_RET_KILL blocks, SECCOMP_RET_ALLOW permits syscalls.',
    ],
    diagnosis: {
      title: 'CVE Analysis: Container Escape Entry Point',
      question: 'What syscall does the attacker call to create a new user namespace and gain capabilities inside the container?',
      code: '/* Attacker code inside container: */\n#define _GNU_SOURCE\n#include <sched.h>\n\nint main(void) {\n    /* Step 1: create new user namespace */\n    if (???(CLONE_NEWUSER) == -1)\n        perror("namespace");\n    /* Step 2: now have CAP_SYS_ADMIN in\n       new namespace, mount cgroup,\n       write release_agent, escape! */\n    return exploit_cgroup_release();\n}',
      answers: ['unshare', '__NR_unshare'],
      hint: 'This syscall detaches the calling process from one or more namespaces. Starts with "un"...',
      xp: 200,
    },
    patch: {
      title: 'Patch: Seccomp-BPF Syscall Filter [container hardening]',
      question: 'Complete the seccomp return value that allows all NON-blocked syscalls to execute normally.',
      code: '/* Container seccomp policy - PATCHED */\nstruct sock_filter filter[] = {\n    /* Load syscall number */\n    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,\n        offsetof(struct seccomp_data, nr)),\n    /* Jump if nr == __NR_unshare */\n    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,\n        __NR_unshare, 0, 1),\n    /* Block: kill process on unshare */\n    BPF_STMT(BPF_RET | BPF_K,\n        SECCOMP_RET_KILL),\n    /* Allow: permit all other syscalls */\n    BPF_STMT(BPF_RET | BPF_K, ___),\n};',
      answers: ['SECCOMP_RET_ALLOW'],
      hint: 'The seccomp return action that permits the syscall to proceed. Opposite of SECCOMP_RET_KILL.',
      xp: 500,
      attempts: 2,
    },
    concepts: ['seccomp-bpf', 'container escape', 'CVE-2022-0492', 'CLONE_NEWUSER'],
    maze: [
      '###########################',
      '#M........#...............#',
      '#.........#...............#',
      '#..####...#....####.......#',
      '#..#..........#...........#',
      '#..#..........#...........#',
      '#..#...####...#...####....#',
      '#......#..D...#...#.......#',
      '#......#......#...#.......#',
      '#..#####......#...#..###..#',
      '#.........#...#...........#',
      '#.........#...#....K......#',
      '#..####...#...#...........#',
      '#..#......#......####.....#',
      '#..#......#......#........#',
      '#..#...####...####..####..#',
      '#..........#..........P...#',
      '#..........#..............#',
      '#..####....#....####......#',
      '#..........#........G.....#',
      '#..........#....B....#..E.#',
      '###########################',
    ],
  },
];

function buildLevelMap(level) {
  const points = {};
  const charMap = CHAR_TO_TILE;
  const rows = level.maze.map((row, y) =>
    row.split('').map((char, x) => {
      const tile = charMap[char] ?? TILE.FLOOR;
      if (char === 'M') points.mentor = { x, y };
      if (char === 'D') points.diag = { x, y };
      if (char === 'P') points.patch = { x, y };
      if (char === 'K') points.concept = { x, y };
      if (char === 'G') points.gate = { x, y };
      if (char === 'E') points.exit = { x, y };
      if (char === 'B') points.bonus = { x, y };
      return tile;
    })
  );
  return { map: rows, points };
}
