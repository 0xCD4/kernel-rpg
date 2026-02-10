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

function buildLevelMap(level) {
  const points = {};
  const rows = level.maze.map((row, y) =>
    row.split('').map((char, x) => {
      const tile = CHAR_TO_TILE[char] ?? TILE.FLOOR;
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
