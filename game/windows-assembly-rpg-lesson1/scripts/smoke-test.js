import fs from "node:fs";
import vm from "node:vm";

const PROJECT_DIR = "/Users/mathematician/Documents/New project/windows-assembly-rpg-lesson1";
const GAME_PATH = `${PROJECT_DIR}/game.js`;
const HTML_PATH = `${PROJECT_DIR}/index.html`;

function makeElement(id = "") {
  return {
    id,
    textContent: "",
    hidden: false,
    innerHTML: "",
    value: "",
    className: "",
    type: "",
    style: {
      setProperty() {}
    },
    children: [],
    addEventListener() {},
    appendChild(child) {
      this.children.push(child);
    },
    getAttribute(attr) {
      return this[attr] ?? null;
    },
    setAttribute(attr, value) {
      this[attr] = value;
    },
    focus() {}
  };
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function buildContext() {
  const ids = [
    "gameCanvas",
    "dialogueName",
    "dialogueText",
    "choices",
    "xp",
    "levelCounter",
    "progressFill",
    "questState",
    "stageName",
    "stageObjective",
    "incidentTitle",
    "incidentSymptom",
    "incidentFix",
    "runbookList",
    "conceptList",
    "missionLog",
    "codeLab",
    "codeLabTitle",
    "codeLabBrief",
    "codeReference",
    "codeInput",
    "codeOutput",
    "runCodeBtn",
    "closeCodeBtn"
  ];

  const elements = new Map();
  ids.forEach((id) => elements.set(id, makeElement(id)));

  const fakeCtx = {
    fillStyle: "",
    strokeStyle: "",
    lineWidth: 1,
    font: "",
    clearRect() {},
    fillRect() {},
    strokeRect() {},
    beginPath() {},
    arc() {},
    fill() {},
    stroke() {},
    moveTo() {},
    lineTo() {},
    quadraticCurveTo() {},
    ellipse() {},
    closePath() {},
    fillText() {}
  };

  const canvas = elements.get("gameCanvas");
  canvas.width = 960;
  canvas.height = 640;
  canvas.getContext = () => fakeCtx;

  const touchButtons = ["up", "left", "down", "right"].map((dir) => {
    const element = makeElement(`touch-${dir}`);
    element["data-touch-dir"] = dir;
    return element;
  });

  const touchInteract = makeElement("touch-interact");
  const touchAdvance = makeElement("touch-advance");

  const context = {
    console,
    Math,
    document: {
      getElementById(id) {
        return elements.get(id) || null;
      },
      createElement(tag) {
        const element = makeElement(`created-${tag}`);
        element.tagName = tag.toUpperCase();
        return element;
      },
      querySelectorAll(selector) {
        return selector === "[data-touch-dir]" ? touchButtons : [];
      },
      querySelector(selector) {
        if (selector === '[data-touch-action="interact"]') {
          return touchInteract;
        }
        if (selector === '[data-touch-action="advance"]') {
          return touchAdvance;
        }
        return null;
      }
    },
    window: {
      addEventListener() {},
      removeEventListener() {}
    },
    requestAnimationFrame() {
      return 1;
    },
    cancelAnimationFrame() {},
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval
  };

  return { context, elements };
}

function verifyDomWiring(html, source) {
  const idMatches = [...source.matchAll(/getElementById\("([^"]+)"\)/g)];
  const ids = idMatches.map((match) => match[1]);
  const missing = ids.filter((id) => !html.includes(`id="${id}"`));
  assert(missing.length === 0, `Missing IDs in index.html: ${missing.join(", ")}`);

  assert(html.includes("Academy Guide"), "Academy Guide section is missing in the UI.");
  assert(html.includes('id="instructionModal"'), "Instruction modal container is missing.");
}

function runProgressionSimulation(context) {
  const progressionScript = `
    const snippets = {
      boot: "function boot_pipeline(state){ state.firmware='uefi'; state.steps.push('bootloader'); state.steps.push('kernel'); state.steps.push('init'); return state.steps.join(' -> '); }",
      sched: "function pick_next_task(rq){ const runnable = rq.filter((task) => task.runnable); runnable.sort((a,b)=>a.vruntime-b.vruntime); return runnable[0] || null; }",
      memory: "function handle_page_fault(vm, addr){ if (!vm.page_table[addr]) { vm.page_table[addr] = vm.alloc_frame(); } vm.stats.minor_faults++; return vm.page_table[addr]; }",
      syscall: "long sys_safe_open(struct ctx *ctx, const char __user *user_ptr) { char *path = copy_from_user(user_ptr); if (!path) { return -EFAULT; } if (path[0] != '/') { return -EINVAL; } return vfs_open(path, ctx->flags); }",
      driver: "irqreturn_t net_irq_handler(int irq, void *dev_id) { struct netdev *dev = dev_id; writel(IRQ_ACK, dev->mmio + IRQ_STATUS); napi_schedule(&dev->napi); return IRQ_HANDLED; }",
      sync: "void update_stats(struct stats *s, int delta) { spin_lock(&s->lock); s->packets += delta; spin_unlock(&s->lock); } int can_mount(struct cred *c) { return capable(CAP_SYS_ADMIN); }"
    };

    for (let i = 0; i < LEVELS.length; i += 1) {
      state.levelStates[i].started = true;
      state.levelStates[i].quizPassed = true;
      const key = LEVELS[i].codeTaskId;
      openCodeLab(i);
      codeInputEl.value = snippets[key];
      runCodeLabTests();
      if (!state.levelStates[i].codingPassed) {
        throw new Error("coding pass failed on level " + i);
      }
      closeCodeLab();
      handleTerminalInteract(i);
      if (!state.levelStates[i].terminalActivated) {
        throw new Error("terminal activation failed on level " + i);
      }
    }

    state.player.x = finalCore.x;
    state.player.y = finalCore.y - 1;
    const handled = handleCoreInteract();
    if (!handled || !state.finalSync) {
      throw new Error("final core sync failed");
    }
  `;

  vm.runInContext(progressionScript, context);
}

function main() {
  const source = fs.readFileSync(GAME_PATH, "utf8");
  const html = fs.readFileSync(HTML_PATH, "utf8");

  verifyDomWiring(html, source);

  const { context } = buildContext();
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "game.js" });

  runProgressionSimulation(context);

  console.log("SMOKE_OK");
}

try {
  main();
} catch (error) {
  console.error("SMOKE_FAIL");
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
}
