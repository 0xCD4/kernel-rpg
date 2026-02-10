import globals from "globals";

const browserGlobals = {
  ...globals.browser
};

const nodeGlobals = {
  ...globals.node
};

export default [
  {
    ignores: ["node_modules/**", "src-tauri/target/**"]
  },
  {
    files: ["game.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: browserGlobals
    },
    rules: {
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }]
    }
  },
  {
    files: ["scripts/**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: nodeGlobals
    },
    rules: {
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }]
    }
  }
];
