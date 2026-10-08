import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["node_modules/**", ".git/**", "contracts/**", "circuits/**", "artifacts/**", "*.mjs", "scripts/**"],
  },
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts", "test/**/*.ts"],
    languageOptions: {
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
    },
  },
);
