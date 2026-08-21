import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

// FE-1A source-rule enforcement (FRONTEND-SECURITY-CONTRACT.md §4, §7, §9 and
// the FE-1A directive §6). Layered with the generated-bundle scan
// (scripts/check-dist.mjs) and the strict runtime CSP proof in FE-1B.
export default tseslint.config(
  {
    // Generated and emitted paths are not authored source. types.gen.ts is
    // machine-written (drift-gated against the OpenAPI document); lint
    // exceptions are isolated here and only here.
    ignores: ["dist/**", "node_modules/**", "tools/**", "src/api/types.gen.ts"],
  },
  eslint.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // -- typed-boundary discipline --------------------------------------
      "@typescript-eslint/no-explicit-any": "error",
      // -- dynamic code execution ----------------------------------------
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      // -- banned browser primitives -------------------------------------
      "no-restricted-globals": [
        "error",
        {
          name: "confirm",
          message:
            "Native dialogs are banned (contract §8.D5). Use the design-system ConfirmationDialog (FE-2).",
        },
        {
          name: "prompt",
          message: "Native dialogs are banned (contract §8.D5).",
        },
        {
          name: "alert",
          message: "Native dialogs are banned (contract §8.D5).",
        },
        {
          name: "localStorage",
          message:
            "Persistent browser storage is banned except the approved theme key via the sanctioned module (contract §9.B1; module lands in FE-2).",
        },
        {
          name: "sessionStorage",
          message: "sessionStorage is banned (contract §9.B1).",
        },
      ],
      "no-restricted-properties": [
        "error",
        {
          object: "window",
          property: "confirm",
          message: "Native dialogs are banned (contract §8.D5).",
        },
        {
          object: "window",
          property: "prompt",
          message: "Native dialogs are banned (contract §8.D5).",
        },
        {
          object: "window",
          property: "alert",
          message: "Native dialogs are banned (contract §8.D5).",
        },
        {
          object: "window",
          property: "localStorage",
          message:
            "Persistent storage banned except the approved theme module (contract §9.B1).",
        },
        {
          object: "window",
          property: "sessionStorage",
          message: "sessionStorage is banned (contract §9.B1).",
        },
        {
          object: "document",
          property: "cookie",
          message:
            "JS never touches cookies — the session cookie is HttpOnly and server-owned (contract §1.S1).",
        },
      ],
      // -- inline-style mutation ban (contract §4) + innerHTML ban --------
      "no-restricted-syntax": [
        "error",
        {
          selector: 'JSXAttribute[name.name="style"]',
          message:
            "Inline React style={} is banned (contract §4.Y1). Use classes / data-* attributes with predeclared CSS.",
        },
        {
          selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]',
          message:
            "dangerouslySetInnerHTML is banned with an empty exception list (contract §9.B5).",
        },
        {
          selector: 'MemberExpression[property.name="style"]',
          message:
            "element.style mutation is banned (contract §4.Y1). Toggle classes or data-* attributes instead.",
        },
        {
          selector:
            'CallExpression[callee.property.name="setAttribute"][arguments.0.value="style"]',
          message: 'setAttribute("style", …) is banned (contract §4.Y1).',
        },
        {
          selector: 'CallExpression[callee.property.name="insertRule"]',
          message: "Runtime stylesheet injection is banned (contract §4.Y1).",
        },
        {
          selector: 'NewExpression[callee.name="CSSStyleSheet"]',
          message:
            "Constructed stylesheets are runtime style injection — banned (contract §4.Y1).",
        },
        {
          selector:
            'CallExpression[callee.property.name="createElement"][arguments.0.value="style"]',
          message:
            "Creating <style> elements at runtime is banned (contract §4.Y1).",
        },
        {
          selector:
            'TSAsExpression:not(:has(> TSTypeReference > Identifier[name="const"]))',
          message:
            "`as SomeType` is banned in authored source (contract §7.T1): untrusted data crosses the boundary through decoders, not assertions. (`as const` is permitted.)",
        },
        {
          selector: "TSTypeAssertion",
          message: "Angle-bracket type assertions are banned (contract §7.T1).",
        },
      ],
    },
  },
  {
    // Plain-JS config and gate scripts are linted without type information
    // (they are outside the TS project); every ban above still applies.
    files: ["**/*.js", "**/*.mjs"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      ...tseslint.configs.disableTypeChecked.languageOptions,
      globals: {
        URL: "readonly",
        console: "readonly",
        process: "readonly",
      },
    },
  },
);
