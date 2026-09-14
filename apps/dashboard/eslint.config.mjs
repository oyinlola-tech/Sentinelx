import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const config = [
  ...nextVitals,
  ...nextTypescript,
  { ignores: [".next/**", "node_modules/**", "src/lib/api-schema.d.ts", "next-env.d.ts"] },
  {
    rules: {
      "no-console": ["warn", { allow: ["warn", "error"] }],
      "react/jsx-no-target-blank": "error",
    },
  },
];

export default config;
