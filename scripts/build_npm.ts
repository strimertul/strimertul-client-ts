import { build } from "https://deno.land/x/dnt@0.34.0/mod.ts";

await build({
  entryPoints: ["./index.ts"],
  outDir: "./npm",
  shims: {},
  esModule: true,
  compilerOptions: {
    lib: ["es2017", "dom"],
  },
  mappings: {
    "https://deno.land/x/kilovolt@v8.0.0/mod.ts": {
      name: "@strimertul/kilovolt-client",
      version: "^8.0.0",
    },
  },
  package: {
    name: "@strimertul/strimertul-client",
    version: Deno.args[0],
    description: "Client for interacting with strimertül",
    keywords: [],
    author: "Ash Keel",
    license: "ISC",
    repository: {
      type: "git",
      url: "git+https://github.com/strimertul/strimertul-client-ts.git",
    },
    bugs: {
      url: "https://github.com/strimertul/strimertul-client-ts/issues",
    },
    homepage: "https://github.com/strimertul/strimertul-client-ts#readme",
  },
});

// post build steps
Deno.copyFileSync("LICENSE", "npm/LICENSE");
Deno.copyFileSync("README.md", "npm/README.md");
