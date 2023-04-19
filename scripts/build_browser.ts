import { bundle } from "https://deno.land/x/emit@0.19.0/mod.ts";

const result = await bundle("./src/strimertul.ts", {
  type: "module",
});

await Deno.writeTextFile("./dist/strimertul.js", result.code);
