// Lets Node 24 run the TypeScript sources directly: a relative "./x.js" import resolves to "./x.ts".
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, next) {
    try {
      return next(specifier, context);
    } catch (err) {
      if (specifier.startsWith(".") && specifier.endsWith(".js"))
        return next(specifier.slice(0, -3) + ".ts", context);
      throw err;
    }
  },
});
