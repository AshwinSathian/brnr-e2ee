// Stryker ignorer: error message text is diagnostic, not part of the contract (the code is, SPEC §16).
// Ignores only message arguments: fail(code, message), new E2eeError(code, message), key32(value, name),
// bad(message), invalid(message) and new Error/TypeError/RangeError(message). Every other string,
// including labels, is still mutated.
import { declareValuePlugin, PluginKind } from "@stryker-mutator/api/plugin";

const isMessageArg = (path) => {
  const p = path.parentPath;
  if (!p || !(p.isCallExpression() || p.isNewExpression())) return false;
  const callee = p.node.callee;
  const name =
    callee.type === "Identifier"
      ? callee.name
      : callee.type === "MemberExpression" &&
          callee.property.type === "Identifier"
        ? `.${callee.property.name}`
        : undefined;
  const i = p.node.arguments.indexOf(path.node);
  // (code, message) helpers, and key32(value, fieldName) whose name only feeds a message.
  // zod's schema.refine(check, message): the message is diagnostic too.
  if ([".refine", "fail", "E2eeError", "key32"].includes(name)) return i === 1;
  // (message) helpers: state.ts bad(), deviceList.ts invalid(), and the built-in error classes.
  if (["bad", "invalid", "Error", "TypeError", "RangeError"].includes(name))
    return i === 0;
  return false;
};

export const strykerPlugins = [
  declareValuePlugin(PluginKind.Ignore, "error-messages", {
    shouldIgnore(path) {
      if (
        (path.isStringLiteral() || path.isTemplateLiteral()) &&
        isMessageArg(path)
      )
        return "Error message text is diagnostic; codes are the contract (SPEC §16).";
      return undefined;
    },
  }),
];
