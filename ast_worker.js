// AST helper powered by Acorn. Reads one JSON object from stdin, writes JSON to stdout.
const acorn = require("acorn");
const fs = require("fs");

function analyze(source) {
  let ast;
  try {
    ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "module", locations: true, allowHashBang: true });
  } catch (e1) {
    try {
      ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "script", locations: true, allowHashBang: true });
    } catch (e2) {
      return { parseError: String(e2.message || e2), findings: [] };
    }
  }
  const findings = [];
  const parents = [];
  function add(id, title, severity, confidence, node, evidence, description, remediation) {
    findings.push({
      id, title, severity, confidence,
      line: node.loc && node.loc.start ? node.loc.start.line : 1,
      column: node.loc && node.loc.start ? node.loc.start.column + 1 : 1,
      evidence: String(evidence || "").slice(0, 220),
      description, remediation
    });
  }
  function isIdentifier(node, name) { return node && node.type === "Identifier" && node.name === name; }
  function memberName(node) {
    if (!node || node.type !== "MemberExpression") return "";
    if (!node.computed && node.property.type === "Identifier") return node.property.name;
    if (node.computed && node.property.type === "Literal") return String(node.property.value);
    return "";
  }
  function shortNode(node) { return source.slice(node.start, Math.min(node.end, node.start + 180)).replace(/\s+/g, " "); }
  function isSource(node) {
    if (!node) return false;
    const s = source.slice(node.start, Math.min(node.end, node.end + 1));
    return /(?:location\.(?:search|hash|href|pathname)|URLSearchParams|document\.URL|document\.referrer|event\.data|localStorage|sessionStorage|\.searchParams)/i.test(s);
  }
  function walk(node, parent, functionStack) {
    if (!node || typeof node.type !== "string") return;
    const nextFunctionStack = /Function(?:Declaration|Expression)$/.test(node.type) || node.type === "ArrowFunctionExpression"
      ? functionStack.concat([node]) : functionStack;
    const p = parent;
    if (node.type === "CallExpression") {
      if (isIdentifier(node.callee, "eval")) {
        add("JSCODE001", "Dynamic code execution via eval", "high", "high", node, shortNode(node),
          "eval executes a string as JavaScript.", "Avoid eval; use structured parsing or explicit function dispatch.");
      }
      if (node.callee.type === "Identifier" && /^(setTimeout|setInterval)$/.test(node.callee.name) &&
          node.arguments[0] && node.arguments[0].type === "Literal" && typeof node.arguments[0].value === "string") {
        add("JSCODE003", "String passed to timer API", "medium", "high", node, shortNode(node),
          "A string timer can evaluate code.", "Pass a function reference instead of a string.");
      }
      if (node.callee.type === "MemberExpression" && memberName(node.callee) === "insertAdjacentHTML") {
        add("JSXSS003", "HTML parsing sink: insertAdjacentHTML", "high", "medium", node, shortNode(node),
          "The method parses its HTML argument.", "Prefer safe DOM APIs or a vetted sanitizer.");
      }
      if (node.callee.type === "MemberExpression" && memberName(node.callee) === "write" &&
          node.callee.object.type === "Identifier" && node.callee.object.name === "document") {
        add("JSXSS004", "Potential document.write sink", "medium", "medium", node, shortNode(node),
          "document.write parses content as HTML.", "Replace with safe DOM APIs.");
      }
      if (node.callee.type === "MemberExpression" && memberName(node.callee) === "postMessage" &&
          node.arguments[1] && node.arguments[1].type === "Literal" && node.arguments[1].value === "*") {
        add("JSMSG001", "postMessage uses wildcard target origin", "medium", "high", node, shortNode(node),
          "Wildcard target origin may disclose messages to an unintended recipient.", "Specify the exact expected origin.");
      }
    }
    if (node.type === "NewExpression" && isIdentifier(node.callee, "Function")) {
      add("JSCODE002", "Dynamic Function constructor", "high", "high", node, shortNode(node),
        "The Function constructor compiles strings as code.", "Avoid constructing executable code from strings.");
    }
    if (node.type === "AssignmentExpression" && node.left.type === "MemberExpression") {
      const prop = memberName(node.left);
      if (prop === "innerHTML" || prop === "outerHTML") {
        const rhs = node.right;
        const tainted = isSource(rhs) || (rhs.type === "Identifier" && /^(input|data|message|param|query|html|content|value)$/i.test(rhs.name));
        add(prop === "innerHTML" ? "JSXSS001" : "JSXSS002",
          "Potential HTML injection sink: " + prop, "high", tainted ? "medium" : "low", node,
          shortNode(node), "Assignment to " + prop + " parses a string as HTML.",
          "Prefer textContent/createElement. If HTML is required, sanitize with a maintained library.");
        if (tainted) add("JSTAINT001", "Potential source-to-HTML-sink data flow", "high", "medium", node,
          shortNode(node), "The assigned expression resembles a user-controlled source or common input variable.",
          "Trace the value back to its origin and verify context-appropriate sanitization before the sink.");
      }
    }
    if (node.type === "CallExpression" && node.callee.type === "Identifier" && node.callee.name === "Math" &&
        node.arguments.length) { /* placeholder; member calls are handled below */ }
    if (node.type === "CallExpression" && node.callee.type === "MemberExpression" &&
        node.callee.object.type === "Identifier" && node.callee.object.name === "Math" &&
        memberName(node.callee) === "random") {
      const nearby = source.slice(Math.max(0, node.start - 120), Math.min(source.length, node.end + 120));
      if (/(token|secret|nonce|session|csrf|key|auth)/i.test(nearby)) {
        add("JSRAND001", "Math.random near security-sensitive identifier", "medium", "low", node, shortNode(node),
          "Math.random is not cryptographically secure.", "Use crypto.getRandomValues or crypto.randomUUID as appropriate.");
      }
    }
    // Generic local taint lead: a risky sink argument contains a common source expression.
    if (node.type === "CallExpression" && node.callee.type === "MemberExpression" &&
        memberName(node.callee) === "insertAdjacentHTML" && node.arguments.length > 1 &&
        isSource(node.arguments[1])) {
      add("JSTAINT001", "Potential URL/message/storage source reaches HTML sink", "high", "medium", node,
        shortNode(node), "A source-like expression is passed directly to an HTML parsing sink.",
        "Validate reachability and sanitization; prefer textContent or safe DOM construction.");
    }
    const keys = Object.keys(node);
    for (const key of keys) {
      if (["start", "end", "loc", "range"].includes(key)) continue;
      const value = node[key];
      if (Array.isArray(value)) value.forEach(child => { if (child && typeof child.type === "string") walk(child, node, nextFunctionStack); });
      else if (value && typeof value.type === "string") walk(value, node, nextFunctionStack);
    }
  }
  walk(ast, null, []);
  return { findings, parseError: null };
}
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try {
    const payload = JSON.parse(input);
    process.stdout.write(JSON.stringify(analyze(payload.source || "")));
  } catch (err) {
    process.stdout.write(JSON.stringify({ parseError: String(err), findings: [] }));
  }
});
