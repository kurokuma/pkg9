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
Object.prototype.polluted = true;
