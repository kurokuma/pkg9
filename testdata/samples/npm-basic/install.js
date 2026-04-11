const token = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
console.log(Buffer.from(token, "base64").toString("utf8"));
