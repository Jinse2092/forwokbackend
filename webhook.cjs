const http = require("http");
const { exec } = require("child_process");

http.createServer((req, res) => {
  if (req.method === "POST") {
    exec("sh /home/ec2-user/forwokbackend/deploy.sh", (err, stdout, stderr) => {
      if (err) {
        console.error(err);
        return res.end("Deploy failed");
      }
      console.log(stdout);
      res.end("Deploy success");
    });
  } else {
    res.end("OK");
  }
}).listen(9000, () => console.log("Webhook listening on 9000"));
