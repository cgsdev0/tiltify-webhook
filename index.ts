import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import "dotenv/config";
import { exec } from "child_process";

const app = express();

const threshold = process.argv[2] || 1;

app.use(
  bodyParser.json({
    limit: "50mb",
  }),
);

app.use(bodyParser.urlencoded({ extended: false }));

const hmacMiddleware = (req: any, res: any, next: any) => {
  const headers = req.headers;
  const timestamp = req.headers["x-tiltify-timestamp"] || "";
  const body = req.bodyText;
  const payload = `${timestamp}.${body}`;
  console.log(payload);
  const digest = crypto
    .createHmac("sha256", process.env.SIGNING_ID!)
    .update(payload)
    .digest("base64");
  if (
    !headers["x-tiltify-signature"] ||
    digest !== headers["x-tiltify-signature"]
  ) {
    console.log("BAD SIG");
    res.status(401).send({ message: "Could not verify the of the request." });
    return;
  }
  next();
};

console.log(process.argv);
app.post("/webhook", hmacMiddleware, (req, res) => {
  console.log(req.body);
  if (
    req.body?.data?.completed_at &&
    (req.body?.data?.amount?.value || 0.0) > threshold
  ) {
    console.log(req.body);
    setTimeout(() => {
      let yourscript = exec("bash randomfunc", (error, stdout, stderr) => {
        console.log(stdout);
        console.log(stderr);
        if (error !== null) {
          console.log(`exec error: ${error}`);
        }
      });
    }, 3000);
  }
  res.send("ok");
});

app.listen(9417, () => {
  console.log(process.env.CLIENT_ID);
  console.log("The application is listening on port 9417!");
});
