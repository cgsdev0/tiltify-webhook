import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import "dotenv/config";

const app = express();

app.use(
  bodyParser.json({
    limit: "50mb",
  }),
);

app.use(bodyParser.urlencoded({ extended: false }));

const hmacMiddleware = (req: any, res: any, next: any) => {
  const headers = req.headers;
  const timestamp = req.headers["X-tiltify-timestamp"] || "";
  const body = req.bodyText;
  console.log(req);
  const payload = `${timestamp}.${body}`;
  const digest = crypto
    .createHmac("sha256", process.env.SIGNING_ID!)
    .update(payload)
    .digest("base64");
  if (
    !headers["x-tiltify-signature"] ||
    digest !== headers["x-tiltify-signature"]
  ) {
    res.status(401).send({ message: "Could not verify the of the request." });
    return;
  }
  next();
};

app.get("/webhook", hmacMiddleware, (req, res) => {
  console.log(req.body);
  res.send("ok");
});

app.listen(9417, () => {
  console.log(process.env.CLIENT_ID);
  console.log("The application is listening on port 9417!");
});
