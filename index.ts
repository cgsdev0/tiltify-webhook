import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import "dotenv/config";

const app = express();

app.use(
  bodyParser.json({
    limit: "50mb",
    verify(req, res, buffer) {
      if (req.originalUrl.search("webhooks") !== -1) {
        req.textBody = buffer.toString();
      }
    },
  }),
);
app.use(bodyParser.urlencoded({ extended: false }));

const hmacMiddleware = (req, res, next) => {
  const headers = req.headers;
  const body = req.textBody;
  const digest = crypto
    .createHmac("sha256", process.env.SIGNING_ID)
    .update(body)
    .digest("base64");
  if (
    !headers["x-shopify-hmac-sha256"] ||
    digest !== headers["x-shopify-hmac-sha256"]
  ) {
    res.status(401).send({ message: "Could not verify the of the request." });
    return;
  }
  next();
};

app.get("/webhook", (req, res) => {
  res.send("This is a test web page!");
});

app.listen(9417, () => {
  console.log(process.env.CLIENT_ID);
  console.log("The application is listening on port 9417!");
});
