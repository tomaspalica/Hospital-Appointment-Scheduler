const express = require("express");
const jwt = require("jsonwebtoken");
const sign = require("./helpers/jwtHelpers");
const { auth } = require("./middlewares/jwt");
require("dotenv").config();

const app = express();
const port = 3000;
const payload = { id: 20, username: "tomek" };

console.log();
app.post("/user/generateToken", (req, res) => {
  console.log(res);
  let data = {
    time: Date(),
    userIde: 12,
  };
  const token = sign.sign(payload, process.env.JWT_SECRET, { exp: "5m" });
  console.log(token);
  // return res.status(200).header('x-auth-token', token).send(200)
  res.send(token);
});
app.get("/user/verification", auth, (req, res) => {
  res.send("hello world");
});
app.get("/", (req, res) => {
  res.send("hellow world");
});
app.listen(port, () => {
  console.log("example app listening to port on 3000");
});
