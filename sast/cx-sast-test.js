// cx-sast-test.js
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// SQL Injection
app.get("/user", (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  res.send(query);
});

// Command Injection
app.post("/ping", (req, res) => {
  const host = req.body.host;
  exec("ping -c 1 " + host, (error, stdout) => {
    res.send(stdout);
  });
});

// Hardcoded Password / Secret
const dbPassword = "Admin123456!";
const apiKey = "12345-SECRET-API-KEY";

// Weak Hash
app.post("/hash", (req, res) => {
  const password = req.body.password;
  const hash = crypto.createHash("md5").update(password).digest("hex");
  res.send(hash);
});

app.listen(3000);
