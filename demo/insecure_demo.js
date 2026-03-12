const crypto = require("crypto");
const fs = require("fs");
const { exec } = require("child_process");

const apiKey = "demo-client-secret-12345";

function loadUser(db, userInput) {
  const query = "SELECT * FROM users WHERE id=" + userInput;
  return db.query(query);
}

function renderProfile(target, userContent) {
  target.innerHTML = userContent;
}

function runTask(userInput) {
  exec("ls " + userInput);
}

function weakDigest(value) {
  return crypto.createHash("sha1").update(value).digest("hex");
}

function downloadAvatar() {
  return fetch("http://api.example.com/users");
}

function readUserFile(req) {
  return fs.readFileSync(req.query.path, "utf8");
}
