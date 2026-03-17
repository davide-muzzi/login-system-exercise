const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const failedAttempts = {};
const LOCK_THRESHOLD = 5;

app.use(express.json());

// Benutzer aus der JSON-Datei laden
const users = JSON.parse(fs.readFileSync("users.json"));

app.post("/register", async (req, res) => {
  const { username, password, role = "student" } = req.body || {};

  if (!username || !password) {
    return res.status(400).send("Username und Passwort erforderlich");
  }

  if (users.find(u => u.username === username)) {
    return res.status(409).send("Username bereits vergeben");
  }

  if (!isPasswordValid(password)) {
    return res.status(400).send("Passwort erfüllt Richtlinien nicht");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword, role });
  res.status(201).send("User erfolgreich registriert");
});

// Route: Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);
  const attemptInfo = failedAttempts[username];

  if (attemptInfo?.locked) {
    return res.status(403).send("Account gesperrt");
  }

  if (!user) {
    registerFailedAttempt(username);
    return res.status(401).send("Login fehlgeschlagen");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    registerFailedAttempt(username);
    if (failedAttempts[username]?.locked) {
      return res.status(403).send("Account gesperrt");
    }
    return res.status(401).send("Login fehlgeschlagen");
  }

  clearFailedAttempts(username);
  const token = jwt.sign({ username: user.username, role: user.role }, "bbzw", {
    expiresIn: "5m",
  });

  res.json({ token });
});

app.post("/api", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send("Token fehlt");
  }

  const token = authHeader.substring(7);

  try {
    const payload = jwt.verify(token, "bbzw");
    res.json({ message: `Hallo ${payload.username}!`, role: payload.role });
  } catch (err) {
    res.status(401).send("Token ungültig");
  }
});

function registerFailedAttempt(username) {
  const key = username || "_unknown";
  const entry = failedAttempts[key] || { count: 0, locked: false };
  entry.count += 1;
  if (entry.count > LOCK_THRESHOLD) {
    entry.locked = true;
  }
  failedAttempts[key] = entry;
}

function clearFailedAttempts(username) {
  if (username && failedAttempts[username]) {
    delete failedAttempts[username];
  }
}

function isPasswordValid(password) {
  return (
    typeof password === "string" &&
    password.length >= 10 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[*+%&?\$]/.test(password)
  );
}

app.listen(3000, () => {
  console.log("Server läuft auf Port 3000");
});
