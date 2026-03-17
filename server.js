const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");
const app = express();
const failedAttempts = {};
const LOCK_THRESHOLD = 5;

app.use(express.json());
app.use(
  session({
    secret: "bbzw",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    },
  })
);

// Benutzer aus der JSON-Datei laden
const users = JSON.parse(fs.readFileSync("users.json"));

// Route: Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
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
  req.session.user = { username: user.username, role: user.role };
  res.send("Login erfolgreich");
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

app.get("/profile", (req, res) => {
  const sessionUser = req.session.user;

  if (!sessionUser) {
    return res.status(401).send("Nicht angemeldet");
  }

  res.json(sessionUser);
});

app.post("/logout", (req, res) => {
  if (!req.session.user) {
    return res.status(401).send("Nicht angemeldet");
  }

  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).send("Logout fehlgeschlagen");
    }

    res.clearCookie("connect.sid");
    res.send("Logout erfolgreich");
  });
});

app.listen(3000, () => {
  console.log("Server läuft auf Port 3000");
});
