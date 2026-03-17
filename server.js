const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");
const app = express();

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

  if (!user) {
    return res.status(401).send("Login fehlgeschlagen");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).send("Login fehlgeschlagen");
  }

  req.session.user = { username: user.username, role: user.role };
  res.send("Login erfolgreich");
});

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
