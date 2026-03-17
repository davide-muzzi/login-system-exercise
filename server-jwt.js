const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();

app.use(express.json());

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

  const token = jwt.sign(
    { username: user.username, role: user.role },
    "bbzw",
    { expiresIn: "5m" }
  );

  res.json({ token });
});

app.listen(3000, () => {
  console.log("Server läuft auf Port 3000");
});
