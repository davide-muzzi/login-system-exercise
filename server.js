const express = require("express");
const fs = require("fs");
const app = express();

app.use(express.json());

// Benutzer aus der JSON-Datei laden
const users = JSON.parse(fs.readFileSync("users.json"));

// Route: Login
app.post("/login", (req, res) => {

  const { username, password } = req.body;

  const user = users.find(
    u => u.username === username && u.password === password
  );

  if (user) {
    res.send("Login erfolgreich");
  } else {
    res.status(401).send("Login fehlgeschlagen");
  }

});

app.listen(3000, () => {
  console.log("Server läuft auf Port 3000");
});