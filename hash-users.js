const fs = require("fs/promises");
const bcrypt = require("bcrypt");

async function main() {
  const data = await fs.readFile("users.json", "utf8");
  const users = JSON.parse(data);

  const hashedUsers = await Promise.all(
    users.map(async (user) => ({
      ...user,
      password: await bcrypt.hash(user.password, 10),
    }))
  );

  await fs.writeFile(
    "users.json",
    JSON.stringify(hashedUsers, null, 2),
    "utf8"
  );

  console.log("users.json updated with hashed passwords");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
