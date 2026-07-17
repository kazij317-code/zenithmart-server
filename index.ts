const dns = require("node:dns");
dns.setServers(["1.1.1.1", "1.0.0.1"]);

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

app.use(
  cors({
    credentials: true,
    origin: [clientUrl, "http://localhost:3000", "http://localhost:3001", "http://localhost:3002", "http://127.0.0.1:3000", "http://127.0.0.1:3001", "http://127.0.0.1:3002"],
  }),
);
app.use(express.json());

app.get("/", (req: any, res: any) => {
  res.send("Hello ZenithMart Server!");
});

app.listen(PORT, () => {
  console.log(`ZenithMart Server is running on port ${PORT}`);
});
