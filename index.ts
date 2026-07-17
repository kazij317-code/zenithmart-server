const dns = require("node:dns");
dns.setServers(["1.1.1.1", "1.0.0.1"]);

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

dotenv.config();

const uri = process.env.MONGO_DB_URI;
const dbName = process.env.AUTH_DB_NAME || "zenithmart";
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

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const db = client.db(dbName);
const productsCollection = db.collection("products");
const userCollection = db.collection("user");
const ordersCollection = db.collection("orders");
const cartCollection = db.collection("cart");
const favoritesCollection = db.collection("favorites");

// Connect to MongoDB
async function connectDB() {
  try {
    await client.connect();
    console.log("Connected to MongoDB successfully!");
  } catch (error) {
    console.error("Failed to connect to MongoDB", error);
  }
}
connectDB();

app.listen(PORT, () => {
  console.log(`ZenithMart Server is running on port ${PORT}`);
});
