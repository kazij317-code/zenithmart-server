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

// ---------------- PRODUCTS ROUTES ----------------

// GET all products with filtering, search, sort, and pagination
app.get("/api/products", async (req: any, res: any) => {
  try {
    const { search, category, minPrice, maxPrice, sortBy, page = 1, limit = 12 } = req.query;
    const query: any = {};

    if (search) {
      query.$or = [
        { title: { $regex: String(search), $options: "i" } },
        { shortDescription: { $regex: String(search), $options: "i" } },
        { fullDescription: { $regex: String(search), $options: "i" } }
      ];
    }

    if (category) {
      query.category = String(category);
    }

    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = Number(minPrice);
      if (maxPrice) query.price.$lte = Number(maxPrice);
    }

    let sort: any = {};
    if (sortBy === "price_asc") sort.price = 1;
    else if (sortBy === "price_desc") sort.price = -1;
    else if (sortBy === "rating") sort.rating = -1;

    const skipIndex = (Number(page) - 1) * Number(limit);

    const total = await productsCollection.countDocuments(query);
    const data = await productsCollection
      .find(query)
      .sort(sort)
      .skip(skipIndex)
      .limit(Number(limit))
      .toArray();

    res.json({
      success: true,
      products: data,
      pagination: {
        total,
        page: Number(page),
        limit: Number(limit),
        totalPages: Math.ceil(total / Number(limit))
      }
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET Single Product details
app.get("/api/products/:id", async (req: any, res: any) => {
  try {
    const { id } = req.params;
    let query;
    if (ObjectId.isValid(id)) {
      query = { _id: new ObjectId(id) };
    } else {
      query = { id: id };
    }
    const product = await productsCollection.findOne(query);
    if (!product) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }
    res.json({ success: true, product });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`ZenithMart Server is running on port ${PORT}`);
});
