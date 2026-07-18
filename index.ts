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

// ---------------- AUTH ROUTES ----------------
const crypto = require("node:crypto");
const { SignJWT, jwtVerify } = require("jose-cjs");

const JWT_SECRET = new TextEncoder().encode(
  process.env.BETTER_AUTH_SECRET || "default_super_secret_key_zenithmart_123!"
);

function hashPassword(password: string) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, storedValue: string) {
  if (!storedValue || !storedValue.includes(":")) return false;
  const [salt, hash] = storedValue.split(":");
  const verifyHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
  return hash === verifyHash;
}

// User Registration
app.post("/api/auth/register", async (req: any, res: any) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: "Name, email, and password are required" });
    }

    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: "User already exists with this email" });
    }

    const hashedPassword = hashPassword(password);
    const newUser = {
      name,
      email,
      password: hashedPassword,
      createdAt: new Date(),
    };

    const result = await userCollection.insertOne(newUser);
    res.status(201).json({ success: true, message: "User registered successfully", userId: result.insertedId });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// User Login
app.post("/api/auth/login", async (req: any, res: any) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Email and password are required" });
    }

    const user = await userCollection.findOne({ email });
    if (!user || !verifyPassword(password, user.password)) {
      return res.status(401).json({ success: false, error: "Invalid email or password" });
    }

    const token = await new SignJWT({ email: user.email, name: user.name, id: user._id.toString() })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("2h")
      .sign(JWT_SECRET);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get User Profile
app.get("/api/auth/profile", async (req: any, res: any) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "Unauthorized: Missing or invalid token" });
    }

    const token = authHeader.split(" ")[1];
    const { payload } = await jwtVerify(token, JWT_SECRET);
    const email = payload.email;

    const user = await userCollection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (error: any) {
    res.status(401).json({ success: false, error: "Unauthorized: Invalid or expired token" });
  }
});

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

// ---------------- CART ROUTES ----------------

// GET Cart items for a user (by email)
app.get("/api/cart", async (req: any, res: any) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ success: false, error: "Email query parameter is required" });
    }
    const cartItems = await cartCollection.find({ email }).toArray();
    // Populate product details for each cart item
    const populatedItems = await Promise.all(
      cartItems.map(async (item: any) => {
        let productQuery;
        if (ObjectId.isValid(item.productId)) {
          productQuery = { _id: new ObjectId(item.productId) };
        } else {
          productQuery = { id: item.productId };
        }
        const product = await productsCollection.findOne(productQuery);
        return { ...item, product };
      })
    );
    res.json({ success: true, cart: populatedItems });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST Add or update item in cart
app.post("/api/cart", async (req: any, res: any) => {
  try {
    const { email, productId, quantity = 1 } = req.body;
    if (!email || !productId) {
      return res.status(400).json({ success: false, error: "Email and productId are required" });
    }
    const existingItem = await cartCollection.findOne({ email, productId });
    if (existingItem) {
      const newQty = Number(existingItem.quantity) + Number(quantity);
      await cartCollection.updateOne({ _id: existingItem._id }, { $set: { quantity: newQty } });
      res.json({ success: true, message: "Cart item quantity updated" });
    } else {
      const result = await cartCollection.insertOne({
        email,
        productId,
        quantity: Number(quantity),
        createdAt: new Date(),
      });
      res.status(201).json({ success: true, message: "Product added to cart", itemId: result.insertedId });
    }
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PUT Update quantity of a cart item
app.put("/api/cart/:id", async (req: any, res: any) => {
  try {
    const { id } = req.params;
    const { quantity } = req.body;
    if (quantity === undefined || quantity === null) {
      return res.status(400).json({ success: false, error: "Quantity is required" });
    }
    let query;
    if (ObjectId.isValid(id)) {
      query = { _id: new ObjectId(id) };
    } else {
      query = { id: id };
    }
    const result = await cartCollection.updateOne(query, { $set: { quantity: Number(quantity) } });
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: "Cart item not found" });
    }
    res.json({ success: true, message: "Cart item updated successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE Remove item from cart
app.delete("/api/cart/:id", async (req: any, res: any) => {
  try {
    const { id } = req.params;
    let query;
    if (ObjectId.isValid(id)) {
      query = { _id: new ObjectId(id) };
    } else {
      query = { id: id };
    }
    const result = await cartCollection.deleteOne(query);
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: "Cart item not found" });
    }
    res.json({ success: true, message: "Cart item removed successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});


app.listen(PORT, () => {
  console.log(`ZenithMart Server is running on port ${PORT}`);
});
