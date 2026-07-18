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
const inquiriesCollection = db.collection("inquiries");
const subscribersCollection = db.collection("subscribers");

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
const nodeCrypto = require("node:crypto");
const { SignJWT, jwtVerify, createRemoteJWKSet } = require("jose-cjs");

const JWT_SECRET = new TextEncoder().encode(
  process.env.BETTER_AUTH_SECRET || "default_super_secret_key_zenithmart_123!"
);

const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL || "http://localhost:3000"}/api/auth/jwks`));

function hashPassword(password: string) {
  const salt = nodeCrypto.randomBytes(16).toString("hex");
  const hash = nodeCrypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, storedValue: string) {
  if (!storedValue || !storedValue.includes(":")) return false;
  const [salt, hash] = storedValue.split(":");
  const verifyHash = nodeCrypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
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

// Middleware to verify authorization token
const verifyToken = async (req: any, res: any, next: any) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "Unauthorized: Missing or invalid token" });
    }

    const token = authHeader.split(" ")[1];
    
    let payload;
    try {
      // 1. Try verifying using Better-Auth JWKS (asymmetric)
      const result = await jwtVerify(token, JWKS);
      payload = result.payload;
    } catch (jwksErr: any) {
      try {
        // 2. Fallback to local JWT_SECRET (symmetric HS256)
        const result = await jwtVerify(token, JWT_SECRET);
        payload = result.payload;
      } catch (jwtErr: any) {
        throw jwtErr;
      }
    }
    
    const email = payload.email || payload.user?.email;
    const userId = payload.sub || payload.id || payload.user?.id;

    const query: any = {};
    const orConditions = [];

    if (email) orConditions.push({ email });
    if (userId) {
      orConditions.push({ id: userId });
      if (ObjectId.isValid(userId)) {
        orConditions.push({ _id: new ObjectId(userId) });
      }
    }

    if (orConditions.length === 0) {
      return res.status(401).json({ success: false, error: "Unauthorized: Invalid token payload structure" });
    }

    query.$or = orConditions;
    const user = await userCollection.findOne(query);
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("JWT verify error details:", error);
    return res.status(401).json({ success: false, error: "Unauthorized: Invalid or expired token" });
  }
};

// Middleware to verify admin role
const verifyAdmin = (req: any, res: any, next: any) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ success: false, error: "Forbidden: Admin access required" });
  }
  next();
};

// ---------------- ADMIN ROUTES ----------------

// GET Business Overview Stats
app.get("/api/admin/stats", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const productCount = await productsCollection.countDocuments();
    const userCount = await userCollection.countDocuments();
    
    const orders = await ordersCollection.find({}).toArray();
    const orderCount = orders.length;
    const totalSales = orders.reduce((sum: number, order: any) => sum + (Number(order.totalAmount) || 0), 0);

    // Sales chart: group last 7 days of sales
    const salesChart = [];
    const today = new Date();
    for (let i = 6; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(today.getDate() - i);
      const dateString = date.toLocaleDateString("en-US", { weekday: "short" });
      
      const dayStart = new Date(date);
      dayStart.setHours(0, 0, 0, 0);
      const dayEnd = new Date(date);
      dayEnd.setHours(23, 59, 59, 999);

      const dayOrders = orders.filter((o: any) => {
        const cDate = new Date(o.createdAt);
        return cDate >= dayStart && cDate <= dayEnd;
      });

      const daySales = dayOrders.reduce((sum: number, o: any) => sum + (Number(o.totalAmount) || 0), 0);
      salesChart.push({
        name: dateString,
        Sales: daySales
      });
    }

    res.json({
      success: true,
      stats: {
        productCount,
        userCount,
        orderCount,
        totalSales
      },
      salesChart
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET Fetch all orders (Admin only)
app.get("/api/admin/orders", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const orders = await ordersCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, orders });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PATCH Update order status (Admin only)
app.patch("/api/admin/orders/:id/status", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ success: false, error: "Status is required" });
    }

    let query;
    if (ObjectId.isValid(id)) {
      query = { _id: new ObjectId(id) };
    } else {
      query = { id: id };
    }

    const result = await ordersCollection.updateOne(query, { $set: { status } });
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: "Order not found" });
    }

    res.json({ success: true, message: `Order status updated to ${status}` });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET All Users list
app.get("/api/admin/users", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const users = await userCollection.find({}).toArray();
    const mappedUsers = users.map((u: any) => ({
      id: u._id.toString(),
      name: u.name,
      email: u.email,
      role: u.role || "user",
      isBlocked: !!u.isBlocked
    }));
    res.json({ success: true, users: mappedUsers });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PATCH Toggle Block User
app.patch("/api/admin/users/:id/block", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const { id } = req.params;
    const { isBlocked } = req.body;
    
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: "Invalid user ID" });
    }

    const result = await userCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { isBlocked: !!isBlocked } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.json({ success: true, message: `User ${isBlocked ? "blocked" : "unblocked"} successfully` });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ---------------- PRODUCTS ROUTES ----------------

// POST Create new product
app.post("/api/products", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const { title, shortDescription, fullDescription, price, category, stock, image, specifications } = req.body;
    if (!title || !shortDescription || !fullDescription || price === undefined || !category || stock === undefined || !image) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    const newProduct = {
      title,
      shortDescription,
      fullDescription,
      price: Number(price),
      rating: 5.0,
      category,
      stock: Number(stock),
      image,
      specifications: specifications || {},
      reviews: []
    };

    const result = await productsCollection.insertOne(newProduct);
    res.status(201).json({ success: true, product: { ...newProduct, _id: result.insertedId } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE A product
app.delete("/api/products/:id", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const { id } = req.params;
    let query;
    if (ObjectId.isValid(id)) {
      query = { _id: new ObjectId(id) };
    } else {
      query = { id: id };
    }

    const result = await productsCollection.deleteOne(query);
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }

    res.json({ success: true, message: "Product deleted successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PUT Update product details (Admin only)
app.put("/api/products/:id", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const { id } = req.params;
    const { title, shortDescription, fullDescription, price, category, stock, image, specifications } = req.body;
    
    let query;
    if (ObjectId.isValid(id)) {
      query = { _id: new ObjectId(id) };
    } else {
      query = { id: id };
    }

    const updatedProduct = {
      $set: {
        title,
        shortDescription,
        fullDescription,
        price: Number(price),
        category,
        stock: Number(stock),
        image,
        specifications: specifications || {}
      }
    };

    const result = await productsCollection.updateOne(query, updatedProduct);
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }

    res.json({ success: true, message: "Product updated successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

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

// DELETE Clear entire cart for a user (by email)
app.delete("/api/cart", async (req: any, res: any) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ success: false, error: "Email query parameter is required" });
    }
    await cartCollection.deleteMany({ email });
    res.json({ success: true, message: "Cart cleared successfully" });
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
      query = { $or: [{ _id: new ObjectId(id) }, { productId: id }] };
    } else {
      query = { $or: [{ id: id }, { productId: id }] };
    }
    const result = await cartCollection.deleteMany(query);
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: "Cart item not found" });
    }
    res.json({ success: true, message: "Cart item removed successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ---------------- FAVORITES ROUTES ----------------

// GET Favorites for a user (by email)
app.get("/api/favorites", async (req: any, res: any) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ success: false, error: "Email query parameter is required" });
    }
    const favorites = await favoritesCollection.find({ email }).toArray();
    // Populate product details for each favorite item
    const populatedItems = await Promise.all(
      favorites.map(async (item: any) => {
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
    res.json({ success: true, favorites: populatedItems });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST Toggle Favorite (Add or remove)
app.post("/api/favorites", async (req: any, res: any) => {
  try {
    const { email, productId } = req.body;
    if (!email || !productId) {
      return res.status(400).json({ success: false, error: "Email and productId are required" });
    }
    const existing = await favoritesCollection.findOne({ email, productId });
    if (existing) {
      await favoritesCollection.deleteOne({ _id: existing._id });
      res.json({ success: true, isFavorite: false, message: "Removed from favorites" });
    } else {
      await favoritesCollection.insertOne({
        email,
        productId,
        createdAt: new Date()
      });
      res.json({ success: true, isFavorite: true, message: "Added to favorites" });
    }
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ---------------- ORDERS ROUTES ----------------

// POST Place a new order
app.post("/api/orders", verifyToken, async (req: any, res: any) => {
  try {
    const { items, totalAmount, shippingAddress, paymentMethod } = req.body;
    const email = req.user.email;
    if (!items || !totalAmount) {
      return res.status(400).json({ success: false, error: "Items and totalAmount are required" });
    }

    const newOrder = {
      email,
      items,
      totalAmount: Number(totalAmount),
      shippingAddress,
      paymentMethod,
      status: "Pending",
      createdAt: new Date()
    };

    const result = await ordersCollection.insertOne(newOrder);

    // Clear the cart for the user after placing the order
    await cartCollection.deleteMany({ email });

    res.status(201).json({
      success: true,
      message: "Order placed successfully and cart cleared",
      orderId: result.insertedId
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET Order history for a user
app.get("/api/orders", verifyToken, async (req: any, res: any) => {
  try {
    const email = req.user.email;
    const orders = await ordersCollection.find({ email }).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, orders });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ---------------- INQUIRIES ROUTES ----------------

// POST Create an inquiry (Public)
app.post("/api/inquiries", async (req: any, res: any) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ success: false, error: "Name, email, and message are required" });
    }

    const newInquiry = {
      name,
      email,
      message,
      createdAt: new Date()
    };

    await inquiriesCollection.insertOne(newInquiry);
    res.status(201).json({ success: true, message: "Inquiry submitted successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET Fetch all inquiries (Admin only)
app.get("/api/admin/inquiries", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const inquiries = await inquiriesCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, inquiries });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ---------------- SUBSCRIBERS ROUTES ----------------

// POST Create a newsletter subscription (Public)
app.post("/api/subscribers", async (req: any, res: any) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: "Email is required" });
    }

    const existing = await subscribersCollection.findOne({ email });
    if (existing) {
      return res.json({ success: true, message: "Already subscribed!" });
    }

    const newSubscriber = {
      email,
      status: "Active",
      createdAt: new Date()
    };

    await subscribersCollection.insertOne(newSubscriber);
    res.status(201).json({ success: true, message: "Subscribed successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET Fetch all subscribers (Admin only)
app.get("/api/admin/subscribers", verifyToken, verifyAdmin, async (req: any, res: any) => {
  try {
    const subscribers = await subscribersCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, subscribers });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET AI recommendations based on category
app.get("/api/ai/recommendations", async (req: any, res: any) => {
  try {
    const { category, productId } = req.query;
    if (!category) {
      return res.status(400).json({ success: false, error: "Category query parameter is required" });
    }

    let query: any = { category: String(category) };
    if (productId) {
      if (ObjectId.isValid(productId)) {
        query._id = { $ne: new ObjectId(productId) };
      } else {
        query.id = { $ne: productId };
      }
    }

    const recommendations = await productsCollection.find(query).limit(4).toArray();
    res.json({ success: true, recommendations });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST AI Chatbot endpoint (ZenithBot)
app.post("/api/ai/chat", async (req: any, res: any) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ success: false, error: "Message is required" });
    }

    const lowerMessage = message.toLowerCase();
    let responseText = "";

    // 1. Handle store policy FAQ questions
    if (lowerMessage.includes("shipping") || lowerMessage.includes("delivery") || lowerMessage.includes("track")) {
      responseText = "At ZenithMart, we offer free standard shipping on all orders worldwide! Deliveries typically take between 3-5 business days depending on your location. Once your order ships, we'll send you a confirmation email with tracking details.";
    } else if (lowerMessage.includes("return") || lowerMessage.includes("refund") || lowerMessage.includes("exchange")) {
      responseText = "We want you to love your purchase! That is why we provide a 30-day return policy. You can return any unused item in its original packaging for a full refund or exchange. Contact support@zenithmart.com to start your return.";
    } else if (lowerMessage.includes("support") || lowerMessage.includes("contact") || lowerMessage.includes("help") || lowerMessage.includes("phone")) {
      responseText = "Our dedicated support team is available 24/7. You can reach us via email at support@zenithmart.com or by calling our toll-free line at +1-800-555-0199.";
    } else if (lowerMessage.includes("hello") || lowerMessage.includes("hi") || lowerMessage.includes("hey") || lowerMessage.includes("greetings")) {
      responseText = "Hello there! Welcome to ZenithMart. I am ZenithBot, your virtual assistant. How can I help you with your shopping experience today?";
    } else {
      // 2. Query products collection based on keywords
      const keywords = ["electronics", "laptop", "phone", "bag", "yoga", "clothing", "shoe", "watch", "camera", "perfume", "jacket"];
      let foundKeyword = "";
      for (const keyword of keywords) {
        if (lowerMessage.includes(keyword)) {
          foundKeyword = keyword;
          break;
        }
      }

      if (foundKeyword) {
        // Query products from MongoDB matching the keyword
        const query = {
          $or: [
            { category: { $regex: foundKeyword, $options: "i" } },
            { title: { $regex: foundKeyword, $options: "i" } },
            { shortDescription: { $regex: foundKeyword, $options: "i" } }
          ]
        };
        const products = await productsCollection.find(query).limit(4).toArray();

        if (products.length > 0) {
          responseText = `I found some premium options in ${foundKeyword} for you:\n\n` +
            products.map((p: any, index: number) => `${index + 1}. **${p.title}** - $${p.price} (Rating: ${p.rating}⭐)\n   *${p.shortDescription}*`).join("\n\n") +
            "\n\nFeel free to explore these items or add them to your cart!";
        } else {
          responseText = `We do have some fantastic catalog options, but I couldn't find active listings matching "${foundKeyword}" right now. Try searching for other collections like Electronics or Accessories!`;
        }
      } else {
        // General query search in title/descriptions
        const query = {
          $or: [
            { title: { $regex: message, $options: "i" } },
            { category: { $regex: message, $options: "i" } }
          ]
        };
        const products = await productsCollection.find(query).limit(3).toArray();
        if (products.length > 0) {
          responseText = `Here are some products matching your interest:\n\n` +
            products.map((p: any, index: number) => `${index + 1}. **${p.title}** - $${p.price}\n   *${p.shortDescription}*`).join("\n\n");
        } else {
          responseText = "I'm not sure I fully understand. You can ask me about product recommendations (e.g. 'Show me some cool electronics'), shipping policies, returns, or support contact details!";
        }
      }
    }

    res.json({ success: true, response: responseText });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`ZenithMart Server is running on port ${PORT}`);
});
