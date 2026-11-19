import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import { jwtVerify, createRemoteJWKSet } from 'jose';


const app = express();

const port = process.env.PORT || 5001;

//middleware
app.use(express.json());
app.use(cors());

const client = new MongoClient(process.env.MONGODB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}




const connectedClient = await connectToMongoDB();
const database = connectedClient.db("wedplan");
const users = database.collection("users");
const services = database.collection("services");
const bookings = database.collection("bookings");


//jwt middleware
const CLIENT_URL = process.env.CLIENT_URL;

const JWKS = createRemoteJWKSet(
  new URL('/api/auth/jwks', CLIENT_URL)
);

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).send({
        message: 'Unauthorized access',
      });
    }

    const token = authHeader.split(' ')[1];

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: CLIENT_URL,
      audience: CLIENT_URL,
    });

    if (!payload.sub) {
      return res.status(401).send({
        message: 'Invalid token',
      });
    }

    // Find the authenticated user in MongoDB

    if (!ObjectId.isValid(payload.sub)) {
      return res.status(401).send({
        message: "Invalid user ID",
      });
    }
    const user = await users.findOne({
      _id: new ObjectId(payload.sub),
    });

    if (!user) {
      return res.status(401).send({
        message: 'User not found',
      });
    }

    if (user.isBlocked) {
      return res.status(403).send({
        message: 'Your account has been blocked',
      });
    }

    req.user = user;

    next();

  } catch (error) {
    console.error('Authentication error:', error.message);

    return res.status(401).send({
      message: 'Invalid or expired token',
    });
  }
};


const verifyVendor = async (req, res, next) => {
  if (req.user.role !== "VENDOR") {
    res.status(403).send({
      message: "Forbidden: Vendor access only",
    });
    return;
  }
  next();
}



//vendor overview
app.get('/vendor/dashboard-stats', verifyToken, async (req, res) => {
  try {
    // Only vendors can access this endpoint
    if (req.user.role !== "VENDOR") {
      return res.status(403).send({
        message: "Forbidden: Vendor access only",
      });
    }

    const vendorId = req.user._id;

    // Count all services belonging to this vendor
    const totalServices = await services.countDocuments({
      vendorId: vendorId.toString(),
    });

    // Count approved and active services
    const activeServices = await services.countDocuments({
      vendorId: vendorId.toString(),
      status: "approved",
    });

    // Count pending booking requests
    const pendingRequests = await bookings.countDocuments({
      vendorId: vendorId.toString(),
      status: "Pending",
    });

    // Count accepted bookings
    const acceptedBookings = await bookings.countDocuments({
      vendorId: vendorId.toString(),
      status: "Accepted",
    });

    res.send({
      totalServices,
      activeServices,
      pendingRequests,
      acceptedBookings,
      subscriptionPlan: req.user.subscriptionPlan || "FREE",
    });

  } catch (error) {
    console.error("Dashboard stats error:", error);

    res.status(500).send({
      message: "Failed to load dashboard statistics",
    });
  }
});


//service related apis

app.post("/services", verifyToken, verifyVendor, async (req, res) => {
  try {
    // 1. Check vendor role
    //verifyVendor

    // 2. Get form data
    const {
      serviceName,
      category,
      description,
      price,
      location,
      images,
    } = req.body;

    // 3. Validate required text fields
    if (
      typeof serviceName !== "string" ||
      !serviceName.trim() ||
      typeof category !== "string" ||
      !category.trim() ||
      typeof description !== "string" ||
      !description.trim() ||
      typeof location !== "string" ||
      !location.trim()
    ) {
      return res.status(400).send({
        message: "All fields are required",
      });
    }

    // 4. Validate category
    const allowedCategories = [
      "Photography",
      "Catering",
      "Decoration",
      "Venue",
      "Makeup",
      "Other",
    ];

    if (!allowedCategories.includes(category)) {
      return res.status(400).send({
        message: "Invalid service category",
      });
    }

    // 5. Validate price
    const servicePrice = Number(price);

    if (
      price === undefined ||
      price === null ||
      price === "" ||
      !Number.isFinite(servicePrice) ||
      servicePrice <= 0
    ) {
      return res.status(400).send({
        message: "Price must be a valid positive number",
      });
    }

    // 6. Validate image URL
    if (
      !Array.isArray(images) ||
      images.length !== 1 ||
      typeof images[0] !== "string"
    ) {
      return res.status(400).send({
        message: "Please provide one service image",
      });
    }

    let imageUrl;

    try {
      imageUrl = new URL(images[0]);

      if (imageUrl.protocol !== "https:") {
        throw new Error("Invalid image URL");
      }
    } catch {
      return res.status(400).send({
        message: "Please provide a valid HTTPS image URL",
      });
    }

    // 7. Prepare service document
    const serviceData = {
      vendorId: req.user._id.toString(),
      serviceName: serviceName.trim(),
      category,
      description: description.trim(),
      price: servicePrice,
      location: location.trim(),
      images: [imageUrl.href],
      status: "pending",
      createdAt: new Date(),
    };

    // 8. Save to MongoDB
    const result = await services.insertOne(serviceData);

    res.status(201).send({
      message: "Service submitted successfully. Waiting for admin approval.",
      insertedId: result.insertedId,
    });

  } catch (error) {
    console.error("Add service error:", error);

    res.status(500).send({
      message: "Failed to add service",
    });
  }
});



app.get('/protected', verifyToken, (req, res) => {
  res.send({
    message: 'Authentication successful!',
    user: {
      id: req.user.id,
      name: req.user.name,
      role: req.user.role,
    },
  });
});






app.get('/', (req, res) => {
  res.send('Wedding is loadingggg!')
})

app.listen(port, () => {
  console.log(`Wedding is loading at ${port}`)
})


export default app;