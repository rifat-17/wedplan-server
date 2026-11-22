import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import Stripe from 'stripe';


const app = express();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

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
const transactions = database.collection("transactions");

await transactions.createIndex(
  { stripeSessionId: 1 },
  { unique: true }
);


//jwt middleware
const CLIENT_URL = process.env.CLIENT_URL;

const JWKS = createRemoteJWKSet(
  new URL('/api/auth/jwks', CLIENT_URL)
);

//verifyToken
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

//vendor verify
const verifyVendor = async (req, res, next) => {
  if (req.user.role !== "VENDOR") {
    res.status(403).send({ message: 'Forbidden' });
    return;
  }
  next();
}

//admin verify
const verifyAdmin = async (req, res, next) => {

  console.log("Authenticated user role:", req.user.role);

  if (req.user.role !== "ADMIN") {
    res.status(403).send({ message: 'Forbidden' });
    return;
  }
  next();
}

//verifyCustomer
const verifyCustomer = async (req, res, next) => {
  if (req.user.role !== "CUSTOMER") {
    res.status(403).send({ message: 'Forbidden' });
    return;
  }
  next();
}


//VeriffyPremium
const verifyPremiumPayment = async (sessionId, vendorId) => {
  // Retrieve Checkout Session from Stripe
  const session = await stripe.checkout.sessions.retrieve(sessionId);

  // Verify session ownership and payment details
  if (
    session.metadata?.vendorId !== vendorId ||
    session.metadata?.plan !== "PREMIUM" ||
    session.payment_status !== "paid" ||
    session.status !== "complete" ||
    session.mode !== "payment" ||
    session.amount_total !== 8900 ||
    session.currency !== "usd"
  ) {
    throw new Error("Payment verification failed.");
  }

  // Find the matching transaction
  const transaction = await transactions.findOne({
    stripeSessionId: session.id,
    vendorId,
  });

  if (!transaction) {
    throw new Error("Transaction not found.");
  }

  // Already processed
  if (transaction.status === "paid") {
    return {
      alreadyPaid: true,
    };
  }

  // Only pending transactions can be processed
  if (transaction.status !== "pending") {
    throw new Error("This transaction cannot be processed.");
  }

  // Activate Premium
  await users.updateOne(
    { _id: new ObjectId(vendorId) },
    {
      $set: {
        subscriptionPlan: "PREMIUM",
      },
    }
  );

  // Update transaction
  await transactions.updateOne(
    {
      _id: transaction._id,
      status: "pending",
    },
    {
      $set: {
        status: "paid",
        paidAt: new Date(),
      },
    }
  );

  return {
    alreadyPaid: false,
  };
};


//subscripton of vendor
app.post("/vendor/subscription/checkout", verifyToken, verifyVendor, async (req, res) => {
  try {

    // Check if vendor already has Premium
    if (req.user.subscriptionPlan === "PREMIUM") {
      return res.status(400).send({
        message: "You already have a Premium subscription.",
      });
    }

    // Create Stripe Checkout Session
    const session = await stripe.checkout.sessions.create({
      mode: "payment",

      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: "WedPlan Premium Plan",
              description: "One-time payment for unlimited services and premium features.",
            },
            unit_amount: 8900,
          },
          quantity: 1,
        },
      ],

      success_url: `${process.env.CLIENT_URL}/dashboard/vendor/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/dashboard/vendor/payment-cancel`,

      metadata: {
        vendorId: req.user._id.toString(),
        plan: "PREMIUM",
      },
    });

    res.send({
      url: session.url,
    });
    // Save pending transaction
    await transactions.insertOne({
      vendorId: req.user._id.toString(),
      plan: "PREMIUM",
      amount: session.amount_total,
      currency: session.currency,
      stripeSessionId: session.id,
      stripeSubscriptionId: null,
      status: "pending",
      createdAt: new Date(),
    });

  } catch (error) {
    console.error("Checkout error:", error);
    res.status(500).send({
      message: "Failed to create checkout session",
    });
  }
});


// Verify vendor premium payment
app.post(
  "/vendor/subscription/verify-payment",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { sessionId } = req.body;

      if (!sessionId) {
        return res.status(400).send({
          message: "Checkout session ID is required.",
        });
      }

      const result = await verifyPremiumPayment(
        sessionId,
        req.user._id.toString()
      );

      return res.send({
        success: true,
        message: result.alreadyPaid
          ? "Payment was already verified."
          : "Premium plan activated successfully.",
      });

    } catch (error) {
      console.error("Payment verification error:", error);

      return res.status(400).send({
        message: error.message || "Payment verification failed.",
      });
    }
  }
);


// Recover pending Premium payments
app.post(
  "/vendor/subscription/recover-payment",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const vendorId = req.user._id.toString();

      // Find all pending transactions for this vendor
      const pendingTransactions = await transactions
        .find({
          vendorId,
          plan: "PREMIUM",
          status: "pending",
        })
        .toArray();

      let recoveredCount = 0;

      for (const transaction of pendingTransactions) {
        try {
          await verifyPremiumPayment(
            transaction.stripeSessionId,
            vendorId
          );

          recoveredCount++;
        } catch (error) {
          // This session may still be unpaid or incomplete.
          console.log(
            `Payment not recovered: ${transaction.stripeSessionId}`,
            error.message
          );
        }
      }

      return res.send({
        success: true,
        recoveredCount,
        message:
          recoveredCount > 0
            ? "Your Premium payment has been recovered."
            : "No completed pending payments found.",
      });

    } catch (error) {
      console.error("Payment recovery error:", error);

      return res.status(500).send({
        message: "Failed to recover payments.",
      });
    }
  }
);


//service related apis
// Get all approved and active services
app.get("/services", async (req, res) => {
  try {
    const { search, category, location, sort } = req.query;

    const filter = {
      status: "approved",
      availability: "active",
    };

    // Category filter
    if (category) {
      filter.category = category;
    }

    const sortOption =
      sort === "price_asc"
        ? { price: 1 }
        : sort === "price_desc"
          ? { price: -1 }
          : { createdAt: -1 };

    // Search by service name
    if (search) {
      filter.serviceName = {
        $regex: String(search).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
        $options: "i",
      };
    }

    // Location filter
    if (location) {
      filter.location = {
        $regex: String(location).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
        $options: "i",
      };
    }

    const servicesList = await services
      .find(filter)
      .sort(sortOption)
      .toArray();

    res.send({
      services: servicesList,
      total: servicesList.length,
    });
  } catch (error) {
    console.error("Get public services error:", error);
    res.status(500).send({
      message: "Failed to fetch services",
    });
  }
});


app.get("/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid service ID",
      });
    }

    const service = await services.findOne({
      _id: new ObjectId(id),
      status: "approved",
      availability: "active",
    });

    if (!service) {
      return res.status(404).send({
        message: "Service not found",
      });
    }

    res.send(service);
  } catch (error) {
    console.error("Get service details error:", error);
    res.status(500).send({
      message: "Failed to fetch service details",
    });
  }
});


app.get("/featured-services", async (req, res) => {
  try {
    const featuredServices = await services
      .aggregate([
        {
          $match: {
            status: "approved",
            availability: "active",
          },
        },
        {
          $sort: {
            createdAt: -1,
          },
        },
        {
          $limit: 6,
        },
        {
          $lookup: {
            from: "users",
            let: {
              vendorId: "$vendorId",
            },
            pipeline: [
              {
                $addFields: {
                  userId: {
                    $toString: "$_id",
                  },
                },
              },
              {
                $match: {
                  $expr: {
                    $eq: ["$userId", "$$vendorId"],
                  },
                },
              },
              {
                $project: {
                  name: 1,
                  image: 1,
                  businessName: 1,
                },
              },
            ],
            as: "vendor",
          },
        },
        {
          $unwind: {
            path: "$vendor",
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $project: {
            serviceName: 1,
            category: 1,
            price: 1,
            location: 1,
            images: 1,
            vendor: 1,
          },
        },
      ])
      .toArray();

    res.send({
      services: featuredServices,
    });
  } catch (error) {
    console.error("Featured services error:", error);

    res.status(500).send({
      message: "Failed to fetch featured services",
    });
  }
});


//booking related apis
app.post("/bookings", verifyToken, verifyCustomer, async (req, res) => {
  try {
    const {
      serviceId,
      eventDate,
      eventLocation,
      additionalMessage,
    } = req.body;

    //prevent add long location
    if (eventLocation.length > 200) {
      return res.status(400).send({
        message: "Event location cannot exceed 200 characters.",
      });
    }

    //prevent long paragraph
    if (additionalMessage && additionalMessage.length > 500) {
      return res.status(400).send({
        message: "Additional message cannot exceed 500 characters.",
      });
    }

    // Validate required fields
    if (!serviceId || !eventDate || !eventLocation) {
      return res.status(400).send({
        message: "Service, event date, and event location are required.",
      });
    }

    if (!ObjectId.isValid(serviceId)) {
      return res.status(400).send({
        message: "Invalid service ID.",
      });
    }

    // Validate event date
    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(eventDate) ||
      !Number.isFinite(Date.parse(`${eventDate}T00:00:00Z`)) ||
      new Date(`${eventDate}T00:00:00Z`).toISOString().slice(0, 10) !== eventDate
    ) {
      return res.status(400).send({
        message: "Invalid event date.",
      });
    }

    //force user to add future date
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const selectedDate = new Date(`${eventDate}T00:00:00`);

    if (selectedDate < today) {
      return res.status(400).send({
        message: "Event date cannot be in the past.",
      });
    }

    // Find the selected service
    const service = await services.findOne({
      _id: new ObjectId(serviceId),
      status: "approved",
      availability: "active",
    });

    if (!service) {
      return res.status(404).send({
        message: "Service not found or unavailable.",
      });
    }

    const customerId = req.user._id.toString();
    const vendorId = service.vendorId;

    // Prevent vendors from booking their own services
    if (customerId === vendorId) {
      return res.status(403).send({
        message: "You cannot book your own service.",
      });
    }

    // Prevent duplicate active booking requests
    const existingBooking = await bookings.findOne({
      serviceId,
      customerId,
      eventDate,
      status: { $in: ["Pending", "Accepted"] },
    });

    if (existingBooking) {
      return res.status(409).send({
        message: "You already have an active booking for this service and event date.",
      });
    }

    // Create booking
    const newBooking = {
      serviceId,
      vendorId,
      customerId,
      eventDate,
      eventLocation: eventLocation.trim(),
      additionalMessage: additionalMessage?.trim() || "",
      status: "Pending",
      createdAt: new Date(),
    };

    const result = await bookings.insertOne(newBooking);

    res.status(201).send({
      message: "Booking request submitted successfully.",
      booking: {
        ...newBooking,
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Create booking error:", error);

    res.status(500).send({
      message: "Failed to create booking.",
    });
  }
});

//vendor bookings
app.get("/vendor/bookings", verifyToken, verifyVendor, async (req, res) => {
  try {
    const vendorId = req.user._id.toString();

    const vendorBookings = await bookings
      .find({ vendorId })
      .sort({ createdAt: -1 })
      .toArray();

    res.send({
      bookings: vendorBookings,
      total: vendorBookings.length,
    });
  } catch (error) {
    console.error("Get vendor bookings error:", error);

    res.status(500).send({
      message: "Failed to fetch vendor bookings.",
    });
  }
});

//vendor update booking status
app.patch(
  "/vendor/bookings/:id/status",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid booking ID.",
        });
      }

      if (!["Accepted", "Rejected"].includes(status)) {
        return res.status(400).send({
          message: "Invalid booking status.",
        });
      }

      const result = await bookings.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.user._id.toString(),
          status: "Pending",
        },
        {
          $set: { status },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({
          message: "Pending booking not found.",
        });
      }

      res.send({
        message: `Booking ${status.toLowerCase()} successfully.`,
      });
    } catch (error) {
      console.error("Update booking status error:", error);

      res.status(500).send({
        message: "Failed to update booking status.",
      });
    }
  }
);


//customer bookings
app.get("/customer/bookings", verifyToken, verifyCustomer, async (req, res) => {
  try {
    const customerId = req.user._id.toString();

    const customerBookings = await bookings
      .find({ customerId })
      .sort({ createdAt: -1 })
      .toArray();

    const bookingsWithDetails = await Promise.all(
      customerBookings.map(async (booking) => {
        const service = await services.findOne({
          _id: new ObjectId(booking.serviceId),
        });

        const vendor = await users.findOne({
          _id: new ObjectId(booking.vendorId),
        });

        return {
          ...booking,
          service: service
            ? {
              serviceName: service.serviceName,
              category: service.category,
              images: service.images,
              price: service.price,
            }
            : null,
          vendor: vendor
            ? {
              name: vendor.name,
              email: vendor.email,
              image: vendor.image,
            }
            : null,
        };
      })
    );

    res.send({
      bookings: bookingsWithDetails,
      total: bookingsWithDetails.length,
    });
  } catch (error) {
    console.error("Get customer bookings error:", error);

    res.status(500).send({
      message: "Failed to fetch customer bookings.",
    });
  }
});


//customer booking cancel
app.patch(
  "/customer/bookings/:id/cancel",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { id } = req.params;
      const customerId = req.user._id.toString();

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid booking ID.",
        });
      }

      const result = await bookings.updateOne(
        {
          _id: new ObjectId(id),
          customerId,
          status: { $in: ["Pending", "Accepted"] },
        },
        {
          $set: { status: "Cancelled" },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({
          message: "Booking not found or cannot be cancelled.",
        });
      }

      res.send({
        message: "Booking cancelled successfully.",
      });
    } catch (error) {
      console.error("Cancel booking error:", error);

      res.status(500).send({
        message: "Failed to cancel booking.",
      });
    }
  }
);


//vendor related apis

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
      availability: "active",
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


// Get all services created by the authenticated vendor
app.get(
  "/vendor/services",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const vendorId = req.user._id.toString();

      const vendorServices = await services
        .find({ vendorId })
        .sort({ createdAt: -1 })
        .toArray();

      res.send({
        services: vendorServices,
        total: vendorServices.length,
      });

    } catch (error) {
      console.error("Get vendor services error:", error);

      res.status(500).send({
        message: "Failed to fetch vendor services",
      });
    }
  }
);


// Update a service created by the authenticated vendor
app.patch(
  "/vendor/services/:id",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid service ID",
        });
      }

      const {
        serviceName,
        category,
        description,
        price,
        location,
        images,
      } = req.body;

      const updateData = {
        serviceName,
        category,
        description,
        price,
        location,
        images,
      };

      // Remove undefined fields
      Object.keys(updateData).forEach((key) => {
        if (updateData[key] === undefined) {
          delete updateData[key];
        }
      });

      const result = await services.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.user._id.toString(),
        },
        {
          $set: updateData,
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({
          message: "Service not found",
        });
      }

      res.send({
        message: "Service updated successfully",
      });

    } catch (error) {
      console.error("Update vendor service error:", error);

      res.status(500).send({
        message: "Failed to update service",
      });
    }
  }
);


// Delete a service created by the authenticated vendor
app.delete(
  "/vendor/services/:id",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid service ID",
        });
      }

      const result = await services.deleteOne({
        _id: new ObjectId(id),
        vendorId: req.user._id.toString(),
      });

      if (result.deletedCount === 0) {
        return res.status(404).send({
          message: "Service not found",
        });
      }

      res.send({
        message: "Service deleted successfully",
      });

    } catch (error) {
      console.error("Delete vendor service error:", error);

      res.status(500).send({
        message: "Failed to delete service",
      });
    }
  }
);


//availability check
app.patch(
  "/vendor/services/:id/availability",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { availability } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid service ID",
        });
      }

      if (!["active", "inactive"].includes(availability)) {
        return res.status(400).send({
          message: "Invalid availability value",
        });
      }

      const result = await services.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.user._id.toString(),
          status: "approved",
        },
        {
          $set: { availability },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({
          message: "Approved service not found",
        });
      }

      res.send({
        message: "Service availability updated successfully",
      });

    } catch (error) {
      console.error("Update service availability error:", error);

      res.status(500).send({
        message: "Failed to update service availability",
      });
    }
  }
);

//TODO: check it later
//service related apis
// app.post("/services", verifyToken, verifyVendor, async (req, res) => {
//   try {
//     // 1. Check vendor role
//     //verifyVendor

//     // 2. Get form data
//     const {
//       serviceName,
//       category,
//       description,
//       price,
//       location,
//       images,
//     } = req.body;

//     // 3. Validate required text fields
//     if (
//       typeof serviceName !== "string" ||
//       !serviceName.trim() ||
//       typeof category !== "string" ||
//       !category.trim() ||
//       typeof description !== "string" ||
//       !description.trim() ||
//       typeof location !== "string" ||
//       !location.trim()
//     ) {
//       return res.status(400).send({
//         message: "All fields are required",
//       });
//     }

//     // 4. Validate category
//     const allowedCategories = [
//       "Photography",
//       "Catering",
//       "Decoration",
//       "Venue",
//       "Makeup",
//       "Other",
//     ];

//     if (!allowedCategories.includes(category)) {
//       return res.status(400).send({
//         message: "Invalid service category",
//       });
//     }

//     // 5. Validate price
//     const servicePrice = Number(price);

//     if (
//       price === undefined ||
//       price === null ||
//       price === "" ||
//       !Number.isFinite(servicePrice) ||
//       servicePrice <= 0
//     ) {
//       return res.status(400).send({
//         message: "Price must be a valid positive number",
//       });
//     }

//     // 6. Validate image URL
//     if (
//       !Array.isArray(images) ||
//       images.length !== 1 ||
//       typeof images[0] !== "string"
//     ) {
//       return res.status(400).send({
//         message: "Please provide one service image",
//       });
//     }

//     let imageUrl;

//     try {
//       imageUrl = new URL(images[0]);

//       if (imageUrl.protocol !== "https:") {
//         throw new Error("Invalid image URL");
//       }
//     } catch {
//       return res.status(400).send({
//         message: "Please provide a valid HTTPS image URL",
//       });
//     }

//     // 7. Prepare service document
//     const serviceData = {
//       vendorId: req.user._id.toString(),
//       serviceName: serviceName.trim(),
//       category,
//       description: description.trim(),
//       price: servicePrice,
//       location: location.trim(),
//       images: [imageUrl.href],
//       status: "pending",
//       availability: "active",
//       createdAt: new Date(),
//     };

//     // 8. Save to MongoDB
//     const result = await services.insertOne(serviceData);

//     res.status(201).send({
//       message: "Service submitted successfully. Waiting for admin approval.",
//       insertedId: result.insertedId,
//     });

//   } catch (error) {
//     console.error("Add service error:", error);

//     res.status(500).send({
//       message: "Failed to add service",
//     });
//   }
// });

//admin related apis



// Get logged-in admin profile
app.get("/admin/profile", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const admin = await users.findOne(
      { _id: req.user._id },
      {
        projection: {
          name: 1,
          email: 1,
          image: 1,
          role: 1,
          isBlocked: 1,
          createdAt: 1,
        },
      }
    );

    if (!admin) {
      return res.status(404).send({
        message: "Admin profile not found",
      });
    }

    res.send({ admin });
  } catch (error) {
    res.status(500).send({
      message: "Failed to fetch admin profile",
    });
  }
});




//admin dashboard
app.get(
  "/admin/dashboard-stats",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const [
        totalUsers,
        totalVendors,
        totalCustomers,
        totalServices,
        pendingServices,
        totalTransactions,
      ] = await Promise.all([
        users.countDocuments(),
        users.countDocuments({ role: "VENDOR" }),
        users.countDocuments({ role: "CUSTOMER" }),
        services.countDocuments(),
        services.countDocuments({ status: "pending" }),
        transactions.countDocuments(),
      ]);

      res.send({
        totalUsers,
        totalVendors,
        totalCustomers,
        totalServices,
        pendingServices,
        totalTransactions,
      });

    } catch (error) {
      console.error("Admin dashboard stats error:", error);

      res.status(500).send({
        message: "Failed to load admin dashboard statistics",
      });
    }
  }
);


//admin user check
app.get(
  "/admin/users",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { search, role } = req.query;

      const query = {};

      // Search by name or email
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ];
      }

      // Filter by user role
      if (role && ["CUSTOMER", "VENDOR", "ADMIN"].includes(role)) {
        query.role = role;
      }

      const allUsers = await users
        .find(query)
        .project({
          name: 1,
          email: 1,
          image: 1,
          role: 1,
          isBlocked: 1,
          subscriptionPlan: 1,
          createdAt: 1,
        })
        .sort({ createdAt: -1 })
        .toArray();

      res.send({
        users: allUsers,
        total: allUsers.length,
      });

    } catch (error) {
      console.error("Get users error:", error);

      res.status(500).send({
        message: "Failed to fetch users",
      });
    }
  }
);



//admin approval
app.patch("/admin/services/:id/approve", verifyToken, verifyAdmin, async (req, res) => {
  try {
    // 1. Only admins can approve services.
    //verifyAdmin

    // 2. Validate the service ID.
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid service ID",
      });
    }

    // 3. Find the service.
    const service = await services.findOne({
      _id: new ObjectId(id),
    });

    if (!service) {
      return res.status(404).send({
        message: "Service not found",
      });
    }

    // 4. Only pending services can be approved.
    if (service.status !== "pending") {
      return res.status(400).send({
        message: "Only pending services can be approved",
      });
    }

    // 5. Find the vendor who owns this service.
    if (!ObjectId.isValid(service.vendorId)) {
      return res.status(400).send({
        message: "Invalid vendor ID",
      });
    }

    const vendor = await users.findOne({
      _id: new ObjectId(service.vendorId),
    });

    if (!vendor) {
      return res.status(404).send({
        message: "Vendor not found",
      });
    }

    // 6. Enforce the Free Plan limit.
    if (vendor.subscriptionPlan !== "PREMIUM") {
      const approvedCount = await services.countDocuments({
        vendorId: service.vendorId,
        status: "approved",
      });

      if (approvedCount >= 3) {
        return res.status(409).send({
          message: "This vendor has reached the Free Plan limit of 3 approved services. They must upgrade to Premium.",
        });
      }
    }

    // 7. Approve the service.
    const result = await services.updateOne(
      {
        _id: new ObjectId(id),
        status: "pending",
      },
      {
        $set: {
          status: "approved",
          approvedAt: new Date(),
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(409).send({
        message: "Service could not be approved. Please try again.",
      });
    }

    res.send({
      message: "Service approved successfully",
    });

  } catch (error) {
    console.error("Approve service error:", error);

    res.status(500).send({
      message: "Failed to approve service",
    });
  }
});

//admin reject
app.patch("/admin/services/:id/reject", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid service ID",
      });
    }

    const service = await services.findOne({
      _id: new ObjectId(id),
    });

    if (!service) {
      return res.status(404).send({
        message: "Service not found",
      });
    }

    if (service.status !== "pending") {
      return res.status(400).send({
        message: "Only pending services can be rejected",
      });
    }

    await services.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: "rejected",
          rejectedAt: new Date(),
        },
      }
    );

    res.send({
      message: "Service rejected successfully",
    });
  } catch (error) {
    console.error("Reject service error:", error);

    res.status(500).send({
      message: "Failed to reject service",
    });
  }
});

//block users
app.patch(
  "/admin/users/:id/block",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Validate user ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid user ID",
        });
      }

      // Find target user
      const targetUser = await users.findOne({
        _id: new ObjectId(id),
      });

      if (!targetUser) {
        return res.status(404).send({
          message: "User not found",
        });
      }

      // Prevent blocking yourself
      if (req.user._id.toString() === id) {
        return res.status(400).send({
          message: "You cannot block your own account",
        });
      }

      // Prevent blocking another admin
      if (targetUser.role === "ADMIN") {
        return res.status(403).send({
          message: "You cannot block an admin account",
        });
      }

      // Block user
      await users.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isBlocked: true } }
      );

      res.send({
        message: "User blocked successfully",
      });

    } catch (error) {
      console.error("Block user error:", error);

      res.status(500).send({
        message: "Failed to block user",
      });
    }
  }
);

//unblock user
app.patch(
  "/admin/users/:id/unblock",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Validate user ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid user ID",
        });
      }

      // Find target user
      const targetUser = await users.findOne({
        _id: new ObjectId(id),
      });

      if (!targetUser) {
        return res.status(404).send({
          message: "User not found",
        });
      }

      if (targetUser.role === "ADMIN") {
        return res.status(403).send({
          message: "Admin accounts cannot be modified here",
        });
      }

      // Unblock user
      await users.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isBlocked: false } }
      );

      res.send({
        message: "User unblocked successfully",
      });

    } catch (error) {
      console.error("Unblock user error:", error);

      res.status(500).send({
        message: "Failed to unblock user",
      });
    }
  }
);


//users
app.get(
  "/admin/users/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid user ID",
        });
      }

      const user = await users.findOne(
        { _id: new ObjectId(id) },
        {
          projection: {
            name: 1,
            email: 1,
            image: 1,
            role: 1,
            isBlocked: 1,
            subscriptionPlan: 1,
            businessName: 1,
            createdAt: 1,
          },
        }
      );

      if (!user) {
        return res.status(404).send({
          message: "User not found",
        });
      }

      res.send({ user });

    } catch (error) {
      console.error("Get user details error:", error);

      res.status(500).send({
        message: "Failed to fetch user details",
      });
    }
  }
);


//services
app.get(
  "/admin/services",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { search, category, status } = req.query;

      // Build MongoDB filter
      const matchQuery = {};

      // Search by service name
      if (search) {
        matchQuery.serviceName = {
          $regex: search,
          $options: "i",
        };
      }

      // Filter by category
      const allowedCategories = [
        "Photography",
        "Catering",
        "Decoration",
        "Venue",
        "Makeup",
        "Other",
      ];

      if (category) {
        if (!allowedCategories.includes(category)) {
          return res.status(400).send({
            message: "Invalid service category",
          });
        }

        matchQuery.category = category;
      }

      // Filter by approval status
      const allowedStatuses = [
        "pending",
        "approved",
        "rejected",
      ];

      if (status) {
        if (!allowedStatuses.includes(status)) {
          return res.status(400).send({
            message: "Invalid service status",
          });
        }

        matchQuery.status = status;
      }

      const allServices = await services
        .aggregate([
          // Apply filters first
          {
            $match: matchQuery,
          },
          {
            $sort: { createdAt: -1 },
          },
          {
            $addFields: {
              vendorObjectId: {
                $toObjectId: "$vendorId",
              },
            },
          },
          {
            $lookup: {
              from: "users",
              localField: "vendorObjectId",
              foreignField: "_id",
              as: "vendor",
            },
          },
          {
            $unwind: {
              path: "$vendor",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              vendorObjectId: 0,
              "vendor.password": 0,
              "vendor.emailVerified": 0,
            },
          },
        ])
        .toArray();

      res.send({
        services: allServices,
        total: allServices.length,
      });

    } catch (error) {
      console.error("Get admin services error:", error);

      res.status(500).send({
        message: "Failed to fetch services",
      });
    }
  }
);

//availability
app.patch("/admin/services/:id/availability", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { availability } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid service ID",
      });
    }

    if (!["active", "inactive"].includes(availability)) {
      return res.status(400).send({
        message: "Invalid availability status",
      });
    }

    const service = await services.findOne({
      _id: new ObjectId(id),
    });

    if (!service) {
      return res.status(404).send({
        message: "Service not found",
      });
    }

    if (service.status !== "approved") {
      return res.status(400).send({
        message: "Only approved services can change availability",
      });
    }

    await services.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          availability,
          updatedAt: new Date(),
        },
      }
    );

    res.send({
      message: `Service ${availability} successfully`,
    });

  } catch (error) {
    console.error("Update availability error:", error);

    res.status(500).send({
      message: "Failed to update service availability",
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


//delete
app.delete("/admin/services/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid service ID",
      });
    }

    const result = await services.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).send({
        message: "Service not found",
      });
    }

    res.send({
      message: "Service deleted successfully",
    });

  } catch (error) {
    console.error("Delete service error:", error);

    res.status(500).send({
      message: "Failed to delete service",
    });
  }
});

//transactions
app.get("/admin/transactions", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { search, status, plan } = req.query;

    const matchQuery = {};

    const allowedStatuses = ["pending", "paid", "failed", "cancelled"];
    const allowedPlans = ["PREMIUM", "FREE"];

    if (status) {
      if (!allowedStatuses.includes(status)) {
        return res.status(400).send({
          message: "Invalid transaction status",
        });
      }

      matchQuery.status = status;
    }

    if (plan) {
      if (!allowedPlans.includes(plan)) {
        return res.status(400).send({
          message: "Invalid subscription plan",
        });
      }

      matchQuery.plan = plan;
    }

    const pipeline = [
      {
        $addFields: {
          vendorObjectId: {
            $toObjectId: "$vendorId",
          },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "vendorObjectId",
          foreignField: "_id",
          as: "vendor",
        },
      },
      {
        $unwind: {
          path: "$vendor",
          preserveNullAndEmptyArrays: true,
        },
      },
    ];

    if (search) {
      pipeline.push({
        $match: {
          $or: [
            { "vendor.name": { $regex: search, $options: "i" } },
            { "vendor.email": { $regex: search, $options: "i" } },
          ],
        },
      });
    }

    pipeline.push(
      { $match: matchQuery },
      {
        $project: {
          _id: 1,
          vendorId: 1,
          plan: 1,
          amount: 1,
          currency: 1,
          status: 1,
          createdAt: 1,
          vendor: {
            _id: 1,
            name: 1,
            email: 1,
            image: 1,
            businessName: 1,
          },
        },
      },
      { $sort: { createdAt: -1 } }
    );

    const allTransactions = await transactions.aggregate(pipeline).toArray();

    res.send({
      transactions: allTransactions,
      total: allTransactions.length,
    });

  } catch (error) {
    console.error("Get transactions error:", error);

    res.status(500).send({
      message: "Failed to fetch transactions",
    });
  }
});



app.get('/', (req, res) => {
  res.send('Wedding is loadingggg!')
})

app.listen(port, () => {
  console.log(`Wedding is loading at ${port}`)
})


export default app;