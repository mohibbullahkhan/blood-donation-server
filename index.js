require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
var admin = require("firebase-admin");

const fbServiceKey = JSON.parse(process.env.FB_SERVICE_KEY);

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: fbServiceKey.project_id,
    clientEmail: fbServiceKey.client_email,
    privateKey: fbServiceKey.private_key.replace(/\\n/g, "\n"),
  }),
});

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    console.log("decoded in the token", decoded);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

const verifyAdmin = async (req, res, next) => {
  const email = req.decoded_email;

  if (!email) {
    return res
      .status(401)
      .send({ message: "Unauthorized: Email not found in token." });
  }
  try {
    const user = await userCollection.findOne(
      { email },
      { projection: { role: 1 } }
    );
    if (!user || user.role !== "admin") {
      console.warn(`403 Forbidden: User ${email} attempted admin access.`);
      return res
        .status(403)
        .send({ message: "Forbidden: Requires Admin role." });
    }
    next();
  } catch (error) {
    console.error("Error verifying admin status:", error);
    res.status(500).send({ message: "Server error during authorization." });
  }
};

let dbClient = null;
let userCollection = null;
let donationRequestsCollection = null;
let fundingsCollection = null;
const inMemoryDonors = [];

async function initDb() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error("MONGO_URI not defined in .env file.");
    throw new Error("Missing MONGO_URI");
  }
  dbClient = new MongoClient(uri);
  await dbClient.connect();
  const db = dbClient.db(process.env.MONGO_DB_NAME || "bloodDonation");
  userCollection = db.collection("users");
  donationRequestsCollection = db.collection("donationRequests");
  fundingsCollection = db.collection("fundings");
  console.log("Connected to MongoDB");
}

// --- Public Routes setup---
app.get("/", (req, res) => {
  res.json({ message: "Blood Donation API running" });
});

app.post("/users", async (req, res) => {
  const user = req.body;

  user.role = "donor";
  user.status = "active";
  user.createdAt = new Date();

  const email = user.email;

  try {
    const userExists = await userCollection.findOne({ email });

    if (userExists) {
      return res.send({ message: "user exists" });
    }

    const result = await userCollection.insertOne(user);
    res.send(result);
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).send({ message: "Failed to create user" });
  }
});

app.get("/search-donors", async (req, res) => {
  const { bloodGroup, district, upazila } = req.query;

  const query = {
    role: "donor",
    status: "active",
  };

  if (bloodGroup) {
    query.bloodGroup = bloodGroup;
  }

  if (district) {
    query.district = { $regex: new RegExp(district, "i") };
  }

  if (upazila) {
    query.upazila = { $regex: new RegExp(upazila, "i") };
  }

  try {
    const donors = await userCollection
      .find(query)
      .project({
        displayName: 1,
        bloodGroup: 1,
        district: 1,
        upazila: 1,
        photoURL: 1,
        email: 1,
      })
      .limit(20)
      .toArray();

    res.send(donors);
  } catch (error) {
    console.error("Error fetching donors:", error);
    res.status(500).send({ message: "Failed to fetch donor data" });
  }
});

app.post("/donation-requests", async (req, res) => {
  const newRequest = req.body;
  const { requesterEmail } = newRequest;

  if (!requesterEmail) {
    return res.status(400).send({ message: "Requester email is required." });
  }

  try {
    const user = await userCollection.findOne(
      { email: requesterEmail },
      { projection: { status: 1, role: 1 } }
    );

    if (!user) {
      return res.status(404).send({ message: "Requester user not found." });
    }

    if (user.status === "blocked") {
      return res.status(403).send({
        message: "Your account is blocked and cannot create donation requests.",
      });
    }

    const donationRequest = {
      requesterName: newRequest.requesterName,
      requesterEmail: requesterEmail,
      recipientName: newRequest.recipientName,
      recipientDistrict: newRequest.recipientDistrict,
      recipientUpazila: newRequest.recipientUpazila,
      hospitalName: newRequest.hospitalName,
      fullAddressLine: newRequest.fullAddressLine,
      bloodGroup: newRequest.bloodGroup,
      donationDate: new Date(newRequest.donationDate),
      donationTime: newRequest.donationTime,
      requestMessage: newRequest.requestMessage,
      donationStatus: "pending",
      donorInformation: null,
      createdAt: new Date(),
    };

    const result = await donationRequestsCollection.insertOne(donationRequest);

    res.status(201).send({
      message: "Blood donation request created successfully.",
      insertedId: result.insertedId,
    });
  } catch (error) {
    console.error("Error creating donation request:", error);
    res.status(500).send({
      message: "Failed to create donation request due to a server error.",
    });
  }
});

// --- User Dashboard Routes setup---

app.get("/my-recent-requests", async (req, res) => {
  const requesterEmail = req.query.email;

  if (!requesterEmail) {
    return res
      .status(400)
      .send({ message: "Requester email query parameter is required." });
  }

  try {
    const recentRequests = await donationRequestsCollection
      .find({ requesterEmail: requesterEmail })
      .sort({ createdAt: -1 })
      .limit(3)
      .toArray();

    if (recentRequests.length === 0) {
      return res.send({
        message: "No donation requests found for this user.",
        requests: [],
      });
    }

    res.send({ requests: recentRequests });
  } catch (error) {
    console.error("Error fetching recent donation requests:", error);
    res.status(500).send({
      message:
        "Failed to fetch recent donation requests due to a server error.",
    });
  }
});

app.get("/my-donation-requests", async (req, res) => {
  const { email, page = 1, limit = 10, status } = req.query;

  if (!email) {
    return res
      .status(400)
      .send({ message: "Requester email query parameter is required." });
  }

  try {
    const pageNumber = parseInt(page);
    const limitNumber = parseInt(limit);
    const skip = (pageNumber - 1) * limitNumber;

    const query = { requesterEmail: email };

    if (
      status &&
      ["pending", "inprogress", "done", "canceled"].includes(
        status.toLowerCase()
      )
    ) {
      query.donationStatus = status.toLowerCase();
    }

    const totalRequests = await donationRequestsCollection.countDocuments(
      query
    );

    const requests = await donationRequestsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNumber)
      .toArray();

    res.send({
      requests: requests,
      totalRequests: totalRequests,
      currentPage: pageNumber,
      totalPages: Math.ceil(totalRequests / limitNumber),
    });
  } catch (error) {
    console.error("Error fetching all donation requests:", error);
    res.status(500).send({
      message: "Failed to fetch donation requests due to a server error.",
      requests: [],
    });
  }
});

app.get("/users/profile/:email", async (req, res) => {
  const userEmail = req.params.email;

  if (!userEmail) {
    return res.status(400).send({ message: "Email parameter is missing." });
  }

  try {
    const userProfile = await userCollection.findOne(
      { email: userEmail },
      {
        projection: { _id: 0, password: 0 },
      }
    );

    if (!userProfile) {
      return res.status(404).send({
        message:
          "User profile not found in database. Please complete registration.",
      });
    }

    res.send(userProfile);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).send({ message: "Failed to retrieve profile data." });
  }
});

app.patch("/users", async (req, res) => {
  const { email, displayName, photoURL, bloodGroup, district, upazila } =
    req.body;

  if (!email) {
    return res
      .status(400)
      .send({ message: "User email is required for profile update." });
  }

  const updateDoc = {};
  if (displayName) updateDoc.displayName = displayName;
  if (photoURL) updateDoc.photoURL = photoURL;
  if (bloodGroup) updateDoc.bloodGroup = bloodGroup;
  if (district) updateDoc.district = district;
  if (upazila) updateDoc.upazila = upazila;

  updateDoc.updatedAt = new Date();

  if (
    Object.keys(updateDoc).length === 1 &&
    updateDoc.hasOwnProperty("updatedAt")
  ) {
    return res
      .status(400)
      .send({ message: "No updatable fields provided in the request." });
  }

  try {
    const result = await userCollection.findOneAndUpdate(
      { email: email },
      { $set: updateDoc },
      {
        returnDocument: "after",
        projection: { _id: 0, password: 0 },
      }
    );

    if (!result.value) {
      return res
        .status(404)
        .send({ message: "User not found or nothing was modified." });
    }

    res.send(result.value);
  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).send({
      message: "Failed to update profile data due to a server error.",
    });
  }
});

// --- Admin Routes setup---

app.get("/admin/dashboard-stats", async (req, res) => {
  try {
    const totalUsers = await userCollection.countDocuments({ role: "donor" });
    const totalRequests = await donationRequestsCollection.countDocuments({});
    let totalFunding = 0;

    if (fundingsCollection) {
      const fundingResult = await fundingsCollection
        .aggregate([
          {
            $group: {
              _id: null,
              totalAmount: { $sum: "$amount" },
            },
          },
        ])
        .toArray();

      if (fundingResult.length > 0) {
        totalFunding = fundingResult[0].totalAmount;
      }
    }

    res.send({
      totalUsers: totalUsers,
      totalRequests: totalRequests,
      totalFunding: totalFunding ? totalFunding.toFixed(2) : "0.00",
    });
  } catch (error) {
    console.error("Error fetching admin dashboard statistics:", error);
    res.status(500).send({
      message: "Failed to fetch admin stats due to a server error.",
      totalUsers: 0,
      totalRequests: 0,
      totalFunding: "0.00",
    });
  }
});

app.get("/users/all", verifyFBToken, verifyAdmin, async (req, res) => {
  const { page = 1, limit = 10, status } = req.query;

  try {
    const pageNumber = parseInt(page);
    const limitNumber = parseInt(limit);
    const skip = (pageNumber - 1) * limitNumber;

    const query = {};

    if (status && ["active", "blocked"].includes(status.toLowerCase())) {
      query.status = status.toLowerCase();
    }

    const totalUsers = await userCollection.countDocuments(query);

    const users = await userCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNumber)
      .project({ password: 0 })
      .toArray();

    res.send({
      users: users,
      totalUsers: totalUsers,
      currentPage: pageNumber,
      totalPages: Math.ceil(totalUsers / limitNumber),
    });
  } catch (error) {
    console.error("Error fetching all users:", error);
    res.status(500).send({
      message: "Failed to fetch users due to a server error.",
      users: [],
    });
  }
});

// 3. Admin: Update User Role (Make Admin/Volunteer)
app.patch("/users/update-role/:email", async (req, res) => {
  const userEmail = req.params.email;
  const { role } = req.body;
  if (!userEmail || !["admin", "volunteer", "donor"].includes(role)) {
    return res.status(400).send({ message: "Invalid email or role provided." });
  }

  try {
    const result = await userCollection.updateOne(
      { email: userEmail },
      { $set: { role: role, updatedAt: new Date() } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "User not found." });
    }
    res.send({
      message: `User ${userEmail}'s role updated to ${role}.`,
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).send({ message: "Failed to update user role." });
  }
});

// 4. Admin: Update User Status (Block/Unblock)
app.patch("/users/update-status/:email", async (req, res) => {
  const userEmail = req.params.email;
  const { status } = req.body;
  if (!userEmail || !["active", "blocked"].includes(status)) {
    return res
      .status(400)
      .send({ message: "Invalid email or status provided." });
  }

  try {
    const result = await userCollection.updateOne(
      { email: userEmail },
      { $set: { status: status, updatedAt: new Date() } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "User not found." });
    }
    res.send({
      message: `User ${userEmail}'s status updated to ${status}.`,
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error updating user status:", error);
    res.status(500).send({ message: "Failed to update user status." });
  }
});

// --- General Request Update/Delete Routes ---

app.patch("/donation-requests/status/:id", async (req, res) => {
  const requestId = req.params.id;
  const { status } = req.body;

  if (!ObjectId.isValid(requestId)) {
    return res.status(400).send({ message: "Invalid Request ID." });
  }

  if (!["done", "canceled"].includes(status)) {
    return res.status(400).send({
      message: "Invalid status provided. Must be 'done' or 'canceled'.",
    });
  }

  try {
    const result = await donationRequestsCollection.updateOne(
      { _id: new ObjectId(requestId) },
      {
        $set: {
          donationStatus: status,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "Donation request not found." });
    }

    res.send({
      message: `Donation status updated to ${status}.`,
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error updating donation request status:", error);
    res
      .status(500)
      .send({ message: "Failed to update donation request status." });
  }
});

app.delete("/donation-requests/:id", async (req, res) => {
  const requestId = req.params.id;

  if (!ObjectId.isValid(requestId)) {
    return res.status(400).send({ message: "Invalid Request ID." });
  }

  try {
    const result = await donationRequestsCollection.deleteOne({
      _id: new ObjectId(requestId),
    });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .send({ message: "Donation request not found or unauthorized." });
    }

    res.send({
      message: "Donation request deleted successfully.",
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error("Error deleting donation request:", error);
    res.status(500).send({ message: "Failed to delete donation request." });
  }
});

// All donation requests

app.get("/dashboard/all-blood-donation-request", async (req, res) => {
  const { page = 1, limit = 10, status } = req.query;

  try {
    const pageNumber = parseInt(page);
    const limitNumber = parseInt(limit);
    const skip = (pageNumber - 1) * limitNumber;

    const query = {};

    if (
      status &&
      ["pending", "inprogress", "done", "canceled"].includes(
        status.toLowerCase()
      )
    ) {
      query.donationStatus = status.toLowerCase();
    }

    const totalRequests = await donationRequestsCollection.countDocuments(
      query
    );

    const requests = await donationRequestsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNumber)
      .toArray();

    res.send({
      requests: requests,
      totalRequests: totalRequests,
      currentPage: pageNumber,
      totalPages: Math.ceil(totalRequests / limitNumber),
    });
  } catch (error) {
    console.error("Error fetching ALL donation requests for admin:", error);
    res.status(500).send({
      message: "Failed to fetch all donation requests due to a server error.",
      requests: [],
    });
  }
});

// Admin: Assign Donor to a Request

app.patch("/donation-requests/assign-donor/:id", async (req, res) => {
  const requestId = req.params.id;
  const { donorName, donorEmail } = req.body;

  if (!ObjectId.isValid(requestId)) {
    return res.status(400).send({ message: "Invalid Request ID." });
  }
  if (!donorName || !donorEmail) {
    return res
      .status(400)
      .send({ message: "Donor name and email are required." });
  }

  const donorInformation = { donorName, donorEmail };

  try {
    const result = await donationRequestsCollection.updateOne(
      {
        _id: new ObjectId(requestId),
        donationStatus: "pending",
      },
      {
        $set: {
          donationStatus: "inprogress",
          donorInformation: donorInformation,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .send({ message: "Request not found or not in 'pending' status." });
    }

    res.send({
      message: "Donor assigned and status updated to 'inprogress'.",
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error assigning donor:", error);
    res.status(500).send({ message: "Failed to assign donor to request." });
  }
});

// --- Public Routes ---

app.get("/blood-requests/public-pending", async (req, res) => {
  try {
    const pendingRequests = await donationRequestsCollection
      .find({ donationStatus: "pending" })
      .sort({ donationDate: 1, donationTime: 1 })
      .project({
        recipientName: 1,
        bloodGroup: 1,
        recipientDistrict: 1,
        donationDate: 1,
        donationTime: 1,
        _id: 1,
      })
      .limit(100)
      .toArray();

    res.send(pendingRequests);
  } catch (error) {
    console.error("Error fetching public pending requests:", error);
    res.status(500).send({
      message: "Failed to fetch public requests.",
      requests: [],
    });
  }
});

app.get("/donation-requests/:id", async (req, res) => {
  const requestId = req.params.id;

  if (!ObjectId.isValid(requestId)) {
    return res.status(400).send({ message: "Invalid Request ID." });
  }

  try {
    const request = await donationRequestsCollection.findOne({
      _id: new ObjectId(requestId),
    });

    if (!request) {
      return res.status(404).send({ message: "Donation request not found." });
    }

    res.send(request);
  } catch (error) {
    console.error("Error fetching single donation request:", error);
    res.status(500).send({ message: "Failed to fetch request details." });
  }
});

// --- Funding and Payment Routes ---

app.post("/create-funding-checkout-session", async (req, res) => {
  const { amount, donatorEmail, donatorName } = req.body;

  console.log("--- Stripe Checkout Debug ---");
  console.log("Incoming Amount:", amount);
  console.log("Incoming Email:", donatorEmail);
  if (!amount || parseFloat(amount) <= 0.5) {
    return res
      .status(400)
      .send({ message: "Minimum donation amount is $0.50." });
  }

  const amountInCents = Math.round(parseFloat(amount) * 100);

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            unit_amount: amountInCents,
            product_data: {
              name: "Blood Donation Foundation Fund",
              description: "Donation for foundation development.",
            },
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      metadata: {
        donatorEmail: donatorEmail,
        donatorName: donatorName || "Anonymous Donor",
        fundingAmount: amount,
      },
      customer_email: donatorEmail,
      success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_DOMAIN}/payment-cancelled`,
    });
    console.log(session);
    res.send({ url: session.url });
  } catch (error) {
    console.error(">>> DETAILED STRIPE API ERROR MESSAGE:", error);
    res.status(500).send({ message: "Failed to create payment session." });
  }
});

app.get("/funding/payment-success-handler", async (req, res) => {
  const sessionId = req.query.session_id;

  if (!sessionId) {
    return res
      .status(400)
      .send({ success: false, message: "Missing session ID." });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status !== "paid") {
      return res
        .status(400)
        .send({ success: false, message: "Payment was not successful." });
    }

    const transactionId = session.payment_intent;

    const existingFunding = await fundingsCollection.findOne({ transactionId });
    if (existingFunding) {
      return res.send({
        success: true,
        message: "Funding already recorded.",
        transactionId,
      });
    }

    const fundingData = {
      donatorName: session.metadata.donatorName,
      donatorEmail: session.metadata.donatorEmail,
      amount: parseFloat(session.metadata.fundingAmount),
      currency: session.currency,
      transactionId: transactionId,
      paidAt: new Date(),
    };

    const result = await fundingsCollection.insertOne(fundingData);

    res.send({
      success: true,
      message: "Funding recorded successfully.",
      transactionId,
      fundingId: result.insertedId,
    });
  } catch (error) {
    console.error("Error processing successful funding payment:", error);
    res
      .status(500)
      .send({ success: false, message: "Failed to process payment success." });
  }
});

// app.get("/fundings/history", async (req, res) => {
//   try {
//     const history = await fundingsCollection
//       .find({})
//       .sort({ paidAt: -1 })
//       .toArray();

//     res.send(history);
//   } catch (error) {
//     console.error("Error fetching funding history:", error);
//     res.status(500).send({ message: "Failed to fetch funding history." });
//   }
// });
app.get("/fundings/history", async (req, res) => {
  try {
    const email = req.query.email; // Get email from query: /fundings/history?email=user@example.com

    let query = {};
    if (email) {
      query = { donatorEmail: email }; // Filter by email if provided
    }

    const history = await fundingsCollection
      .find(query)
      .sort({ paidAt: -1 })
      .toArray();

    res.send(history);
  } catch (error) {
    console.error("Error fetching funding history:", error);
    res.status(500).send({ message: "Failed to fetch funding history." });
  }
});

// ... (rest of the backend code)

process.on("SIGINT", async () => {
  try {
    if (dbClient) await dbClient.close();
  } catch (e) {
    console.error("Error closing DB", e);
  }
  process.exit();
});

// 🔑 Ensure DB is connected before listening
async function startServer() {
  try {
    await initDb();
    app.listen(port, () => console.log(`Server listening on port ${port}`));
  } catch (err) {
    console.error("💥 Failed to start server due to database error:", err);
    process.exit(1);
  }
}

startServer();
