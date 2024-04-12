const express = require("express");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose"); // Added Mongoose for MongoDB

const app = express();
app.use(express.json());

const cors = require("cors");
app.use(cors()); // Update with your frontend URL

// Replace with your MongoDB connection string from MongoDB Atlas
const mongoURI = process.env.MONGO_URL;

mongoose
  .connect(mongoURI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error(err));

// Define user schema for MongoDB
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema); // Create User model

const bcrypt = require("bcrypt");

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, process.env.SECRET_KEY, async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        next();
      }
    });
  }
};

app.get("/", (request, response) => {
  response.send("Hello World");
});

app.post("/register/", async (request, response) => {
  const { username, password } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return response.status(400).send("User Already Existed");
    }

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    response.status(200).send("User Created Successfully");
  } catch (err) {
    console.error(err);
    response.status(500).send("Server Error");
  }
});

app.post("/login/", async (request, response) => {
  const { username, password } = request.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return response.status(400).send("Invalid User");
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);
    if (!isPasswordMatched) {
      return response.status(400).send("Invalid Password");
    }

    const payload = { username };
    const jwtToken = jwt.sign(payload, process.env.SECRET_KEY);
    response.send({ jwtToken });
  } catch (err) {
    console.error(err);
    response.status(500).send("Server Error");
  }
});

app.get("/users/", authenticateToken, async (request, response) => {
  try {
    const users = await User.find();
    response.send(users);
  } catch (err) {
    console.error(err);
    response.status(500).send("Server Error");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on port ${port}`));
