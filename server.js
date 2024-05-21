import bcrypt from "bcrypt";
import cors from "cors";
import express from "express";
import mongoose from "mongoose";

//connect to mongodb via mongoose
const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth";
mongoose.connect(mongoUrl);
mongoose.Promise = Promise;

const User = mongoose.model("User", {
  name: {
    type: String,
    unique: true,
  },
  email: {
    type: String,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  accessToken: {
    type: String,
    default: () => bcrypt.genSaltSync(),
  },
});

const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({ accessToken: req.header("Authorization") });
  if (user) {
    req.user = user;
    next();
  } else {
    res.status(401).json({ loggedout: true });
  }
};

// Defines the port the app will run on. Defaults to 8080, but can be overridden
// when starting the server. Example command to overwrite PORT env variable value:
// PORT=9000 npm start
const port = process.env.PORT || 8080;
const app = express();

// Add middlewares to enable cors and json body parsing
app.use(cors());
app.use(express.json());

// Start defining your routes here
app.get("/", (req, res) => {
  res.send("Hello Technigo!");
});

app.post("/users", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const user = new User({
      name,
      email,
      password: bcrypt.hashSync(password, 10),
    });
    await user.save();
    res.status(201).json({ id: user._id, accessToken: user.accessToken });
  } catch (error) {
    console.log(error);
    res
      .status(400)
      .json({ message: "Could not create user", errors: error.errors });
  }
});

app.get("/secrets", authenticateUser);
app.get("/secrets", (req, res) => {
  res.json({ secret: "This is a super secret message" });
});

app.post("/sessions", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({ userId: user._id, accessToken: user.accessToken });
  } else {
    res.json({ notFound: true });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
