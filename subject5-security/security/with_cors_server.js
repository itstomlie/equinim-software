const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const app = express();
const PORT = 3001;

// --- Middleware ---

// CORS: Allow requests from any origin
app.use(cors());

// Rate Limiting: Limit each IP to 5 requests per minute for specific routes
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // Limit each IP to 5 requests per windowMs
  message: "Too many requests from this IP, please try again after a minute",
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Apply the rate limiting middleware to specific sensitive routes (or all routes if desired)
// We'll apply it globally for this demo, except for the basic root route
app.use("/hash", limiter);
app.use("/encrypt", limiter);
// We could apply it to all requests *after* cors by doing: app.use(limiter);

// Body Parsing: Needed to parse JSON bodies (e.g., for the /hash endpoint)
app.use(express.json());

// Apply rate limiter also to the new decrypt route
app.use("/decrypt", limiter);

// --- Routes ---

// Basic route (not rate limited)
app.get("/", (req, res) => {
  res.json({ message: "Hello from Express server WITH CORS!" });
});

// Hashing route (rate limited)
app.post("/hash", async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res
      .status(400)
      .json({ error: "Password is required in the request body" });
  }

  try {
    // Generate a salt and hash the password
    const saltRounds = 12; // Recommended value
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    res.json({ originalPassword: password, hashedPassword: hashedPassword });
  } catch (error) {
    console.error("Hashing error:", error);
    res.status(500).json({ error: "Failed to hash password" });
  }
});

// Encryption route (rate limited) - Changed to POST
app.post("/encrypt", (req, res) => {
  // Changed from GET to POST
  try {
    const { message } = req.body; // Read message from request body

    if (!message) {
      return res
        .status(400)
        .json({ error: "Message is required in the request body" });
    }

    // IMPORTANT: In a real app, use secure key management. Don't hardcode keys!
    // Key must be 32 bytes for AES-256
    const key = crypto
      .createHash("sha256")
      .update("my-secret-key-for-demo")
      .digest("base64")
      .substring(0, 32);
    // IV should be random per encryption, 16 bytes for AES
    const iv = crypto.randomBytes(16);

    console.log(key);

    const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");

    // Send the IV along with the encrypted message (needed for decryption)
    // Usually, the IV is prepended to the ciphertext
    res.json({
      iv: iv.toString("hex"),
      encryptedData: encrypted,
      note: "Data encrypted with AES-256. You'd need the secret key to decrypt.",
    });
  } catch (error) {
    console.error("Encryption error:", error);
    res.status(500).json({ error: "Failed to encrypt message" });
  }
});

// Decryption route (rate limited)
app.post("/decrypt", (req, res) => {
  const { iv, encryptedData } = req.body;

  if (!iv || !encryptedData) {
    return res.status(400).json({
      error:
        "Both iv (hex) and encryptedData (hex) are required in the request body",
    });
  }

  try {
    // IMPORTANT: Use the SAME key derivation as in encryption
    const key = crypto
      .createHash("sha256")
      .update("my-secret-key-for-demo")
      .digest("base64")
      .substring(0, 32);
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(key),
      Buffer.from(iv, "hex")
    );

    let decrypted = decipher.update(encryptedData, "hex", "utf8");
    decrypted += decipher.final("utf8");

    res.json({ decryptedMessage: decrypted });
  } catch (error) {
    // Errors commonly occur if the key is wrong, IV is wrong, or data is corrupt
    console.error("Decryption error:", error);
    res.status(500).json({
      error: "Failed to decrypt message. Check key, IV, and data.",
      details: error.message,
    });
  }
});

// --- Server Start ---
app.listen(PORT, () => {
  console.log(
    `Express server (CORS, Rate Limit, Hash, Encrypt) running at http://localhost:${PORT}/`
  );
});
