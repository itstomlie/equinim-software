const express = require("express");
const path = require("path");

const app = express();
const port = 3000;

// --- Simple In-Memory "Session" ---
// WARNING: This is NOT suitable for production.
// Real applications should use proper session management (e.g., express-session).
const sessions = {}; // Store user data keyed by a simple session ID (just username for demo)

// --- Middleware ---
// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: true }));

// Simple session middleware (attach session data to req)
app.use((req, res, next) => {
  // In a real app, you'd use a secure cookie to store/retrieve session ID
  // For simplicity, we'll just use a query param or header if present,
  // or check the simple sessions object. This is highly insecure.
  const sessionId = req.query.sessionId || req.headers["x-session-id"];
  if (sessionId && sessions[sessionId]) {
    req.session = sessions[sessionId]; // Attach user data
  } else {
    req.session = null; // No active session
  }
  next();
});

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next(); // User is logged in, proceed
  }
  // User not logged in
  res
    .status(401)
    .send('Unauthorized: Please login first. <a href="/">Login</a>');
}

// Authorization Middleware (checks role)
function isAuthorized(requiredRole) {
  return (req, res, next) => {
    if (
      req.session &&
      req.session.user &&
      req.session.user.role === requiredRole
    ) {
      return next(); // User has the required role
    }
    // User does not have the required role
    res
      .status(403)
      .send(
        `Forbidden: You need the '${requiredRole}' role to access this resource. <a href="/">Home</a>`
      );
  };
}

// --- Routes ---

// Serve the HTML page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Login Route
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // --- Extremely Simple Authentication ---
  // WARNING: Never store passwords in plain text! Use hashing (e.g., bcrypt).
  // WARNING: Use a database for users in a real app.
  if (username === "user" && password === "password") {
    const sessionId = username; // Using username as session ID for simplicity
    sessions[sessionId] = { user: { username: "user", role: "user" } };
    // In a real app, set a secure, HTTP-only cookie with the session ID.
    // For demo, we just tell the user to use it as a query param.
    res.send(
      `Login successful! Welcome, ${username}. <br>To access protected routes, append '?sessionId=${sessionId}' to the URL or include 'X-Session-ID: ${sessionId}' header. <br><a href="/">Home</a>`
    );
  } else if (username === "admin" && password === "adminpass") {
    const sessionId = username;
    sessions[sessionId] = { user: { username: "admin", role: "admin" } };
    res.send(
      `Login successful! Welcome, ${username}. <br>To access protected routes, append '?sessionId=${sessionId}' to the URL or include 'X-Session-ID: ${sessionId}' header. <br><a href="/">Home</a>`
    );
  } else {
    res
      .status(401)
      .send('Login failed: Invalid credentials. <a href="/">Try again</a>');
  }
});

// Logout Route
app.post("/logout", (req, res) => {
  // For our simple demo, we need the sessionId to know *who* is logging out
  const sessionId = req.query.sessionId || req.headers["x-session-id"];
  if (sessionId && sessions[sessionId]) {
    delete sessions[sessionId]; // Remove session data
    res.send('Logout successful. <a href="/">Login again</a>');
  } else {
    res
      .status(400)
      .send(
        'Could not log out: Session ID not provided or invalid. <a href="/">Home</a>'
      );
  }
});

// Protected Route (requires login, any role)
app.get("/user-resource", isAuthenticated, (req, res) => {
  res.send(
    `Hello ${req.session.user.username}! This is a protected resource for all logged-in users.`
  );
});

// Protected Route (requires login and 'admin' role)
app.get(
  "/admin-resource",
  isAuthenticated,
  isAuthorized("admin"),
  (req, res) => {
    res.send(
      `Hello ${req.session.user.username}! This is a protected resource for admins only.`
    );
  }
);

// --- Start Server ---
app.listen(port, () => {
  console.log(`Auth demo server listening at http://localhost:${port}`);
});

// Basic Error Handling (Optional but good practice)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});
