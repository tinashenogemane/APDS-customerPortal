import express from "express";
import db from "../db/conn.mjs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import ExpressBrute from "express-brute";
import { ObjectId } from "mongodb";

const router = express.Router();

// Setup Express-Brute to prevent brute-force attacks
var store = new ExpressBrute.MemoryStore();
var bruteforce = new ExpressBrute(store);

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";

// RegEx patterns for whitelisting inputs
const regexPatterns = {
    fullName: /^[a-zA-Z\s]+$/,             // Only letters and spaces
    idNumber: /^\d{13}$/,                  // Exactly 13 digits for ID numbers
    accountNumber: /^\d{10,12}$/,          // Account numbers can be 10 to 12 digits
    password: /^[A-Za-z\d@$!%*#?&]{8,}$/,  // At least 8 characters, letters, digits, and symbols
    amount: /^\d+(\.\d{1,2})?$/,           // Valid format for money (e.g., 100 or 100.00)
    currency: /^[A-Z]{3}$/,                // Currency in 3 uppercase letters (ISO 4217)
    swiftCode: /^[A-Z]{6}[A-Z\d]{2}([A-Z\d]{3})?$/  // SWIFT code format
};

// Validation helper function
function validateInput(data, pattern) {
    return pattern.test(data);
}

// Customer Signup
router.post("/signup", async (req, res) => {
    const { fullName, idNumber, accountNumber, password } = req.body;

    try {
        // Validate inputs using RegEx patterns
        if (!validateInput(fullName, regexPatterns.fullName) ||
            !validateInput(idNumber, regexPatterns.idNumber) ||
            !validateInput(accountNumber, regexPatterns.accountNumber) ||
            !validateInput(password, regexPatterns.password)) {
            return res.status(400).json({ message: "Invalid input format" });
        }

        // Hash the user's password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new customer document
        let newCustomer = {
            fullName,
            idNumber,
            accountNumber,
            password: hashedPassword,
        };

        //database
        let collection = await db.collection("customers");
        await collection.insertOne(newCustomer);

        res.status(201).json({ message: "Customer registered successfully" });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ message: "Signup failed" });
    }
});

// Customer Login
router.post("/login", bruteforce.prevent, async (req, res) => {
    console.log("Login request received:", req.body); // Log incoming request data

    const { username, accountNumber, password } = req.body;

    try {
        // Validate inputs
        if (!validateInput(username, regexPatterns.fullName) ||
            !validateInput(accountNumber, regexPatterns.accountNumber) ||
            !validateInput(password, regexPatterns.password)) {
            console.log("Invalid input format"); // Log validation failure
            return res.status(400).json({ message: "Invalid input format" });
        }

        // Find the customer by username and account number (case-insensitive)
        const collection = await db.collection("customers");
        const customer = await collection.findOne({ 
            fullName: new RegExp(`^${username}$`, 'i'), 
            accountNumber 
        });

        if (!customer) {
            console.log("User not found or account number is incorrect"); // Log user not found
            return res.status(401).json({ message: "User not found or account number is incorrect" });
        }

        // Compare the passwords
        const passwordMatch = await bcrypt.compare(password, customer.password);
        if (!passwordMatch) {
            console.log("Incorrect password"); // Log incorrect password
            return res.status(401).json({ message: "Incorrect password" });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { username: customer.fullName, accountNumber },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        console.log("Login successful, token generated"); // Log successful login
        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Login error:", error); // Log server error
        res.status(500).json({ message: "Login failed due to server error" });
    }
});

// Employee Login
router.post("/employee/login", bruteforce.prevent, async (req, res) => {
    const { username, password } = req.body;
    console.log("Received login request for employee:", username); // Log the incoming request

    try {
        // Validate inputs
        if (!validateInput(username, regexPatterns.fullName) ||
            !validateInput(password, regexPatterns.password)) {
            console.log("Invalid input format for username or password"); // Log validation failure
            return res.status(400).json({ message: "Invalid input format" });
        }

        // Find the employee in the database (case-insensitive)
        const collection = await db.collection("employees");
        const employee = await collection.findOne({ username: new RegExp(`^${username}$`, 'i') });
        console.log("Employee found:", employee); // Log the employee data

        // If the employee does not exist
        if (!employee) {
            console.log("Employee not found"); // Log employee not found
            return res.status(401).json({ message: "Employee not found" });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, employee.password);
        console.log("Password match:", passwordMatch); // Log password comparison result
        if (!passwordMatch) {
            console.log("Incorrect password"); // Log incorrect password
            return res.status(401).json({ message: "Incorrect password" });
        }

        // Generate JWT for the employee
        const token = jwt.sign(
            { username: employee.username, role: "employee" },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        console.log("Employee login successful, token generated"); // Log successful login
        res.status(200).json({ message: "Employee login successful", token });
    } catch (error) {
        console.error("Employee login error:", error); // Log server error
        res.status(500).json({ message: "Login failed due to server error" });
    }
});

// Customer Payment Creation
router.post("/payment", async (req, res) => {
    const { customer, amount, currency, provider, payeeAccount, swiftCode, token } = req.body;
    console.log("Received payment request:", req.body); // Log incoming request data

    // Validate required fields
    if (!customer || !amount || !currency || !provider || !payeeAccount || !payeeAccount.recipientName || !payeeAccount.recipientAccountNumber || !swiftCode) {
        return res.status(400).json({ message: "Invalid payment data" });
    }

    // Simulate user validation (replace with actual validation logic)
    const isValidUser = validateUserSession(customer, token); // Implement this function to check user session
    if (!isValidUser) {
        return res.status(401).json({ message: "Unauthorized user" });
    }

    try {
        // Insert payment into the database
        const collection = await db.collection("payments");
        const payment = {
            customer,
            amount,
            currency,
            provider,
            payeeAccount,
            swiftCode,
            status: "Pending",
            createdAt: new Date()
        };
        const result = await collection.insertOne(payment);
        console.log("Payment inserted:", result.insertedId); // Log the inserted payment ID

        res.status(200).json({ message: "Payment created successfully" });
    } catch (error) {
        console.error("Error inserting payment:", error); // Log any errors during insertion
        res.status(500).json({ message: "Failed to create payment." });
    }
});

// Example function to validate user session
function validateUserSession(username, token) {
    // Implement actual logic to validate the user session
    // For example, check if the token is valid for the given username
    return true; // Placeholder: replace with actual validation
}

// Employee Payment Verification
router.post("/payment/verify", async (req, res) => {
    const { paymentId, swiftCode, token } = req.body;
    console.log("Received verification request:", req.body); // Log incoming request data

    try {
        // Validate inputs
        if (!validateInput(swiftCode, regexPatterns.swiftCode)) {
            console.log("Invalid SWIFT code format"); // Log validation failure
            return res.status(400).json({ message: "Invalid SWIFT code format" });
        }

        // Verify JWT
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded || decoded.role !== "employee") {
            console.log("Unauthorized access attempt"); // Log unauthorized access
            return res.status(401).json({ message: "Unauthorized" });
        }

        // Find the payment by ID
        const collection = await db.collection("payments");
        const payment = await collection.findOne({ _id: new ObjectId(paymentId) });

        if (!payment) {
            console.log("Payment not found"); // Log payment not found
            return res.status(404).json({ message: "Payment not found" });
        }

        // Verify SWIFT code
        if (payment.swiftCode !== swiftCode) {
            console.log("SWIFT code mismatch"); // Log SWIFT code mismatch
            return res.status(400).json({ message: "SWIFT code mismatch" });
        }

        // Mark the payment as verified
        await collection.updateOne({ _id: new ObjectId(paymentId) }, { $set: { status: "Verified" } });

        console.log("Payment verified successfully"); // Log successful verification
        res.status(200).json({ message: "Payment verified successfully" });
    } catch (error) {
        console.error("Payment verification error:", error); // Log server error
        res.status(500).json({ message: "Payment verification failed" });
    }
});

router.get("/payment/verify", async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log("Decoded token:", decoded); // Log decoded token

        if (!decoded || decoded.role !== "employee") {
            console.log("Unauthorized access attempt"); // Log unauthorized access
            return res.status(401).json({ message: "Unauthorized" });
        }

        const collection = await db.collection("payments");
        const payments = await collection.find({ status: "Pending" }).toArray();
        console.log("Pending payments found:", payments); // Log pending payments

        res.status(200).json({ payments });
    } catch (error) {
        console.error("Error fetching payments:", error); // Log server error
        res.status(500).json({ message: "Failed to fetch payments." });
    }
});

export default router;
