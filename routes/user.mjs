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

        // Insert into database
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
    const { username, accountNumber, password } = req.body;

    try {
        // Validate inputs
        if (!validateInput(username, regexPatterns.fullName) ||
            !validateInput(accountNumber, regexPatterns.accountNumber) ||
            !validateInput(password, regexPatterns.password)) {
            return res.status(400).json({ message: "Invalid input format" });
        }

        // Find the customer by username and account number
        const collection = await db.collection("customers");
        const customer = await collection.findOne({ fullName: username, accountNumber });

        // If the customer does not exist
        if (!customer) {
            return res.status(401).json({ message: "User not found or account number is incorrect" });
        }

        // Compare the passwords
        const passwordMatch = await bcrypt.compare(password, customer.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Incorrect password" });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { username, accountNumber },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Login failed due to server error" });
    }
});

// Employee Login
router.post("/employee/login", bruteforce.prevent, async (req, res) => {
    const { username, password } = req.body;

    try {
        // Validate inputs
        if (!validateInput(username, regexPatterns.fullName) ||
            !validateInput(password, regexPatterns.password)) {
            return res.status(400).json({ message: "Invalid input format" });
        }

        // Find the employee in the database
        const collection = await db.collection("employees");
        const employee = await collection.findOne({ username });

        // If the employee does not exist
        if (!employee) {
            return res.status(401).json({ message: "Employee not found" });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, employee.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Incorrect password" });
        }

        // Generate JWT for the employee
        const token = jwt.sign(
            { username, role: "employee" },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({ message: "Employee login successful", token });
    } catch (error) {
        console.error("Employee login error:", error);
        res.status(500).json({ message: "Login failed due to server error" });
    }
});

// Customer Payment Creation
router.post("/payment", async (req, res) => {
    const { amount, currency, provider, payeeAccount, swiftCode, token } = req.body;

    try {
        // Validate inputs
        if (!validateInput(amount, regexPatterns.amount) ||
            !validateInput(currency, regexPatterns.currency) ||
            !validateInput(swiftCode, regexPatterns.swiftCode) ||
            !payeeAccount || 
            !validateInput(payeeAccount.recipientName, regexPatterns.fullName) ||
            !validateInput(payeeAccount.recipientAccountNumber, regexPatterns.accountNumber)) {
            return res.status(400).json({ message: "Invalid input format" });
        }

        // Verify JWT
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        // Create a payment document
        let newPayment = {
            customer: decoded.username,
            accountNumber: decoded.accountNumber,
            amount,
            currency,
            provider,
            payeeAccount: {
                recipientName: payeeAccount.recipientName,  // Extract recipient name
                recipientAccountNumber: payeeAccount.recipientAccountNumber,  // Extract recipient account number
            },
            swiftCode,
            status: "Pending"
        };

        // Insert the payment into the database
        let collection = await db.collection("payments");
        await collection.insertOne(newPayment);

        res.status(201).json({ message: "Payment created successfully", payment: newPayment });
    } catch (error) {
        console.error("Payment creation error:", error);
        res.status(500).json({ message: "Payment creation failed" });
    }
});


// Employee Payment Verification
router.post("/payment/verify", async (req, res) => {
    const { paymentId, swiftCode, token } = req.body;

    try {
        // Validate inputs
        if (!validateInput(swiftCode, regexPatterns.swiftCode)) {
            return res.status(400).json({ message: "Invalid SWIFT code format" });
        }

        // Verify JWT
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded || decoded.role !== "employee") {
            return res.status(401).json({ message: "Unauthorized" });
        }

        // Find the payment by ID
        const collection = await db.collection("payments");
        const payment = await collection.findOne({ _id: new ObjectId(paymentId) });

        if (!payment) {
            return res.status(404).json({ message: "Payment not found" });
        }

        // Verify SWIFT code
        if (payment.swiftCode !== swiftCode) {
            return res.status(400).json({ message: "SWIFT code mismatch" });
        }

        // Mark the payment as verified
        await collection.updateOne({ _id: new ObjectId(paymentId) }, { $set: { status: "Verified" } });

        res.status(200).json({ message: "Payment verified successfully" });
    } catch (error) {
        console.error("Payment verification error:", error);
        res.status(500).json({ message: "Payment verification failed" });
    }
});

export default router;
