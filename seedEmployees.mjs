import db from "../BACKEND/db/conn.mjs";
import bcrypt from "bcrypt";

async function seedEmployees() {
    try {
        // Dummy employee data
        const employees = [
            {
                username: "John cena",
                password: "Password123",
            },
            {
                username: "Jack hill",
                password: "Password456",
            }
        ];

        // Hash passwords and prepare data for insertion
        const hashedEmployees = await Promise.all(employees.map(async (employee) => {
            const hashedPassword = await bcrypt.hash(employee.password, 10);
            return {
                username: employee.username,
                password: hashedPassword,
            };
        }));

        // Insert into the employees collection
        const collection = await db.collection("employees");
        await collection.insertMany(hashedEmployees);

        console.log("Dummy employees seeded successfully!");
    } catch (error) {
        console.error("Error seeding employees:", error);
    }
}

// Call the function to seed employees
seedEmployees().then(() => {
    process.exit(0);
});
