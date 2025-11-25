<<<<<<< HEAD
console.log("Start of Backend Project");
=======
import dotenv from "dotenv";
import connectDB from "./db/db_connection.js";
import app from "./app.js"
const port = 3000;

dotenv.config({
  path: "./.env",
});

connectDB()
  .then(
    app.listen(port, () => {
      console.log(`Example app listening on port http://localhost:${port}`);
    }),
  )
  .catch((err) => {
    console.error("MongoDB connection error", err);
    process.exit(1);
  });
>>>>>>> 01052ce (message 1)
