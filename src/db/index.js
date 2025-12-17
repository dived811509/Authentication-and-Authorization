import mongoose from "mongoose";
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅Mongodb connected");
  } catch (error) {
    console.log("❌mongodb connection error", error);
    process.exit(1);
  }
};
export default connectDB;
