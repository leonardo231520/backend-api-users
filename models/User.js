import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: "" },
  lastname: { type: String, default: "" },
  role: { type: String, enum: ["admin", "user"], default: "user" },
  lastLogin: { type: Date, default: Date.now },
  isOnline: { type: Boolean, default: false }, // 🟢 NUEVO campo de estado
});


const User = mongoose.model("User", userSchema);
export default User;
