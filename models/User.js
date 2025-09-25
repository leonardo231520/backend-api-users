import mongoose from "mongoose";

// 👇 ACTUALIZA EL SCHEMA DE USER (agrega lastLogin)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: "" },
  lastname: { type: String, default: "" },
  lastLogin: { type: Date, default: Date.now } // 👈 NUEVO CAMPO
});

const User = mongoose.model("User", userSchema);
export default User;
