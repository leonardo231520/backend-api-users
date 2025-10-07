import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

// Inicializar Express
const app = express();
app.use(express.json());
app.use(cors());

// ==========================================
// 🔗 CONEXIÓN A MONGO
// ==========================================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB conectado"))
  .catch((err) => console.error("❌ Error MongoDB:", err));

// ==========================================
// 🧱 MODELOS
// ==========================================

// 🧍 USUARIOS (ahora con ROLE)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: "" },
  lastname: { type: String, default: "" },
  role: { type: String, enum: ["admin", "user"], default: "user" },
  lastLogin: { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// 🔥 SENSORES
const sensorSchema = new mongoose.Schema({
  flame: { type: Number, required: true },
  gas: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now },
});
const Sensor = mongoose.model("Sensor", sensorSchema);

// 🚨 ALERTAS (actualizado con gas, flame y timestamp)
const alertSchema = new mongoose.Schema({
  message: { type: String, required: true },
  flame: { type: Number, default: 0 },
  gas: { type: Number, default: 0 },
  timestamp: { type: Date, default: Date.now },
});
const Alert = mongoose.model("Alert", alertSchema);

// ==========================================
// 🧩 MIDDLEWARES
// ==========================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token requerido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido" });
    req.user = user;
    next();
  });
};

const verifyAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Acceso denegado: solo administradores" });
  }
  next();
};

// ==========================================
// 🔐 AUTENTICACIÓN
// ==========================================
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name, lastname, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "El usuario ya existe" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
      name: name || "",
      lastname: lastname || "",
      role: role || "user",
      lastLogin: new Date(),
    });

    await newUser.save();
    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    res.status(500).json({ message: "Error en el registro", error });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Usuario no encontrado" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Contraseña incorrecta" });

    await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        lastname: user.lastname,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Error en el login", error });
  }
});

app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener usuario", error });
  }
});

app.get("/api/users/connected", authenticateToken, async (req, res) => {
  try {
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const connectedUsers = await User.find({
      lastLogin: { $gte: tenMinutesAgo },
      _id: { $ne: req.user.id },
    })
      .select("-password")
      .limit(20);

    res.json(
      connectedUsers.map((user) => ({
        id: user._id,
        email: user.email,
        name: user.name,
        lastname: user.lastname,
        lastLogin: user.lastLogin,
        role: user.role,
        isOnline: true,
      }))
    );
  } catch (error) {
    res.status(500).json({ message: "Error al obtener usuarios conectados", error });
  }
});

app.post("/api/users/keep-alive", authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { lastLogin: new Date() });
    res.json({ message: "Estado actualizado", timestamp: new Date() });
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar estado", error });
  }
});

app.put("/api/users/profile", authenticateToken, async (req, res) => {
  try {
    const { name, lastname } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { name, lastname },
      { new: true }
    ).select("-password");

    res.json({ message: "Perfil actualizado", user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar perfil", error });
  }
});

// ==========================================
// 📡 RUTAS DE SENSORES Y ALERTAS
// ==========================================

// 🔹 Obtener últimos sensores
app.get("/api/sensors", async (req, res) => {
  try {
    const sensors = await Sensor.find().sort({ timestamp: -1 }).limit(50);
    if (!sensors.length)
      return res.status(404).json({ message: "No se encontraron datos de sensores" });

    const formatted = sensors.map((s) => ({
      id: s._id.toString(),
      flame: s.flame,
      gas: s.gas,
      timestamp: s.timestamp,
      status:
        s.gas > 70 || s.flame > 65
          ? "danger"
          : s.gas > 40 || s.flame > 40
          ? "warning"
          : "normal",
    }));

    res.json(formatted);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener sensores", error });
  }
});

// 🔹 Agregar sensor con generación automática de alertas
app.post("/api/sensors", async (req, res) => {
  try {
    const { flame, gas } = req.body;
    if (typeof flame !== "number" || typeof gas !== "number") {
      return res.status(400).json({ message: "flame y gas deben ser números" });
    }

    const newSensor = new Sensor({ flame, gas });
    await newSensor.save();

    // Condición de alerta
    if (gas > 70 || flame > 65) {
      const alertMessage = "⚠️ Nivel de peligro detectado";
      const newAlert = new Alert({ message: alertMessage, flame, gas });
      await newAlert.save();
    }

    res.status(201).json({ message: "Sensor guardado correctamente" });
  } catch (error) {
    res.status(500).json({ message: "Error al guardar sensor", error });
  }
});

// 🔹 Agregar alerta manual (opcional)
app.post("/api/alerts", async (req, res) => {
  try {
    const { message, flame, gas } = req.body;
    if (!message) return res.status(400).json({ message: "El mensaje es requerido" });

    const newAlert = new Alert({ message, flame, gas });
    await newAlert.save();
    res.status(201).json({ message: "Alerta guardada", alert: newAlert });
  } catch (error) {
    res.status(500).json({ message: "Error al guardar alerta", error });
  }
});

// ==========================================
// 🧭 RUTAS ADMINISTRADORAS
// ==========================================
app.get("/api/admin/users", authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error al listar usuarios", error });
  }
});

// ==========================================
// 🚀 SERVIDOR
// ==========================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`));

// ==========================================
// ⚙️ SCRIPT PARA ACTUALIZAR USUARIOS EXISTENTES
// ==========================================
const updateExistingUsers = async () => {
  try {
    const resultRole = await User.updateMany(
      { role: { $exists: false } },
      { $set: { role: "user" } }
    );
    const resultLogin = await User.updateMany(
      { lastLogin: { $exists: false } },
      { $set: { lastLogin: new Date() } }
    );

    console.log(`✅ Usuarios actualizados - role: ${resultRole.modifiedCount}`);
    console.log(`✅ Usuarios actualizados - lastLogin: ${resultLogin.modifiedCount}`);
  } catch (error) {
    console.error("❌ Error actualizando usuarios:", error);
  }
};
updateExistingUsers();
