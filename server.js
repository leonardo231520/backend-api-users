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
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: "" },
  lastname: { type: String, default: "" },
  role: { type: String, enum: ["admin", "user"], default: "user" },
  lastLogin: { type: Date, default: Date.now },
  isOnline: { type: Boolean, default: false }, // ✅ Estado online
});
const User = mongoose.model("User", userSchema);

const sensorSchema = new mongoose.Schema({
  flame: { type: Number, required: true },
  gas: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now },
});
const Sensor = mongoose.model("Sensor", sensorSchema);

const alertSchema = new mongoose.Schema({
  message: { type: String, required: true },
  flame: { type: Number, default: 0 },
  gas: { type: Number, default: 0 },
  timestamp: { type: Date, default: Date.now },
});
const Alert = mongoose.model("Alert", alertSchema);

const systemStateSchema = new mongoose.Schema({
  active: { type: Boolean, default: false },
  updatedAt: { type: Date, default: Date.now },
});
const SystemState = mongoose.model("SystemState", systemStateSchema);

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
    return res
      .status(403)
      .json({ message: "Acceso denegado: solo administradores" });
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
    if (existingUser)
      return res.status(400).json({ message: "El usuario ya existe" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
      name: name || "",
      lastname: lastname || "",
      role: role || "user",
      lastLogin: new Date(),
      isOnline: false,
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
    if (!user)
      return res.status(400).json({ message: "Usuario no encontrado" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Contraseña incorrecta" });

    // ✅ Marcar usuario como activo
    await User.findByIdAndUpdate(user._id, {
      lastLogin: new Date(),
      isOnline: true,
    });

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
        isOnline: true,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Error en el login", error });
  }
});

// ✅ Cierre de sesión
app.post("/auth/logout", authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { isOnline: false });
    res.json({ message: "Sesión cerrada correctamente" });
  } catch (error) {
    res.status(500).json({ message: "Error al cerrar sesión", error });
  }
});

// ==========================================
// 👤 USUARIOS Y ESTADOS
// ==========================================
app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user)
      return res.status(404).json({ message: "Usuario no encontrado" });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener usuario", error });
  }
});

app.get("/api/users/connected", authenticateToken, async (req, res) => {
  try {
    const connectedUsers = await User.find({ isOnline: true })
      .select("-password")
      .limit(20);
    res.json(connectedUsers);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error al obtener usuarios conectados", error });
  }
});

app.post("/api/users/keep-alive", authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, {
      lastLogin: new Date(),
      isOnline: true,
    });
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
// 🆕 CAMBIO DE ROL
// ==========================================
app.put(
  "/api/users/change-role/:id",
  authenticateToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { role } = req.body;
      if (!["admin", "user"].includes(role))
        return res.status(400).json({ message: "Rol inválido" });

      if (req.user.id === req.params.id)
        return res
          .status(403)
          .json({ message: "No puedes cambiar tu propio rol" });

      const userToUpdate = await User.findById(req.params.id);
      if (!userToUpdate)
        return res.status(404).json({ message: "Usuario no encontrado" });

      userToUpdate.role = role;
      await userToUpdate.save();

      res.json({
        message: `Rol cambiado correctamente a ${role}`,
        user: {
          id: userToUpdate._id,
          email: userToUpdate.email,
          name: userToUpdate.name,
          role: userToUpdate.role,
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Error al cambiar rol", error });
    }
  }
);

// ==========================================
// 📡 SENSORES Y ALERTAS
// ==========================================
app.get("/api/sensors", async (req, res) => {
  try {
    const sensors = await Sensor.find().sort({ timestamp: -1 }).limit(50);
    if (!sensors.length)
      return res
        .status(404)
        .json({ message: "No se encontraron datos de sensores" });

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

app.post("/api/sensors", async (req, res) => {
  try {
    const { flame, gas } = req.body;
    if (typeof flame !== "number" || typeof gas !== "number")
      return res
        .status(400)
        .json({ message: "flame y gas deben ser números" });

    const newSensor = new Sensor({ flame, gas });
    await newSensor.save();

    if (gas > 70 || flame > 65) {
      const newAlert = new Alert({
        message: "⚠️ Nivel de peligro detectado",
        flame,
        gas,
      });
      await newAlert.save();
    }

    res.status(201).json({ message: "Sensor guardado correctamente" });
  } catch (error) {
    res.status(500).json({ message: "Error al guardar sensor", error });
  }
});

app.get("/api/alerts", async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ timestamp: -1 });
    res.json(alerts);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener alertas", error });
  }
});

// ==========================================
// 🧭 RUTAS ADMIN
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
// 📊 DASHBOARD
// ==========================================
app.get("/api/dashboard/summary", async (req, res) => {
  try {
    const totalSensores = await Sensor.countDocuments();
    const totalAlertas = await Alert.countDocuments();
    const ultimo = await Sensor.findOne().sort({ timestamp: -1 });
    const promedioFlame = await Sensor.aggregate([
      { $group: { _id: null, avg: { $avg: "$flame" } } },
    ]);
    const promedioGas = await Sensor.aggregate([
      { $group: { _id: null, avg: { $avg: "$gas" } } },
    ]);

    let state = await SystemState.findOne();
    if (!state) {
      state = new SystemState({ active: true });
    } else {
      state.active = true;
      state.updatedAt = new Date();
    }
    await state.save();

    res.json({
      totalSensores,
      totalAlertas,
      ultimo: ultimo || null,
      promedioFlame: promedioFlame[0]?.avg || 0,
      promedioGas: promedioGas[0]?.avg || 0,
    });
  } catch (error) {
    res.status(500).json({ message: "Error al obtener resumen", error });
  }
});

// ==========================================
// 🚀 SERVIDOR
// ==========================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`)
);

// ==========================================
// ⚙️ ACTUALIZAR USUARIOS EXISTENTES
// ==========================================
const updateExistingUsers = async () => {
  try {
    await User.updateMany({ role: { $exists: false } }, { $set: { role: "user" } });
    await User.updateMany(
      { lastLogin: { $exists: false } },
      { $set: { lastLogin: new Date() } }
    );
    await User.updateMany(
      { isOnline: { $exists: false } },
      { $set: { isOnline: false } }
    );
    console.log("✅ Usuarios actualizados correctamente");
  } catch (error) {
    console.error("❌ Error actualizando usuarios:", error);
  }
};
updateExistingUsers();
