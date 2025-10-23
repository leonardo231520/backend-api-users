import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { Server } from "socket.io"; // AÑADIDO
import http from "http"; // AÑADIDO

dotenv.config();

// ==========================================
// INICIALIZAR EXPRESS
// ==========================================
const app = express();
app.use(express.json());
app.use(cors());

// ==========================================
// CONEXIÓN A MONGO
// ==========================================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch((err) => console.error("Error MongoDB:", err));

// ==========================================
// MODELOS
// ==========================================
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: "" },
  lastname: { type: String, default: "" },
  role: { type: String, enum: ["admin", "user"], default: "user" },
  lastLogin: { type: Date, default: Date.now },
  isOnline: { type: Boolean, default: false },
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
// MIDDLEWARES
// ==========================================
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader)
      return res.status(401).json({ message: "Token requerido" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Token inválido" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    await User.findByIdAndUpdate(decoded.id, { lastLogin: new Date() });

    next();
  } catch (err) {
    console.error("Error en authenticateToken:", err);
    return res.status(403).json({ message: "Token inválido o expirado" });
  }
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
// AUTENTICACIÓN
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
    if (!user) return res.status(400).json({ message: "Usuario no encontrado" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Contraseña incorrecta" });

    user.lastLogin = new Date();
    user.isOnline = true;
    await user.save();

    const token = jwt.sign(
      { id: user._id.toString(), role: user.role },
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

app.post("/auth/logout", authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { isOnline: false });
    res.json({ message: "Sesión cerrada correctamente" });
  } catch (error) {
    res.status(500).json({ message: "Error al cerrar sesión", error });
  }
});

// ==========================================
// USUARIOS
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

// ==========================================
// CAMBIO DE ROL
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
// SENSORES Y ALERTAS
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
      const alertMessage = `Nivel crítico: Gas ${gas} ppm, Flama ${flame}`;
      
      const newAlert = new Alert({ message: alertMessage, flame, gas });
      await newAlert.save();

      // DISPARAR ALERTA GLOBAL POR SENSOR
      if (!global.alarmActive) {
        global.alarmActive = true;
        io.emit("smoke-alert", {
          message: alertMessage,
          confidence: 1.0,
          type: "sensor",
          source: "hardware",
          timestamp: new Date().toISOString()
        });
        setTimeout(() => { global.alarmActive = false; }, 30000);
      }
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
// NUEVA RUTA: DISPARAR ALERTA GLOBAL
// ==========================================
app.post("/api/trigger-alarm", async (req, res) => {
  try {
    const { message, confidence = 0.9, type = "camera", source = "app" } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Falta mensaje" });
    }

    if (global.alarmActive) {
      return res.json({ success: true, message: "Alarma ya activa" });
    }

    global.alarmActive = true;
    console.log(`ALERTA GLOBAL: ${message} (${(confidence * 100).toFixed(1)}%)`);

    io.emit("smoke-alert", {
      message,
      confidence,
      type,
      source,
      timestamp: new Date().toISOString(),
      totalClients: io.engine.clientsCount
    });

    // Guardar en BD
    try {
      const newAlert = new Alert({
        message,
        gas: type === "sensor" ? 999 : 0,
        flame: type === "sensor" ? 999 : 0,
      });
      await newAlert.save();
    } catch (e) {}

    setTimeout(() => {
      global.alarmActive = false;
    }, 30000);

    res.json({ success: true, clients: io.engine.clientsCount });
  } catch (error) {
    console.error("Error en /api/trigger-alarm:", error);
    res.status(500).json({ error: "Error interno" });
  }
});

// ==========================================
// CHAT IA CONTRA INCENDIOS (Gemini)
// ==========================================
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Mensaje requerido" });

    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

    const prompt = `
Eres FireGuard IA, un asistente especializado en prevención y manejo de incendios.
Responde SIEMPRE en español con recomendaciones claras y seguras.
El usuario dice: "${message}"
`;

    const result = await model.generateContent(prompt);
    let respuesta = result.response.text().replace(/\*/g, "").trim();

    res.json({ reply: respuesta });
  } catch (error) {
    console.error("Error en /api/chat:", error);
    res.status(500).json({ error: "Error al procesar el mensaje" });
  }
});

// ==========================================
// VERIFICACIÓN AUTOMÁTICA DE INACTIVIDAD
// ==========================================
setInterval(async () => {
  try {
    const limiteInactividad = 30 * 60 * 1000;
    const ahora = new Date();

    const usuariosInactivos = await User.updateMany(
      { isOnline: true, lastLogin: { $lt: new Date(ahora - limiteInactividad) } },
      { $set: { isOnline: false } }
    );

    if (usuariosInactivos.modifiedCount > 0) {
      console.log(`${usuariosInactivos.modifiedCount} usuarios marcados como inactivos.`);
    }
  } catch (err) {
    console.error("Error al actualizar usuarios inactivos:", err);
  }
}, 10 * 60 * 1000);

// ==========================================
// SERVIDOR + SOCKET.IO
// ==========================================
const PORT = process.env.PORT || 4000;
const httpServer = http.createServer(app); // AÑADIDO

const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

let connectedClients = 0;
global.alarmActive = false; // AÑADIDO

io.on("connection", (socket) => {
  connectedClients++;
  console.log(`Dispositivo conectado: ${socket.id} (${connectedClients} total)`);

  if (global.alarmActive) {
    socket.emit("smoke-alert", { message: "ALERTA ACTIVA", confidence: 0.95 });
  }

  socket.on("disconnect", () => {
    connectedClients--;
    console.log(`Dispositivo desconectado: ${socket.id}`);
  });
});

httpServer.listen(PORT, () =>
  console.log(`Servidor corriendo en http://localhost:${PORT}`)
);