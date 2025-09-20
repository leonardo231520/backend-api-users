import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Configuración de variables de entorno
dotenv.config();

// Inicializar Express
const app = express();
app.use(express.json());
app.use(cors());

// Conexión a MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB conectado"))
  .catch((err) => console.error("❌ Error MongoDB:", err));

// Esquema y modelo de User
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// Esquema y modelo de Sensor
const sensorSchema = new mongoose.Schema({
  flame: { type: Number, required: true },
  gas: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now },
});
const Sensor = mongoose.model("Sensor", sensorSchema);

// Esquema y modelo de Alert
const alertSchema = new mongoose.Schema({
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});
const Alert = mongoose.model("Alert", alertSchema);

// Rutas de Autenticación
// REGISTER
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "El usuario ya existe" });
    }

    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    res.status(500).json({ message: "Error en el registro", error });
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Buscar usuario
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Usuario no encontrado" });
    }

    // Comparar contraseña
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Contraseña incorrecta" });
    }

    // Generar token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({
      token,
      user: { id: user._id, email: user.email },
    });
  } catch (error) {
    res.status(500).json({ message: "Error en el login", error });
  }
});

// Rutas de API
// Obtener datos de sensores (última lectura)
app.get("/api/sensors", async (req, res) => {
  try {
    const latestSensor = await Sensor.findOne().sort({ timestamp: -1 });
    if (!latestSensor) {
      return res
        .status(404)
        .json({ message: "No se encontraron datos de sensores" });
    }
    res.json({ flame: latestSensor.flame, gas: latestSensor.gas });
  } catch (error) {
    res.status(500).json({ message: "Error al obtener datos de sensores", error });
  }
});

// Obtener lista de alertas
app.get("/api/alerts", async (req, res) => {
  try {
    const alerts = await Alert.find()
      .sort({ timestamp: -1 })
      .limit(50)
      .select("message timestamp");
    res.json(
      alerts.map((alert) => ({
        id: alert._id.toString(),
        message: alert.message,
        timestamp: alert.timestamp.toISOString(),
      }))
    );
  } catch (error) {
    res.status(500).json({ message: "Error al obtener alertas", error });
  }
});

// Ruta para agregar datos de sensores (para pruebas)
app.post("/api/sensors", async (req, res) => {
  try {
    const { flame, gas } = req.body;
    if (typeof flame !== "number" || typeof gas !== "number") {
      return res
        .status(400)
        .json({ message: "flame y gas deben ser números" });
    }
    const newSensor = new Sensor({ flame, gas });
    await newSensor.save();
    res.status(201).json({ message: "Datos de sensores guardados" });
  } catch (error) {
    res.status(500).json({ message: "Error al guardar datos de sensores", error });
  }
});

// Ruta para agregar alertas (para pruebas)
app.post("/api/alerts", async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ message: "El mensaje es requerido" });
    }
    const newAlert = new Alert({ message });
    await newAlert.save();
    res.status(201).json({ message: "Alerta guardada" });
  } catch (error) {
    res.status(500).json({ message: "Error al guardar alerta", error });
  }
});

// Iniciar el servidor
const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`)
);