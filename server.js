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

// 👇 ESQUEMA DE USER ACTUALIZADO (AGREGAR CAMPOS NAME, LASTNAME Y LASTLOGIN)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: "" },
  lastname: { type: String, default: "" },
  lastLogin: { type: Date, default: Date.now } // 👈 NUEVO CAMPO
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

// 👇 MIDDLEWARE DE AUTENTICACIÓN
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ message: 'Token de acceso requerido' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido o expirado' });
    }
    req.user = user;
    next();
  });
};

// Rutas de Autenticación
// REGISTER ACTUALIZADO PARA ACEPTAR NAME Y LASTNAME
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name, lastname } = req.body;

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
      name: name || "",
      lastname: lastname || "",
      lastLogin: new Date() // 👈 INICIAR lastLogin
    });

    await newUser.save();

    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    res.status(500).json({ message: "Error en el registro", error });
  }
});

// LOGIN ACTUALIZADO PARA GUARDAR lastLogin
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

    // 👇 ACTUALIZAR ÚLTIMO LOGIN
    await User.findByIdAndUpdate(user._id, {
      lastLogin: new Date()
    });

    // Generar token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({
      token,
      user: { 
        id: user._id, 
        email: user.email,
        name: user.name,
        lastname: user.lastname
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Error en el login", error });
  }
});

// 👇 RUTA PARA OBTENER USUARIO ACTUAL
app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const userData = {
      id: user._id,
      email: user.email,
      name: user.name || "",
      lastname: user.lastname || ""
    };

    res.json(userData);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener usuario", error });
  }
});

// 👇 RUTA PARA OBTENER USUARIOS CONECTADOS (ÚLTIMOS 10 MINUTOS)
app.get("/api/users/connected", authenticateToken, async (req, res) => {
  try {
    // Obtener usuarios que hayan hecho login en los últimos 10 minutos
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    
    const connectedUsers = await User.find({
      lastLogin: { $gte: tenMinutesAgo },
      _id: { $ne: req.user.id } // Excluir al usuario actual
    }).select('-password').limit(20);

    res.json(connectedUsers.map(user => ({
      id: user._id,
      email: user.email,
      name: user.name,
      lastname: user.lastname,
      lastLogin: user.lastLogin,
      isOnline: true
    })));
  } catch (error) {
    res.status(500).json({ message: "Error al obtener usuarios conectados", error });
  }
});

// 👇 RUTA PARA ACTUALIZAR ÚLTIMO LOGIN (KEEP-ALIVE)
app.post("/api/users/keep-alive", authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, {
      lastLogin: new Date()
    });
    res.json({ message: "Estado actualizado", timestamp: new Date() });
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar estado", error });
  }
});

// 👇 RUTA OPCIONAL: ACTUALIZAR DATOS DEL USUARIO
app.put("/api/users/profile", authenticateToken, async (req, res) => {
  try {
    const { name, lastname } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { name, lastname },
      { new: true }
    ).select('-password');

    res.json({
      message: "Perfil actualizado exitosamente",
      user: updatedUser
    });
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar perfil", error });
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

// ✅ Nueva versión: devuelve lista de sensores recientes
app.get("/api/sensors", async (req, res) => {
  try {
    const sensors = await Sensor.find().sort({ timestamp: -1 }).limit(50);
    if (!sensors.length) {
      return res.status(404).json({ message: "No se encontraron datos de sensores" });
    }

    // Normalizamos para el frontend
    const formatted = sensors.map(s => ({
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
    res.status(500).json({ message: "Error al obtener datos de sensores", error });
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

// 👇 SCRIPT PARA ACTUALIZAR USUARIOS EXISTENTES (EJECUTAR UNA SOLA VEZ)
const updateExistingUsers = async () => {
  try {
    // Agregar campos name y lastname a usuarios existentes
    const resultName = await User.updateMany(
      { name: { $exists: false } },
      { $set: { name: "", lastname: "" } }
    );
    
    // Agregar campo lastLogin a usuarios existentes
    const resultLogin = await User.updateMany(
      { lastLogin: { $exists: false } },
      { $set: { lastLogin: new Date() } }
    );
    
    console.log(`✅ Usuarios actualizados - name/lastname: ${resultName.modifiedCount}`);
    console.log(`✅ Usuarios actualizados - lastLogin: ${resultLogin.modifiedCount}`);
  } catch (error) {
    console.error("❌ Error actualizando usuarios:", error);
  }
};

// Ejecutar al iniciar el servidor (opcional)
updateExistingUsers();