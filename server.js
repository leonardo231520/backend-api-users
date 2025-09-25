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

// 👇 ESQUEMA DE USER ACTUALIZADO (AGREGAR CAMPOS NAME Y LASTNAME)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: "" },     // 👈 NUEVO CAMPO
  lastname: { type: String, default: "" }  // 👈 NUEVO CAMPO
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

// 👇 MIDDLEWARE DE AUTENTICACIÓN (AGREGAR ESTO)
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
    const { email, password, name, lastname } = req.body; // 👈 AGREGAR NAME Y LASTNAME

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
      name: name || "",        // 👈 GUARDAR NAME
      lastname: lastname || "" // 👈 GUARDAR LASTNAME
    });

    await newUser.save();

    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    res.status(500).json({ message: "Error en el registro", error });
  }
});

// LOGIN ACTUALIZADO PARA DEVOLVER NAME Y LASTNAME
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
      user: { 
        id: user._id, 
        email: user.email,
        name: user.name,        // 👈 DEVOLVER NAME REAL
        lastname: user.lastname // 👈 DEVOLVER LASTNAME REAL
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Error en el login", error });
  }
});

// 👇 RUTA PARA OBTENER USUARIO ACTUAL (MEJORADA)
app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    // 👇 FILTRAR Y DEVOLVER SOLO LOS DATOS REALES DE LA BD
    const userData = {
      id: user._id,
      email: user.email,
      // Si name existe en la BD, usarlo; si no, dejar string vacío
      name: user.name || "",
      // Si lastname existe en la BD, usarlo; si no, dejar string vacío
      lastname: user.lastname || ""
    };

    // 👇 VERIFICAR SI HAY DATOS EN LA BD
    console.log("📊 Datos del usuario desde BD:", {
      email: user.email,
      name: user.name,
      lastname: user.lastname,
      tieneNombre: !!user.name,
      tieneApellido: !!user.lastname
    });

    res.json(userData);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener usuario", error });
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

// 👇 SCRIPT PARA ACTUALIZAR USUARIOS EXISTENTES (EJECUTAR UNA SOLA VEZ)
const updateExistingUsers = async () => {
  try {
    const result = await User.updateMany(
      { name: { $exists: false } }, // Solo usuarios sin campo name
      { $set: { name: "", lastname: "" } } // Agregar campos vacíos
    );
    console.log(`✅ Usuarios actualizados: ${result.modifiedCount}`);
  } catch (error) {
    console.error("❌ Error actualizando usuarios:", error);
  }
};

// Ejecutar al iniciar el servidor (opcional)
updateExistingUsers();