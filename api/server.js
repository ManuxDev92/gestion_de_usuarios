// Server.js 
require('dotenv').config(); 

const express = require('express'); 
const mongoose = require('mongoose'); 
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 
const helmet = require('helmet');

if (!process.env.JWT_SECRET) {
    console.error('❌ Falta JWT_SECRET en .env');
    process.exit(1); 
}


// ------- App y middlewares --------
const app = express();
// Habilita parseo de JSON en el body (req.body)
app.use(express.json()); 
app.use(cors( {
    origin: ['http://localhost:5500', 'http://127.0.0.1:5500'], // ajusta si usas otro puerto/origen
    credentials: false
})); 

function auth (req, res, next) {
    try {
        const hdr = req.headers.authorization || ''; 
        const [type, token] = hdr.split(' '); 
        if (type !== 'Bearer' || !token) throw new UserError('No authorized.', 401); 

        const payload = jwt.verify(token, process.env.JWT_SECRET); 
        req.userId = payload.sub; 
        next(); 
    }   catch (_e) {
        next(new UserError('No authorized.', 401)); 
    }
}

// Ejemplo: perfil de usuario autrnticado: 
app.get('/me', auth, async (req, res, next) => {
    try {
        const me = await User.findById(req.userId).lean(); 
        if (!me) throw new UserError('User not found.', 404); 
        res.json({ id: me._id, name: me.name, email: me.email, createdAt: me.createdAt }); 
    }   catch (err) {
        next (err);  
    }
});


// ------- Conexion a MongoDB --------

// Se extrae la URI de Mongo y el puerto desde las env vars (PORT con default 3000)
const { MONGODB_URI, PORT = 3000} = process.env; 
// Inicia conexion a MongoDB. autoIndex crear indices (como el unique de email)
mongoose
    .connect(MONGODB_URI, {autoIndex: true})
    .then(() => console.log('✅ Coneccted to MongoDB'))
    .catch((err) => {
        console.error('❌ Error connecting to MongoDB:', err.message); 
        // Si no se conecta, salimos del proceso para no dejar el server a media 
        process.exit(1);
    });

// ---------- Definimos los errores ---------

// Error personalizado para devolver HTTP status y mesajes consistentes
class UserError extends Error {
    constructor(message, status = 400) {
        super(message); 
        this.name = 'UserError'; 
        this.status = status; // 404, 400 y asi... 
    }
}

// ------- Helpers -------


// Email básico: algo@dominio.tld
function isValidEmail(email) {
    return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidUsername(u) {
    //letras, numero, punto guion entre 3-20 caracteres 
    return /^[a-zA-Z0-9._-]{3,20}$/.test(u);
}


function assertUsername(u) {
    if (typeof u !== 'string' || !isValidUsername(u)) {
        throw new UserError('Username should be more than 3-20 characters (letters, numbers, ".", "_" o "-").', 400); 
    }
}

// Valida que un :id sea un ObjectId valido de Mongo, si no lanza 400
function assertObjectID(id) {
    if (!mongoose.Types.ObjectId.isValid(id)) {
        throw new UserError('Invalid ID. Should a valid ObjectId.', 400); 
    }
}

function assertPassword(pwd) {
    if (typeof pwd !== 'string' || pwd.length < 6) {
        throw new UserError('The password must have at least 6 characters.', 400)
    }
}

// Valida/normaliza el body de usuario. 
// partial = false -> creacion (name y email obligatorios)
// partial = true -> actualizacion (solo valida lo que venga)
function validateUserPayload(payload = {}, { partial = false } = {}) {
    const out = {}; 

    // name: que es requerido en la creacion o si viene en actualizacion
    if (!partial || payload.name !== undefined) {
        if (typeof payload.name !== 'string' || payload.name.trim().length < 2) {
            throw new UserError('The name must have at least 2 characters.', 400); 
        }
        out.name = payload.name.trim(); // esto normaliza espacios
    }

    // email: requerido para creacion o si viene en actualizacion 
    if (!partial || payload.email !== undefined) {
        if (typeof payload.email !== 'string' || !isValidEmail(payload.email)) {
            throw new UserError('Email must be in a valid format.', 400); 
        }
        out.email = payload.email.toLowerCase(); // nromaliza a minuscula 
    }

    // En creacion, exige ambos si no llegaron
    if (!partial) {
        if (out.name === undefined) throw new UserError('Name is required', 400); 
        if (out.email === undefined) throw new UserError('Email is required. ', 400); 
    }
    return out; // devuelve solo campos validado o normalizados. 
}

// -------  Esquema y Modelo ------

// Define el esquema del documento "User" en Mongo. 
const userSchema = new mongoose.Schema(
    {
        name: { type: String, required: true, minlength: 2, trim: true },
        username: { type: String, required: true, trim: true, lowercase: true, unique: true},
        email: { type: String, required: true, lowercase: true, trim: true, unique: true }, 
        passwordHash: { type: String, required: true, select: false},
        createdAt: { type: Date, default: Date.now }, // se setea automaticamente 
    }, 
    { versionKey: false } // oculta __v que es el control de version de mongoose 
); 

// Crea un indice unico por email 
userSchema.index({ email: 1 }, { unique: true}); 
userSchema.index({ username: 1 }, { unique: true }); 

// Crea el modelo User a partir del esquema
const User = mongoose.model('User', userSchema); 


// Logger simple: imprime metodo, URL, status y tiempo de respuesta
app.use((req, res, next) => {
    const started = Date.now(); 
    res.on('finish', () => {
        const ms = Date.now() - started; 
        console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
    });
    next(); 
});

// ---------- Health ----------

// Endpoint para verificar que el server esta good
app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', uptime: process.uptime() }); 
}); 


// ----- Listar (paginado, orden por createdAt DESC) ---------
app.get('/users', async (req, res, next) => {
    try {
        // Lee y sanea limit/offset de la query string
        let { limit = '10', offset = '0' } = req.query; 
        limit = parseInt(limit, 10); 
        offset = parseInt(offset, 10); 
        if (Number.isNaN(limit) || limit < 1 || limit > 100) limit = 10;
        if (Number.isNaN(offset) || offset < 0 ) offset = 0;
        if (offset > 1e6) offset = 1e6; // límite defensivo

        // Ejecuta en paralelo: datos paginados + total de documentos
        const [data, total] = await Promise.all([
            User.find().sort({ createdAt: -1 }).skip(offset).limit(limit).lean(), // -lean() devuelve objetos JS "planos" (mas rapido)
            User.countDocuments(),
        ]); 

        // Respuesta con data y metadatos de paginacion
        res.json({ data, meta: { total, limit, offset } }); 
    }   catch (err) {
        next(err); // delega al manejador de errores
    }
}); 

// ----- Obtener por ID ------
app.get('/users/:id', async(req, res, next) => {
    try {
        assertObjectID(req.params.id); // valida el id
        const user = await User.findById(req.params.id).lean(); 
        if (!user) throw new UserError('User not found.', 404); 
        res.json(user); 
    }   catch (err) {
        next(err);
    }
});


// ------- AUTH --------------------------------

// Registro: reutiliza el validador y crea el user 
app.post('/auth/register', async (req, res, next) => {
    try {
        const { username, name, email, password } = req.body || {}; 
        // exige Username 
        assertUsername(username); 
        // exige password
        assertPassword(password); 
        // Reutiliza el validador (name/email)
        const payload = validateUserPayload(
            { name, email},
            { partial: false }
        ); 

        const passwordHash = await bcrypt.hash(password, 10); 

        const created = await User.create({ 
            ...payload, 
            username: username.toLowerCase().trim(),
            passwordHash }); 

        res.status(201).json({ 
            id: created._id, 
            name: created.name,
            username: created.username, 
            email: created.email 
        });

    }   catch (err) {
        //Duplicado claros por indice unico
        if (err && err.code === 11000) {
            if (err.keyPattern?.email) return next(new UserError('Email is already registered.', 400)); 
            if (err.keyPattern?.username) return next(new UserError('Username is already registered', 400)); 
            return next(new UserError('Data duplicated.', 400)); 
        }
        if (err.name === 'ValidationError') {
            const msg = Object.values(err.errors).map(e => e.message).join('; '); 
            return next(new UserError(msg, 400)); 
        }
        next(err); 
    }
}); 

// ---------- LOGIN -------------------
app.post('/auth/login', async (req, res, next) => {
    try {
        // Indentifier puede ser email o username
        const { identifier, password } = req.body || {}; 
        if (typeof identifier !== 'string' || identifier.trim().length < 2) {
            throw new UserError('Username or email not valid', 400); 
        }
        assertPassword(password); 

        let query = {}; 
        if (isValidEmail(identifier)) {
            query = { email: identifier.toLowerCase( )}; 
        }   else {
            query = { username: identifier.trim() }; 
        }

        // Trae el hash 
        const user = await User.findOne(query).select('+passwordHash').lean(); 
        if (!user) throw new UserError('Invalid credentials', 401); 

        const ok = await bcrypt.compare(password, user.passwordHash); 
        if (!ok) throw new UserError('Invalid credentials', 401); 

        const token = jwt.sign(
            { sub: user._id.toString(), name: user.name, email: user.email, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES || '1h' }
        );
        
        // No exponer el passwordHash
        const { passwordHash, ...safeUser } = user;
        res.json({ token, user: safeUser });  

    }   catch (err) {
        next(err); 
    }
}); 


// --------- Actualiza de forma parcial --------
app.put('/users/:id', async (req, res, next ) => {
    try {
        assertObjectID(req.params.id); // se valida el ID 
        // Valida o nromaliza solo los campos que lleguen
        const updates = validateUserPayload(req.body || {}, { partial: true }); 

        // findByIdAndUpdate actualiza y devuelve el doc nuevo (new: true)
        // runValidators aplica validaciones del schema en updates
        const updated = await User.findByIdAndUpdate(
            req.params.id,
            { $set: updates },
            { new: true, runValidators: true, context: 'query' }
        ).lean(); 

        if (!updated) throw new UserError('User not found.', 404);
        res.json(updated); 
    }   catch (err) {
        if (err && err.code === 11000) {
            return next(new UserError('Email is already registered.', 400)); 
        }
        if (err.name === 'ValidationError') {
            const msg = Object.values(err.errors).map(e => e.message).join('; '); 
            return next(new UserError(msg, 400)); 
        }
        next(err); 
    }
});

// --------- Eliminar -----------

app.delete('/users/:id', async (req, res, next) => {
    try {
        assertObjectID(req.params.id); // valida el id 
        const deleted = await User.findByIdAndDelete(req.params.id).lean(); 
        if (!deleted) throw new UserError('User not found.', 404); 
        res.json({ deleted }); 
    }   catch (err) {
        next (err);
    }
}); 



// ------- Manbejador de errores -----------

// Captura cualquier throw/next(err) y responde en JSON con status correcto 
app.use((err, _req, res, _next) => {
    console.log(err); 
    const status = err.status || 500; 
    res.status(status).json({ error: err.message || 'Internal Server Error' }); 
}); 

// ---------- Arranque -----------

// Levanta el servidor en el puerto PORT 
app.listen(PORT, () => {
    console.log(`API running on http://localhost:${PORT}`); 
}); 

