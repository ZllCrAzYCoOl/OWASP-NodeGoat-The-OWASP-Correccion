// Configuración por defecto. Los secretos NUNCA se escriben en el código: llegan por variables de entorno.
const crypto = require("crypto");

const port = process.env.PORT || 4000;
const db = process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat";
const isProduction = process.env.NODE_ENV === "production";

const requiredSecret = (name) => {
    const value = process.env[name];
    if (value) {
        return value;
    }
    if (isProduction) {
        throw new Error(`Falta la variable de entorno obligatoria ${name}`);
    }
    // Solo desarrollo y pruebas: valor aleatorio efímero (cambia en cada arranque)
    return crypto.randomBytes(32).toString("hex");
};

module.exports = {
    port,
    db,
    cookieSecret: requiredSecret("COOKIE_SECRET"),
    cryptoKey: requiredSecret("CRYPTO_KEY"),
    // Activar solo cuando la aplicación se sirva por HTTPS (la cookie de sesión viaja únicamente cifrada)
    cookieSecure: process.env.COOKIE_SECURE === "true",
    hostName: process.env.HOST_NAME || "localhost",
    environmentalScripts: []
};
