const path = require("path");
const util = require("util");

const finalEnv = process.env.NODE_ENV || "development";

const allConf = require(path.resolve(__dirname + "/../config/env/all.js"));
const envConf = require(path.resolve(__dirname + "/../config/env/" + finalEnv.toLowerCase() + ".js")) || {};

const config = { ...allConf, ...envConf };

// El registro nunca debe mostrar secretos ni la cadena de conexión (contiene la contraseña de la base)
const SENSITIVE = ["cookieSecret", "cryptoKey", "db", "zapApiKey"];
const safeConfig = Object.fromEntries(
    Object.entries(config).map(([key, value]) => [key, SENSITIVE.includes(key) ? "[OCULTO]" : value])
);

console.log(`Current Config:`);
console.log(util.inspect(safeConfig, false, null));

module.exports = config;
