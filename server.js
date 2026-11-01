"use strict";

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
const csrf = require("./app/middleware/csrf");
const nunjucks = require("nunjucks"); // Motor de plantillas mantenido (compatible con la sintaxis usada)
const MongoClient = require("mongodb").MongoClient; // Driver for connecting to MongoDB
const http = require("http");
const marked = require("marked");
const app = express(); // Web framework to handle routing requests
const routes = require("./app/routes");
const { port, db, cookieSecret, cookieSecure, environmentalScripts } = require("./config/config"); // Application config properties

MongoClient.connect(db, { useUnifiedTopology: true }, (err, client) => {
    if (err) {
        console.log("Error: DB: connect");
        // Se registra solo el mensaje: el objeto de error puede incluir la cadena de conexión
        console.log(err.message);
        process.exit(1);
    }
    console.log(`Connected to the database`);
    const database = client.db();

    // Fix A5 (configuración insegura): sin cabecera x-powered-by y con cabeceras de seguridad
    app.disable("x-powered-by");
    app.use((req, res, next) => {
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Referrer-Policy", "no-referrer");
        const scriptSrc = environmentalScripts.length ? "'self' 'unsafe-inline'" : "'self'";
        res.setHeader("Content-Security-Policy",
            `default-src 'self'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; ` +
            "font-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'");
        if (cookieSecure) {
            res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }
        next();
    });

    app.use(favicon(__dirname + "/app/assets/favicon.ico"));

    // Los recursos estáticos se declaran antes de la sesión
    app.use(express.static(`${__dirname}/app/assets`));

    // Express middleware to populate "req.body" so we can access POST variables
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
        // Mandatory in Express v4
        extended: false
    }));

    // Fix A5 y A3: nombre de cookie genérico, HttpOnly, SameSite, caducidad y sin sesiones vacías
    app.use(session({
        secret: cookieSecret,
        name: "sessionId",
        saveUninitialized: false,
        resave: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: cookieSecure,
            maxAge: 30 * 60 * 1000
        }
    }));

    // Fix A8 (CSRF): token por sesión validado en cada petición que modifica datos
    app.use(csrf);
    app.use((req, res, next) => {
        res.setHeader("Cache-Control", "no-store");
        next();
    });

    // Motor de plantillas Nunjucks con escape automático activado (Fix A3, XSS).
    // Sustituye a "swig", que no tiene mantenimiento y tiene vulnerabilidades sin parche.
    app.set("view engine", "html");
    nunjucks.configure(`${__dirname}/app/views`, {
        autoescape: true,
        express: app
    });

    // Fix A9: marked con sanitización activada
    marked.setOptions({
        sanitize: true
    });
    app.locals.marked = marked;

    // Application routes
    routes(app, database);

    // HTTP: en AWS el tráfico llega por el puerto 4000 limitado por el grupo de seguridad.
    // Para HTTPS, termina TLS en un balanceador y activa COOKIE_SECURE=true.
    http.createServer(app).listen(port, () => {
        console.log(`Express http server listening on port ${port}`);
    });

});
