"use strict";

const crypto = require("crypto");

// Protección CSRF con token por sesión (patrón "synchronizer token"), sin dependencias externas.
// Reemplaza a "csurf", que está archivado y arrastra una versión vulnerable de "cookie".
// - Genera un token aleatorio por sesión y lo expone a las plantillas como "csrftoken".
// - Exige ese token (campo "_csrf" o cabecera "x-csrf-token") en toda petición que no sea GET/HEAD/OPTIONS.
const SAFE_METHODS = ["GET", "HEAD", "OPTIONS"];

const csrfProtection = (req, res, next) => {
    if (!req.session) {
        return next(new Error("CSRF: se requiere sesión"));
    }
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    }
    res.locals.csrftoken = req.session.csrfToken;

    if (SAFE_METHODS.includes(req.method)) {
        return next();
    }

    const sent = (req.body && req.body._csrf) || req.headers["x-csrf-token"] || "";
    const expected = Buffer.from(req.session.csrfToken);
    const received = Buffer.from(String(sent));
    // Comparación en tiempo constante
    if (received.length === expected.length && crypto.timingSafeEqual(received, expected)) {
        return next();
    }
    const error = new Error("Invalid CSRF token");
    error.code = "EBADCSRFTOKEN";
    return next(error);
};

module.exports = csrfProtection;
