// Error handling middleware

const errorHandler = (err, req, res, next) => {

    "use strict";

    console.error(err.message);
    // La traza solo se registra fuera de producción
    if (process.env.NODE_ENV !== "production") {
        console.error(err.stack);
    }
    res.status(err.code === "EBADCSRFTOKEN" ? 403 : 500);
    res.render("error-template", {
        // No se expone el detalle interno al usuario en producción
        error: process.env.NODE_ENV === "production" ? "Internal Server Error" : err
    });
};

module.exports = { errorHandler };
