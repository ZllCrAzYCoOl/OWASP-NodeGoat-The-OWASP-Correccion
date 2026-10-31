const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

// Fix SSRF: la URL base la fija el servidor; el usuario solo aporta el símbolo, que se valida
const BASE_URL = "https://finance.yahoo.com/quote/";
const SYMBOL_RE = /^[A-Za-z0-9.\-^=]{1,12}$/;

const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
}[c]));

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            const symbol = String(req.query.symbol);
            if (!SYMBOL_RE.test(symbol)) {
                return res.status(400).send("Invalid stock symbol");
            }
            const options = { open_timeout: 5000, response_timeout: 5000, follow_max: 0 };
            return needle.get(BASE_URL + encodeURIComponent(symbol), options, (error, newResponse, body) => {
                res.writeHead(200, {
                    "Content-Type": "text/html; charset=utf-8"
                });
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (!error && newResponse.statusCode === 200 && body) {
                    // Fix XSS reflejado: el contenido remoto se escapa antes de mostrarse
                    res.write("<pre>" + escapeHtml(body) + "</pre>");
                }
                return res.end();
            });
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;
