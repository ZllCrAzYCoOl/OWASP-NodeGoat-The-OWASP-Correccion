/* The ProfileDAO must be constructed with a connected database object */
const crypto = require("crypto");
const config = require("../../config/config");

function ProfileDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof ProfileDAO)) {
        console.log("Warning: ProfileDAO constructor called without 'new' operator");
        return new ProfileDAO(db);
    }

    const users = db.collection("users");

    // Fix A6 (exposición de datos sensibles): SSN, fecha de nacimiento y datos bancarios se guardan cifrados
    // con AES-256-GCM (cifrado autenticado), IV aleatorio por cada valor y clave tomada de CRYPTO_KEY.
    const key = crypto.createHash("sha256").update(String(config.cryptoKey)).digest(); // 32 bytes

    const encrypt = (plainText) => {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
        const encrypted = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
        return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString("hex")).join(":");
    };

    const decrypt = (payload) => {
        try {
            const [iv, tag, encrypted] = String(payload).split(":").map((part) => Buffer.from(part, "hex"));
            const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
            decipher.setAuthTag(tag);
            return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
        } catch (error) {
            return "";
        }
    };

    this.updateUser = (userId, firstName, lastName, ssn, dob, address, bankAcc, bankRouting, callback) => {

        // Create user document
        const user = {};
        if (firstName) {
            user.firstName = firstName;
        }
        if (lastName) {
            user.lastName = lastName;
        }
        if (address) {
            user.address = address;
        }
        if (bankAcc) {
            user.bankAcc = bankAcc;
        }
        if (bankRouting) {
            user.bankRouting = bankRouting;
        }
        if (ssn) {
            user.ssn = ssn;
        }
        if (dob) {
            user.dob = dob;
        }

        const stored = { ...user };
        ["ssn", "dob", "bankAcc", "bankRouting"].forEach((field) => {
            if (stored[field]) {
                stored[field] = encrypt(stored[field]);
            }
        });

        users.update({
                _id: parseInt(userId)
            }, {
                $set: stored
            },
            err => {
                if (!err) {
                    console.log("Updated user profile");
                    return callback(null, user);
                }

                return callback(err, null);
            }
        );
    };

    this.getByUserId = (userId, callback) => {
        users.findOne({
                _id: parseInt(userId)
            },
            (err, user) => {
                if (err) return callback(err, null);
                if (!user) return callback(new Error("User not found"), null);
                ["ssn", "dob", "bankAcc", "bankRouting"].forEach((field) => {
                    user[field] = user[field] ? decrypt(user[field]) : "";
                });

                callback(null, user);
            }
        );
    };
}

module.exports = { ProfileDAO };
