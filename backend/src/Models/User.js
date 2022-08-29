const mongoose = require("mongoose");


const UserSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true,
        minLength: 6
    },
    googleId: {
        type: String,
        required: false,
    }
})

module.exports = mongoose.model("user", UserSchema)

