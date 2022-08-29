const { Router } = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");
require('dotenv').config()
const userModel = require('../models/User')

const authRoute = Router();

const CLIENT_URL = "http://localhost:3000";

authRoute.get("/login/success", async (req, res) => {
    let user = req.user;

    if (user) {
        const { username, email } = req.user

        const exist = await userModel.findOne({ email })

        if (!exist) {
            return res.status(401).send({
                error: 'user dont have a account please register',
            })
        }

        const refreshToken = jwt.sign(
            { username: exist.username, email },
            process.env.JWTSECRET,
            {
                expiresIn: '7d',
            },
        )
        const accessToken = jwt.sign(
            { username: exist.username, email },
            process.env.JWTSECRET,
            {
                expiresIn: '15m',
            },
        )

        res.cookie('refreshToken', refreshToken)
        res.cookie('accessToken', accessToken)

        // res.send({ username: exist.username, email })
        res.redirect(CLIENT_URL)
    }
});

authRoute.get("/login/failed", (req, res) => {
    res.status(401).json({
        success: false,
        message: "faliure",
    });
});

authRoute.get(
    "/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

authRoute.get(
    "/google/callback",
    passport.authenticate("google", {
        successRedirect: "/auth/login/success",
        failureRedirect: "/login/failed",
    })
);

module.exports = authRoute;
