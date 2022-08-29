const { Router } = require('express')
const userModel = require('../models/User')
const jwt = require('jsonwebtoken')
const mail = require('../utils/nodeMailer')
const argon2 = require('argon2')

const route = Router()

route.post('/', async (req, res) => {
  const { email } = req.body

  try {
    const user = await userModel.findOne({ email })
    if (!user) {
      return res
        .status(404)
        .send({ error: 'User dont have any account please create a account' })
    }

    const token = jwt.sign(
      { username: user.username, email: user.email },
      process.env.JWTSECRET,
      { expiresIn: '10m' },
    )

    mail({ username: user.username, token, email })
    res.status(200).send('You will get a link in your email')
  } catch (e) {
    res.status(500).send({ error: 'cant able to send link' })
  }
})


route.post('/reset', async (req, res) => {
  const { password, token } = req.body
  //   console.log(password, 'password')
  try {
    var username, email

    const verify = jwt.verify(
      token,
      process.env.JWTSECRET,
      (error, decoded) => {
        if (error) {
          return
        }

        username = decoded.username
        email = decoded.email
        return true
      },
    )
    console.log(verify)
    if (!username) {
      return res.status(401).send({ error: 'link is not valid' })
    }
    const hash = await argon2.hash(password)
    const user = await userModel.updateOne(
      { email },
      { $set: { password: hash } },
      { new: true },
    )
    // console.log(user, 'forgot')
    const refreshToken = jwt.sign({ username, email }, process.env.JWTSECRET, {
      expiresIn: '7d',
    })
    const accessToken = jwt.sign({ username, email }, process.env.JWTSECRET, {
      expiresIn: '15m',
    })
    res.cookie('refreshToken', refreshToken)
    res.cookie('accessToken', accessToken)
    res.status(200).send('password successfully changed')
  } catch (e) {
    res.status(500).send(e.message)
  }
})

route.post('/:id', async (req, res) => {
  const { id } = req.params

  //   console.log(id, 'verify')
  try {
    const verify = await jwt.verify(id, process.env.JWTSECRET)
    if (!verify) {
      return res.status(401).send({ error: 'link is not valid' })
    }

    res.status(200).send(true)
  } catch (e) {
    res
      .status(500)
      .send({ error: 'Cant able to set Password Somthing went wrong' })
  }
})

module.exports = route
