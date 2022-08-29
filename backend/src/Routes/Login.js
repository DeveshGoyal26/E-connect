const { Router } = require('express')
const userModel = require('../models/User')
const jwt = require('jsonwebtoken')
const argon2 = require('argon2')

const route = Router()

route.post('/', async (req, res) => {
  const { username, email, password } = req.body
  if (!email || !password) {
    return res.status(401).send({ error: 'please provide all the fields' })
  }
  try {
    const exist = await userModel.findOne({ email });

    if (!exist) {
      return res.status(401).send({
        error: 'user dont have a account please register',
      })
    }

    const verifypass = await argon2.verify(exist.password, password)
    if (!verifypass) {
      return res.status(401).send({ error: 'please give valid credentials' })
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

    res.send({ username: exist.username, email })
  } catch (err) {
    console.log('err:', err)
    res.status(500).send({ error: 'something wrong in login' })
  }
})

route.get('/', (req, res) => {
  const accessToken = req.cookies.accessToken
  const refreshToken = req.cookies.refreshToken
  const googleToken = req.cookies["connect.sid"]

  if (!accessToken || !refreshToken) {
    return res.status(401).send({ error: 'authorization failed' })
  }

  const verify = jwt.verify(
    accessToken,
    process.env.JWTSECRET,
    (err, decoded) => {
      if (err) {
        const ref = jwt.verify(
          refreshToken,
          process.env.JWTSECRET,
          (err, decoded) => {
            if (err) {
              return res.status(401).status({ error: 'Authorization failed' })
            }
            const { username, email } = decoded
            const newAccessToken = jwt.sign(
              { username, email },
              process.env.JWTSECRET,
              { expiresIn: '15min' },
            )

            res.cookie('accessToken', newAccessToken)
            return res.status(200).send({ username, email })
            //   next()
          },
        )
      }
      console.log('iam coming man', decoded)
      const { username, email } = decoded
      // res.status(200).send({ username, email })
      res.status(200).send({ username, email })
    },
  )
})

module.exports = route
