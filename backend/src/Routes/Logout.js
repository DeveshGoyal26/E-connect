const { Router } = require('express')

const route = Router()

route.post('/', (req, res) => {
  if (req.logOut) {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
    });
  }
  // console.log("ikkade")
  try {
    res.clearCookie('refreshToken')
    res.clearCookie('accessToken')
    res.clearCookie('connect.sid')
    // req.session = null
    res.status(200).send({ message: 'successfully Loggedout' })
  } catch (e) {
    res.status(500).send({ error: 'somthing went wrong' })
  }
})

module.exports = route
