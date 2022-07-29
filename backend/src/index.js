const http = require('http')
const express = require('express')
const Connection = require('./server/server')
const cors = require('cors')
const { Server } = require('socket.io')
const cookieParser = require('cookie-parser')
const Login = require('./Routes/Login')
const Signup = require('./Routes/Signup')
const session = require("express-session");
require('dotenv').config()
const app = express()
const server = http.createServer(app)
const io = new Server(server)
const Authorization = require('./Routes/AuthMiddlewere/authMiddlewere')
const Logout = require('./Routes/Logout')
const authRoute = require('./Routes/Auth')
const passport = require('passport')
const passportSetup = require("./Passport/Passport");

const port = process.env.PORT || 8080

let users = []
let messages = {
  general: [],
  random: [],
  DSA: [],
  MEMES: [],
  Coding: []
}

io.on('connection', (socket) => {
  socket.on('join server', (data) => {
    const user = {
      username: data.username,
      id: socket.id,
    }

    let t = false;

    users.filter(el => {
      if (data.username === el.username) {
        t = true;
        return;
      }
    })

    if (t) {
      return;
    } else {
      users.push(user)
      io.emit('new user', users)
    }

  })

  socket.on('join room', (roomName, cb) => {
    socket.join(roomName)
    cb(messages[roomName])
  })

  socket.on('send message', ({ content, to, sender, chatName, isChannel }) => {
    if (isChannel) {
      const payload = {
        content,
        chatName,
        sender,
        id: socket.id
      };
      socket.to(to).emit("new message", payload);
    }
    else {
      const payload = {
        content,
        chatName: sender,
        sender,
        id: socket.id
      };
      socket.to(to).emit("new message", payload);
    }

    if (messages[chatName]) {
      messages[chatName].push({
        sender,
        content,
        id: socket.id
      });
    }
  })

  socket.on('disconnect', () => {
    users = users.filter((u) => u.id !== socket.id)
    io.emit('new user', users)
  })

})

app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    maxAge: 24 * 60 * 60 * 100,
  })
);

app.use(passport.initialize());
app.use(passport.session());


app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  cors({
    origin: ['http://localhost:3000'],
    credentials: true,
  }),
)

app.get('/', Authorization, (req, res) => {
  res.send('Welcome')
})
app.use("/auth", authRoute);
app.use('/login', Login)
app.use('/signup', Signup)
app.use('/logout', Logout)

server.listen(port, async (err, res) => {
  try {
    await Connection
    console.log('Connected Successfully')
  } catch (err) {
    console.log(err)
  }

  if (err) {
    return console.log('Something went wrong')
  }
  console.log('Sever is live at http://localhost:8080')
})
