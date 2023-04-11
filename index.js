// require('dotenv/config')
require('dotenv').config()
const path = require('path')
const express = require('express')
const PORT = 4000
const cookieParser = require('cookie-parser')
const cors = require('cors')
const {verify} = require('jsonwebtoken')
const {hash, compare} = require('bcryptjs')
const { fakeDB } = require('./fakeDB')
const {createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken} = require('./tokens')
const {isAuth} = require('./isAuth')

const server = express()

server.use(cookieParser())

server.use(
    cors({
        origin: 'http://localhost:3000',
        credentials: true
    })
)

server.use(express.json())
server.use(express.urlencoded({extended: true}))

//registering a user
server.post('/register', async(req,res) => {
    const {email, password} = req.body
    try {
        //checking if user already exists.
        const user = fakeDB.find(user => user.email === email)
        if(user) throw new Error('User already exists!')
        //if user does not exist, hash the password.
        const hashedPassword = await hash(password, 10)
        //insert user in the database.
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashedPassword
        })
        res.send({message: 'User created.'})
        console.log(fakeDB)
    } catch(err) {
        res.send({
            error: `${err.message}`
        })
    }
})

//login a user
server.post('/login', async (req,res) => {
    const { email, password } = req.body
    try {
      // check if user exists.
      const user = fakeDB.find(user => user.email === email)
      if (!user) throw new Error('User does not exist')
      // check if passwords match.
      const valid = await compare(password, user.password)
      if (!valid) throw new Error('Password not correct')
      // create refresh and access tokens.
      const accesstoken = createAccessToken(user.id)
      const refreshtoken = createRefreshToken(user.id)
      // store refresh token in database.
      user.refreshtoken = refreshtoken
      // send token.
      sendRefreshToken(res, refreshtoken)
      sendAccessToken(res, req, accesstoken)
    } catch (err) {
      res.send({
        error: `${err.message}`
      });
    }
});

//logout a user
server.post('/logout', (_req,res) => {
    res.clearCookie('refreshtoken', {path: '/refresh_token'})
    return res.send({
        message: 'Logged out.'
    })
})

//protected route
server.post('/protected', async(req,res) => {
    try {
        const userId = isAuth(res)
        if(userId !== null) {
            res.send({
                data: 'Data is protected.'
            })
        }
    } catch (err) {
        res.send({
            error: `${err.message}`
        })
    }
})

server.listen(PORT, () => console.log(`server listening on port ${PORT}`))