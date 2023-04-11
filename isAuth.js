const {verify} = require('jsonwebtoken')

exports.isAuth = req => {
    const authorization = req.headers['authorization']
    if(!authorization) throw new Error('Please log in.')
    const token = authorization.split(' ')[1]
    const {userId} = verify(token, process.env.ACCESS_TOKEN_SECRET)
    return userId;
}