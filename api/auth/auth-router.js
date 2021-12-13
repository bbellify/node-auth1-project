const bcrypt = require('bcryptjs')
const router = require('express').Router()
const User = require('../users/users-model')
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware')
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
  const { username, password } = req.body
  const newUser = {
    username,
    password: bcrypt.hashSync(password, 8)
  }

  User.add(newUser)
    .then(user => {
      res.status(200).json(user)
    })
    .catch(next)

})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', async (req, res, next) => {
  try {
  const { username, password } = req.body
  const [userFromDb] = await User.findBy({ username })

  if (!userFromDb) {
    return next({ status: 401, message: 'Invalid credentials' })
  }
  const verified = bcrypt.compareSync(password, userFromDb.password)

  if (!verified) {
    return next({ status: 401, message: 'Invalid credentials' })
  }

  req.session.user = userFromDb
  res.json({
    message: `Welcome ${userFromDb.username}!`
  })

  } catch (err) {
    next(err)
  }

})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res, next) => {

})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router