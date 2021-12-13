const bcrypt = require('bcryptjs')
const router = require('express').Router()
const User = require('../users/users-model')
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware')


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

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
  const { user, password } = req.body
  
  const verified = bcrypt.compareSync(password, user.password)

  if (!verified) {
    return next({ status: 401, message: 'Invalid credentials' })
  }

  req.session.user = user
  res.json({
    message: `Welcome ${user.username}!`
  })

  } catch (err) {
    next(err)
  }

})

router.get('/logout', async (req, res, next) => {
  try {
    if (req.session.user) {
      req.session.destroy((err) => {
        if (err) {
          next(err)
        } else {
          res.json({ message: 'logged out'})
        }
      })
    } else {
      res.json({ message: 'no session' })
    }
  } catch (err) {
    next(err)
  }

})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router