const router = require('express').Router()
const Users = require('./users-model')
const { restricted } = require('../auth/auth-middleware')

router.get('/', restricted, (req, res, next) => {
  Users.find() 
    .then(users => {
      res.json(users)
    })
    .catch(next)
})

module.exports = router