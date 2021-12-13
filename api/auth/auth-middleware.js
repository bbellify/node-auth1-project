const User = require('../users/users-model')

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  if (req.session.user) {
    next()
  } else {
    next({ status: 401, message: 'You shall not pass!'})
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  const { username } = req.body
  const isTaken = await User.findBy({ username })
  if (isTaken.length !== 0) {
    next({ status: 422, message: 'Username taken'})
  } else {
    next()
  }
}

async function checkUsernameExists(req, res, next) {
  const { username } = req.body
  const [user] = await User.findBy({ username })
  if (!user) {
    next({ status: 401, message: 'Invalid credentials'})
  } else {
    req.body.user = user
    next()
  }
}

function checkPasswordLength(req, res, next) {
  const { password } = req.body
  if (!password || password.length < 3 ) {
    next({ status: 422, message: 'Password must be longer than 3 chars' })
  } else {
    next()
  }

}

module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
}