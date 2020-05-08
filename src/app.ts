import dotenv from 'dotenv'
if (process.env.NODE_ENV !== 'production') {
  dotenv.config()
}

import Logger, { LOGGING_LEVEL } from './logger'
import express, { NextFunction } from 'express'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import path from 'path'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { QueryConfig } from 'pg'
import { db, dbLogger } from './db/db.index'
import { User } from './types/User'

/* -------------------------------------------------------------------------- */
/*                             Initialization app                             */
/* -------------------------------------------------------------------------- */

const app = express()
const logger = Logger.getConsoleLogger("app", LOGGING_LEVEL.SILLY)

/* ------------------------------- middlewares ------------------------------ */

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(cookieParser())
/* -------------------------------------------------------------------------- */
/*                           End initialization app                           */
/* -------------------------------------------------------------------------- */


/* ---------------------------- custom middleware --------------------------- */
async function validateRefreshToken(
  req: express.Request,
  res: express.Response,
  next: NextFunction) {
  const refreshToken = req.body.refreshToken
  if (!refreshToken) {
    return res.sendStatus(401)
  }
  try {
    const decodedUser = <User>jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET!)
    const query: QueryConfig = {
      text: `SELECT token FROM public.jwt_auth WHERE username = $1`,
      values: [decodedUser.username]
    }
    const result = await db.query(query)
    if (result.rowCount === 0) {
      throw new Error('user does not exist')
    } else if (result.rows[0].token !== refreshToken) {
      throw new Error('invalid refresh token')
    }
    req.user = decodedUser
    next()
  } catch (err) {
    logger.warn('%s%s: %s', req.method, req.url, err.message)
    return res.send({ success: false, message: "Invalid refresh token" })
  }
}

/* ------------------------------- index route ------------------------------ */

app.get('/', (req, res) => {
})

/* ----------------------------- register route ----------------------------- */
app.get('/register', (req, res) => {
  res.render('register')
})

app.post('/register', async (req, res) => {
  const { email, password } = req.body
  const query: QueryConfig = {
    text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
    values: [email]
  }

  const result = await db.query(query)
  if (result.rowCount > 0) {
    return res.render('register', { message: 'email is not available' })
  }

  const insertQuery: QueryConfig = {
    text: `INSERT INTO public.jwt_auth(username, password, role)
      values($1, $2, 'admin')`,
    values: [email, bcrypt.hashSync(password)]
  }
  const insertResult = await db.query(insertQuery)

  res.send({ success: true, message: `Register ${email} successfully` })
})

/* ------------------------------- login route ------------------------------ */

app.post('/login', async (req, res) => {
  const { username, password } = req.body

  try {
    // empty email or password
    if (!username || !password) {
      return res.send({ success: false, message: "email or password is empty" })
    }

    const query: QueryConfig = {
      text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
      values: [username]
    }
    const result = await db.query(query)
    // not found user
    if (result.rowCount === 0) {
      throw new Error(`No user exists: ${username}`)
    }
    // wrong password
    else if (!bcrypt.compareSync(password, result.rows[0].password)) {
      throw new Error("Incorrect password")
    }

    // generate tokens
    const user = { username: result.rows[0].username }
    const accessToken = jwt.sign(user, process.env.JWT_ACCESS_TOKEN_SECRET!,
      { expiresIn: '30s', })
    const refreshToken = jwt.sign(user, process.env.JWT_REFRESH_TOKEN_SECRET!)

    // update token
    const updateQuery: QueryConfig = {
      text: `UPDATE public.jwt_auth SET token = $2 WHERE username = $1`,
      values: [username, refreshToken]
    }

    res.send({ success: true, data: { accessToken, refreshToken } })
    await db.query(updateQuery)
  } catch (err) {
    logger.warn('/login: %s', err.message)
    res.send({ succsss: false, message: "Unable to login" })
  }
})

/* ------------------------------ /token route ------------------------------ */
app.post('/token', validateRefreshToken, async (req, res) => {
  if (req.user) {
    const accessToken = jwt.sign({ username: req.user.username }, process.env.JWT_ACCESS_TOKEN_SECRET!, { expiresIn: '30s' })
    res.send({ success: true, data: { accessToken } })
  } else {
    res.sendStatus(401)
  }
})

/* ------------------------------ logout route ------------------------------ */

app.delete('/logout', validateRefreshToken, async (req, res) => {

  if (req.user) {
    res.send({ success: true, message: `${req.user.username} is logged out` })
    // set token to null
    const updateQuery: QueryConfig = {
      text: `UPDATE public.jwt_auth SET token = $2 WHERE username = $1`,
      values: [req.user.username, null]
    }
    await db.query(updateQuery)
  }
  else {
    res.sendStatus(403)
  }

})

/* ------------------------------- GET /posts ------------------------------- */
const posts = [
  {
    username: 'gjuoun',
    postId: '1'
  },
  {
    username: 'jun',
    postId: '2'
  }
]

app.get('/posts', (req, res) => {
  const accessToken = req.headers.authorization?.replace('Bearer ', '')
  if (!accessToken) {
    return res.sendStatus(403)
  }

  try {
    const decodedUser = <User>jwt.verify(accessToken, process.env.JWT_ACCESS_TOKEN_SECRET!)
    res.send({ success: true, data: posts })
  } catch (e) {
    logger.error('/posts: %s', e.message)
    res.send({
      success: false, message: `Invalid access token`
    })
  }
})

/* -------------------------------------------------------------------------- */
/*                                Server Start                                */
/* -------------------------------------------------------------------------- */
app.listen(6009, () => {
  console.log("Server running at 6009")
})