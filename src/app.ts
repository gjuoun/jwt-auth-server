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
import { HttpError } from './types/HttpError'

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
    throw new HttpError(401, "No refresh token is provided")
  }

  // decode user from req.body
  const decodedUser = <User>jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET!)
  const query: QueryConfig = {
    text: `SELECT token FROM public.jwt_auth WHERE username = $1`,
    values: [decodedUser.username]
  }
  const result = await db.query(query)
  if (result.rowCount === 0) {
    throw new HttpError(401, 'user does not exist')
  } else if (result.rows[0].token !== refreshToken) {
    throw new HttpError(404, 'invalid refresh token')
  }
  // set user
  req.user = decodedUser
  next()

}

/* ------------------------------- index route ------------------------------ */

app.get('/', (req, res) => {
})

/* ----------------------------- register route ----------------------------- */

app.post('/register', async (req, res, next) => {
  const { email, password } = req.body
  const query: QueryConfig = {
    text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
    values: [email]
  }

  const result = await db.query(query)
  if (result.rowCount > 0) {
    throw new HttpError(409, "email is not available")
  }

  const insertQuery: QueryConfig = {
    text: `INSERT INTO public.jwt_auth(username, password, role)
      values($1, $2, 'admin')`,
    values: [email, bcrypt.hashSync(password)]
  }
  const insertResult = await db.query(insertQuery)

  // set successful message
  res.message = `Register ${email} successfully`
  next()
})

/* ------------------------------- login route ------------------------------ */

app.post('/login', async (req, res, next) => {
  const { username, password } = req.body

  // empty email or password
  if (!username || !password) {
    throw new HttpError(301, "email or password is empty")
  }

  const query: QueryConfig = {
    text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
    values: [username]
  }
  const result = await db.query(query)
  // not found user
  if (result.rowCount === 0) {
    throw new HttpError(301, `No user exists: ${username}`)
  }
  // wrong password
  else if (!bcrypt.compareSync(password, result.rows[0].password)) {
    throw new HttpError(301, `Incorrect Password`)
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

  // set payload
  res.data = { accessToken, refreshToken }
  await db.query(updateQuery)
  next()
})

/* ------------------------------ /token route ------------------------------ */
app.post('/token', validateRefreshToken, async (req, res, next) => {
  if (req.user) {
    const accessToken = jwt.sign({ username: req.user.username }, process.env.JWT_ACCESS_TOKEN_SECRET!, { expiresIn: '30s' })
    res.data = { accessToken }
  }
  next()
})

/* ------------------------------ logout route ------------------------------ */

app.delete('/logout', validateRefreshToken, async (req, res,next) => {

  if (req.user) {
    res.send({ success: true, message: `${req.user.username} is logged out` })
    // set token to null
    const updateQuery: QueryConfig = {
      text: `UPDATE public.jwt_auth SET token = $2 WHERE username = $1`,
      values: [req.user.username, null]
    }
    await db.query(updateQuery)
    res.message = `Logout ${req.user.username} successfully!`
  }

  next()
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

app.get('/posts', (req, res, next) => {
  const accessToken = req.headers.authorization?.replace('Bearer ', '')
  if (!accessToken) {
    throw new HttpError(403, "No access token is provided")
  }

  try {
    const decodedUser = <User>jwt.verify(accessToken, process.env.JWT_ACCESS_TOKEN_SECRET!)
    res.data = {  posts }
    next()
  } catch (e) {
    throw new HttpError(401, "Invalid access token")
  }
})

/* ------------------------------ data handling ----------------------------- */
app.use((err: Error, req: express.Request, res: express.Response, next: NextFunction) => {
  if (res.data || res.message) {
    res.send({
      success: true,
      data: res.data,
      message: res.message
    })
  }
  next()
})


/* ----------------------------- error handling ----------------------------- */
app.use(function (err: Error, req: express.Request, res: express.Response, next: NextFunction) {
  if (err) {
    res.status(404).send({
      success: false,
      message: err.message
    })
  }
  next()
})

/* -------------------------------------------------------------------------- */
/*                                Server Start                                */
/* -------------------------------------------------------------------------- */
app.listen(6009, () => {
  console.log("Server running at 6009")
})