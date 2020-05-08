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
import jwt, { VerifyErrors, JsonWebTokenError, NotBeforeError, TokenExpiredError } from 'jsonwebtoken'
import moment from 'moment'
import { db, dbLogger } from './db/db.index'
import { QueryConfig } from 'pg'

/* -------------------------------------------------------------------------- */
/*                             Initialization app                             */
/* -------------------------------------------------------------------------- */

const app = express()
const logger = Logger.getConsoleLogger("app", LOGGING_LEVEL.SILLY)

/* ------------------------------- middlewares ------------------------------ */

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(cookieParser())
// app.use(express.static(path.join(__dirname, '../static')))
app.set('view engine', 'pug')
app.set('views', path.join(__dirname, "../views"))

/* -------------------------------- Constant -------------------------------- */

const JWT_SECRET = "my-secret"

/* -------------------------------------------------------------------------- */
/*                           End initialization app                           */
/* -------------------------------------------------------------------------- */




/* ---------------------------- custom middleware --------------------------- */

function validateJWT(
  req: express.Request,
  res: express.Response,
  next: NextFunction) {

  if (!req.cookies.JWT_TOKEN) {
    logger.warn('No JWT token is provided')
    return next()
  }

  try {
    const decodedUser = jwt.verify(req.cookies.JWT_TOKEN, JWT_SECRET)
    req.user = <{ username: string }>decodedUser
  } catch (err) {
    logger.info("JTW error - %s", err.message)
  }

  next()
}

/* ------------------------------- index route ------------------------------ */

app.get('/', validateJWT, (req, res) => {
  logger.debug('user - %o', req.user)
  res.render('index', req.user ? { user: req.user } : {})
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

app.get('/login', (req, res) => {
  res.render('index')
})
app.post('/login', async (req, res) => {
  const { username, password } = req.body

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
    return res.send({ success: false, message: `You are unable to login using ${username}` })
  }
  // wrong password
  if (!bcrypt.compareSync(password, result.rows[0].password)) {
    return res.send({ success: false, message: "Incorrect password" })
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
})

/* ------------------------------ /token route ------------------------------ */
app.post('/token', (req, res) => {
  const refreshToken = req.body.refreshToken
  if (!refreshToken) {
    return res.sendStatus(401)
  }

  try {
    const decodedUser = jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET!)
    const accessToken = jwt.sign(decodedUser, process.env.JWT_ACCESS_TOKEN_SECRET!, { expiresIn: '30s' })
    res.send({ success: true, data: { accessToken } })
  } catch (e) {
    logger.error('Invalid token: %s', e.message)
  }
})

/* ------------------------------ logout route ------------------------------ */

app.delete('/logout', async (req, res) => {
  const refreshToken = req.body.refreshToken
  if (!refreshToken) {
    return res.sendStatus(401)
  }

  try {
    const decodedUser = <{ username: string }>jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET!)
    res.send({ success: true, message: `${decodedUser.username} is logged out` })
    // set token to null
    const updateQuery: QueryConfig = {
      text: `UPDATE public.jwt_auth SET token = $2 WHERE username = $1`,
      values: [decodedUser.username, null]
    }
    await db.query(updateQuery)
  } catch (e) {
    logger.error('Invalid token: %s', e.message)
    res.send({
      success: false, message: `Invalid token `
    })
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
  const accessToken = req.body.accessToken
  if (!accessToken) {
    return res.sendStatus(403)
  }

  try {
    const decodedUser = <{ username: string }>jwt.verify(accessToken, process.env.JWT_ACCESS_TOKEN_SECRET!)
    res.send({ success: true, data: posts })
  } catch (e) {
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