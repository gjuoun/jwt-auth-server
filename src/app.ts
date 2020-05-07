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

const app = express()


const logger = Logger.getConsoleLogger("app", LOGGING_LEVEL.SILLY)

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(cookieParser())
// app.use(express.static(path.join(__dirname, '../static')))
app.set('view engine', 'pug')
app.set('views', path.join(__dirname, "../views"))

const JWT_SECRET = "my-secret"

function validateJWT(
  req: express.Request,
  res: express.Response,
  next: NextFunction) {

  if (!req.cookies.JWT_TOKEN) {
    logger.warn('No JWT token is provided')
    return next()
  }

  try {
    const decoded = jwt.verify(req.cookies.JWT_TOKEN, JWT_SECRET)
    req.user = <{ username: string }>decoded
  } catch (err) {
    logger.info("JTW error - %s", err.message)
  }

  next()
}

app.get('/', validateJWT, (req, res) => {
  logger.debug('user - %o', req.user)
  res.render('index', req.user ? { user: req.user } : {})
})

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

  // res.send({ success: true, data: `Register ${email} successfully` })
  res.render('register', { message: `Register ${email} successfully` })
})

app.get('/login', (req, res) => {
  res.render('index')
})
app.post('/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.send({ success: false, message: "email or password is empty" })
  }

  const query: QueryConfig = {
    text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
    values: [email]
  }
  const result = await db.query(query)
  if (result.rowCount === 0) {
    return res.render('index', { message: `You are unable to login using ${email}` })
  }
  if (!bcrypt.compareSync(password, result.rows[0].password)) {
    return res.render('index', { message: "Incorrect password" })
  }

  const { username } = result.rows[0]
  // set JWT_TOKEN cookie
  res.cookie(`JWT_TOKEN`,
    jwt.sign({ username }, JWT_SECRET)
    , {
      expires: moment().add(7, 'days').toDate(),
      httpOnly: true,
      path: '/',
      sameSite: 'lax'
    })
  res.render('index', { user: { username } })

})

app.post('/logout', (req, res) => {
  res.redirect('/')
})


app.listen(6009, () => {
  console.log("Server running at 6009")
})