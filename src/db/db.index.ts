import { Client } from 'pg'
import Logger, { LOGGING_LEVEL } from '../logger'

const logger = Logger.getConsoleLogger("db", LOGGING_LEVEL.INFO)

const client = new Client({
  host: 'localhost',
  database: 'postgres',
  user: 'postgres',
  password: '21346687',
  port: 5432,
})

client.connect((err) => {
  if (err) {
    logger.error(err.message)
  }
  logger.info('connected to DB')
})

client.on("error", (err) => {
  logger.error(err.message)
})


export { client as db, logger as dbLogger }