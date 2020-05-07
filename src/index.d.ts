declare global {
  namespace Express {
    export interface Request {
      user: {
        username: string
      }
    }
  }
}

export { }