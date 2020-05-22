declare global {

  namespace Express {
    interface Request {
      user: {
        username: string
      }
    }

    interface Response{
      message: any
      data: any
    }
  }


  namespace jest {
    interface Matchers<R> {
      toBeSuccess(): R;
    }
  }
}



export { }