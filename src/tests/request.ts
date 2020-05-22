import http, { ClientRequestArgs } from 'http'

export function getRequest(url: string, option: ClientRequestArgs) {
  return new Promise((res, rej) => {
    http.get(url, option, (response) => {
      let data = ""

      response.on("data", (_data) => {
        data += _data
      })
      response.on("end", () => {
        res(JSON.parse(data))
      })
    })
  })
}

export function postRequest(url: string, data: object, option?: ClientRequestArgs) {
  return new Promise<object>((res, rej) => {
    const dataStr = JSON.stringify(data)
    const req = http.request(url,
      {
        method: "post",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": dataStr.length
        }
      }, (response) => {
        let data = ""
        response.on("data", (_data) => {
          data += _data
        })
        response.on("end", () => {
          if (data) {
            res(JSON.parse(data))
          }
        })
      })

    req.write(dataStr)
    req.end()
  })
}
