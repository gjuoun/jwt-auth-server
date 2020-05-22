import chalk from 'chalk'
import axios, { AxiosError } from 'axios'

const baseUrl = `http://localhost:6009`

let accessToken = ""
let refreshToken = ""



describe("test localhost:6009", () => {
  expect.extend({
    toBeSuccess(data) {

      if (data.success) {
        return {
          message: () => data.message ?? "",
          pass: true
        };
      } else {
        return {
          message: () => data.message,
          pass: false
        };
      }
    }
  });

  beforeEach(async () => {
    // expect.assertions(3)
    const username = `jun@123.com`
    const password = `12345`

    const res: any = await axios.post(
      `${baseUrl}/login`,
      { username, password })

    let { success, data, message } = res.data

    expect(res.data).toBeSuccess()
    accessToken = data.accessToken
    refreshToken = data.refreshToken
  })


  test("GET: /posts", async (done) => {

    await axios.get(
      `${baseUrl}/posts`,
      {
        headers: {
          "Authorization": `Bearer ${accessToken}`
        }
      }
    ).then((response) => {
      expect(response.data).toBeSuccess()
      done()
    }).catch((e: AxiosError) => {
      const data = e.response?.data
      expect(data.success).toBe(false)
      expect(typeof data.message).toBe("string")
      done()
    })

  })

  test("POST: /token -> get new accessToken ", async () => {

    let res: any = await axios.post(`${baseUrl}/token`, { refreshToken })

    let { success, data, message } = res.data

    expect(res.data).toBeSuccess()
    expect(data).toHaveProperty("accessToken")

    accessToken = data.accessToken
  })

  test("DELETE: /logout", async () => {

    let res: any = await axios.delete(`${baseUrl}/logout`, { data: { refreshToken } })

    let { success, data, message } = res.data

    expect(res.data).toBeSuccess()
    expect(message).toMatch(/^Logout\s(?<name>.*)\ssuccessfully!$/)
  })
})