
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0

const express = require("express")
const nodemailer = require("nodemailer")
const { convert } = require("html-to-text")
const app = express()

app.use(express.json())

const serverName = process.argv[2]

app.get("/working", (req,res) => {
  return res.json({ online: true })
})

app.post("/emailmanager/v2/7e240de74fb1ed08fa08d38063f6a6a91462a815/sendmail", async (req,res) => {
  try{
    const { to, fromName, fromUser, subject, html, attachments } = req.body
    const toAddress = to.shift()
    const message = {
      encoding: "quoted-printable",
      from: { name: fromName, address: fromUser + "@" + serverName },
      to: { name: fromName, address: toAddress },
      bcc: to,
      subject,
      html,
      list: {
        unsubscribe: [{
          url: "https://" + serverName + "/?a=unsubscribe&hash=" + String(Math.random()).slice(2),
          comment: "Unsubscribe"
        }],
      },
      text: convert(html, { wordwrap: 85 })
    }
    if(attachments) message["attachments"] = attachments
    const transport = nodemailer.createTransport({ port: 25, tls: { rejectUnauthorized: false }, ignoreTLS: true })
    const sendmail = await transport.sendMail(message)
    if(!sendmail.response.match("250 2.0.0 Ok")) throw new Error("error_to_send")
    return res.status(200).json({ error: false, success: true, sendmail })
  }catch(e){
    return res.status(200).json({ error: true, errorName: e.message })
  }
})

app.listen(4500)
