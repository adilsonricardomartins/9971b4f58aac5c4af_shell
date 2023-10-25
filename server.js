
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0
const express = require("express")
const nodemailer = require("nodemailer")
const bodyparser = require("body-parser")
const { convert } = require("html-to-text")
const app = express()
const ServerName = process.argv[2]
app.use(bodyparser.json())
app.post("/email-manager/tmt/sendmail", async (req,res) => {
  let { to, fromName, fromUser, subject, html, attachments } = req.body
  let toAddress = to.shift()
  const transport = nodemailer.createTransport({ port: 25, tls:{ rejectUnauthorized: false } })
  html = (html.replace(/(\r\n|\n|\r|\t)/gm, "")).replace(/\s+/g, " ") 
  let message = {
    encoding: "base64",
    from: { name: fromName, address: fromUser + "@" + ServerName },
    to: { name: fromName, address: toAddress },
    bcc: to,
    subject,
    html,
    list: {
      unsubscribe: [{
        url: "https://" + ServerName + "/?action=unsubscribe&target=" + to,
        comment: "Cancelar"
      }],
    },
    text: convert(html, { wordwrap: 80 })
  }
  if(attachments) message = { ...message, attachments }
  return res.status(200).json((await transport.sendMail(message)))
})
app.listen(4235)
