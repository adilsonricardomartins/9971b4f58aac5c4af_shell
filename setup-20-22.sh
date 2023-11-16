#!/bin/bash
# Support 20.04/22.04

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

# NodeJS 21
NODE_MAJOR=21

sudo apt-get update 

sudo apt-get install -y ca-certificates curl gnupg

sudo mkdir -p /etc/apt/keyrings

curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg

echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list

sudo apt-get update && sudo apt-get install wget curl jq python3-certbot-dns-cloudflare opendkim opendkim-tools nodejs -y

sudo mkdir -p /root/.secrets && sudo chmod 0700 /root/.secrets/ && sudo touch /root/.secrets/cloudflare.cfg && sudo chmod 0400 /root/.secrets/cloudflare.cfg

sudo cat <<EOF > /root/.secrets/cloudflare.cfg
dns_cloudflare_email = $CloudflareEmail
dns_cloudflare_api_key = $CloudflareAPI
EOF

sudo cat <<EOF > /etc/hosts
127.0.0.1 localhost
127.0.0.1 $ServerName
$ServerIP $ServerName
EOF

sudo cat <<EOF > /etc/hostname
$ServerName
EOF

sudo hostnamectl set-hostname "$ServerName"

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d $ServerName

sudo mkdir -p /etc/opendkim && sudo mkdir -p /etc/opendkim/keys
sudo chmod -R 777 /etc/opendkim/ && sudo chown -R opendkim:opendkim /etc/opendkim/

sudo cat <<EOF > /etc/default/opendkim
RUNDIR=/run/opendkim
SOCKET="inet:9982@localhost"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EXTRAAFTER=
EOF

sudo cat <<EOF > /etc/opendkim.conf
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
Socket                  inet:9982@localhost
RequireSafeKeys false
EOF

sudo cat <<EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
$ServerName
*.$Domain
EOF

sudo opendkim-genkey -b 2048 -s $DKIMSelector -d $ServerName -D /etc/opendkim/keys/

sudo cat <<EOF > /etc/opendkim/KeyTable
$DKIMSelector._domainkey.$ServerName $ServerName:$DKIMSelector:/etc/opendkim/keys/$DKIMSelector.private
EOF

sudo cat <<EOF > /etc/opendkim/SigningTable
*@$ServerName $DKIMSelector._domainkey.$ServerName
EOF

sudo chmod -R 777 /etc/opendkim/ && sudo chown -R opendkim:opendkim /etc/opendkim/
sudo cp /etc/opendkim/keys/$DKIMSelector.txt /root/dkim.txt && sudo chmod -R 777 /root/dkim.txt

DKIMFileCode=$(cat /root/dkim.txt)

echo '#!/usr/bin/node
const DKIM = `'$DKIMFileCode'`
console.log(DKIM.replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find((c) => c.match("p=")).replace("p=",""))
'| sudo tee /root/dkimcode.sh > /dev/null

sudo chmod 777 /root/dkimcode.sh

sleep 3

debconf-set-selections <<< "postfix postfix/mailname string '"$ServerName"'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string '"$ServerName", localhost'"

sudo apt-get install --assume-yes postfix

sudo cat <<EOF > /etc/postfix/access.recipients
$ServerName OK
EOF

sudo cat <<EOF > /etc/postfix/main.cf
myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
append_dot_mydomain = no
readme_directory = no
max_queue_lifetime = 1200
compatibility_level = 2
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:9982
non_smtpd_milters = inet:localhost:9982
smtpd_recipient_restrictions =
  permit_mynetworks,
  check_recipient_access hash:/etc/postfix/access.recipients,
  permit_sasl_authenticated,
  reject_unauth_destination
smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem
smtpd_tls_security_level=may
smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = $ServerName, localhost
relayhost =
mynetworks = $ServerName 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
EOF

service opendkim restart
service postfix restart

DKIMCode=$(/root/dkimcode.sh)

echo "  -- Obtendo Zona"
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '{"result"}[] | .[0] | .id')
  
  echo "  -- Cadastrando A"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "A", "name": "'$DKIMSelector'", "content": "'$ServerIP'", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando SPF"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "'$ServerName'", "content": "v=spf1 a:'$ServerName' ~all", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando DMARK"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "_dmarc.'$ServerName'", "content": "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmark@'$ServerName'; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando DKIM"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "'$DKIMSelector'._domainkey.'$ServerName'", "content": "v=DKIM1; h=sha256; k=rsa; p='$DKIMCode'", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando MX"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "MX", "name": "'$ServerName'", "content": "'$ServerName'", "ttl": 60, "priority": 10, "proxied": false }'


sudo cat <<EOF > /root/package.json
{
  "name": "sender",
  "version": "1.0.0",
  "dependencies": {
    "body-parser": "1.20.1",
    "express": "4.18.2",
    "html-to-text": "8.2.1",
    "nodemailer": "6.8.0"
  }
}
EOF

sudo cat <<EOF > /root/server.js
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0
const express = require("express")
const nodemailer = require("nodemailer")
const bodyparser = require("body-parser")
const { convert } = require("html-to-text")
const app = express()
app.use(bodyparser.json())
app.post("/email-manager/tmt/sendmail", async (req,res) => {
  let { to, fromName, fromUser, subject, html, attachments } = req.body
  let toAddress = to.shift()
  const transport = nodemailer.createTransport({ port: 25, tls:{ rejectUnauthorized: false } })
  html = (html.replace(/(\r\n|\n|\r|\t)/gm, "")).replace(/\s+/g, " ") 
  let message = {
    encoding: "base64",
    from: { name: fromName, address: fromUser + "@$ServerName" },
    to: { name: fromName, address: toAddress },
    bcc: to,
    subject,
    html,
    list: {
      unsubscribe: [{
        url: "https://" + "$ServerName/?action=unsubscribe&target=" + to,
        comment: "Cancelar"
      }],
    },
    text: convert(html, { wordwrap: 80 })
  }
  if(attachments) message = { ...message, attachments }
  return res.status(200).json((await transport.sendMail(message)))
})
app.listen(4235)
EOF

sleep 3

npm i -g pm2
npm install 

pm2 start server.js 
pm2 startup 
pm2 save

(crontab -l ; echo "*/2 * * * * sudo postsuper -d ALL bounced corrupt deferred") | crontab -
sleep 3



