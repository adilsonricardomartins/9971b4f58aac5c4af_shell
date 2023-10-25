const { readFileSync } = require("node:fs")

class Utils {
    getDkimCode(){
        const dkim = readFileSync("dkim.txt", "utf-8").replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "")
        return dkim.split(";").find((c) => c.match("p=")).replace("p=","")
    }
}

class CloudFlareService extends Utils {
    constructor(email, key, domain, selector, serverIp){
        super()
        this.domain = domain
        this.serverIp = serverIp
        this.selector = selector
        this.baseURL = "https://api.cloudflare.com/client/v4"
        this.zoneID = null
        this.headers = {
            "X-Auth-Email": email,
            "X-Auth-Key": key,
            "Content-Type": "application/json"
        }
    }

    async request({ url, ...options }){
        try{
            const request = await fetch(this.baseURL + url, { ...options, headers: this.headers })
            const response = await request.json()
            const status = request.status
            return { status, response }
        }catch(e){}
    }

    async getZone(){
        const { response, status } = await this.request({
            url: `/zones?name=${this.domain}&status=active`,
            method: "GET"
        })
        if(status !== 200 || !response.result || response.result.length <= 0) throw new Error("Dominio não encontrado")
        const zoneId = response.result.find(({ name }) => name === this.domain)
        if(!zoneId) throw new Error("Dominio não encontrado")
        this.zoneID = zoneId.id
    }

    async getRecords() {
        const { response } = await this.request({
            url: `/zones/${this.zoneID}/dns_records?per_page=100&name=contains:${this.selector}&type=contains:${this.selector}&content=contains:${this.selector}&match=any&comment.contains=${this.selector}`,
            method: "GET"
        })
        return response.result
    }

    async createRecord(payload){
        await this.request({
            url: `/zones/${this.zoneID}/dns_records`,
            method: "POST",
            body: JSON.stringify(payload)
        })
    }

    async deleteRecord(id){
        await this.request({
            url: `/zones/${this.zoneID}/dns_records/${id}`,
            method: "DELETE"
        })
    }

    async deleteRecords(){
        const records = await this.getRecords()
        await Promise.all(records.map(({ id }) => this.deleteRecord(id)))
    }
}

const register = async (email, key, domain, selector, serverIp) => {
    try{
        const serverName = `${selector}.${domain}`
        const cloudflare = new CloudFlareService(email, key, domain, selector, serverIp)
        await cloudflare.getZone()
        await cloudflare.deleteRecords()
        await Promise.all([
            cloudflare.createRecord({ type: "A", name: selector, content: serverIp, ttl: 60, proxied: false }),
            cloudflare.createRecord({ type: "TXT", name: serverName, content: `v=spf1 a:'${serverName}' ~all`, ttl: 60, proxied: false }),
            cloudflare.createRecord({ type: "TXT", name: `_dmarc.${serverName}`, content: `v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarknew@'${serverName}'; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r`, ttl: 60, proxied: false }),
            cloudflare.createRecord({ type: "TXT", name: `${selector}._domainkey.${serverName}`, content: `v=DKIM1; h=sha256; k=rsa; p='${cloudflare.getDkimCode()}'`, ttl: 60, proxied: false }),
            cloudflare.createRecord({ type: "MX", name: serverName, content: serverName, ttl: 60, priority: 10, proxied: false }),
        ])
    }catch(e){
        console.log("CloudFlare ERROR:", e.message)
        process.exit(0)
    }
}

const start = async () => {
    if(process.argv){
        const args = process.argv.slice(2)
        if(args.length !== 5){
            console.log("Configuração Inválida!")
            process.exit(0)
        }else{
            const [ email, key, domain, selector, serverIp ] = args
            await register(email, key, domain, selector, serverIp)
        }
    }
}

start()