const axios = require('axios')
const log4js = require('log4js')
const { createHash } = require('crypto')
const { MongoClient, ObjectID } = require('mongodb')

const logger = log4js.getLogger('EJSU')
logger.level = 'debug'
const wxApiCgi = 'https://api.weixin.qq.com/cgi-bin'
const wxApiSns = 'https://api.weixin.qq.com/sns'

const ShuXue = {
    md5: content => {
        let hash = createHash('md5')
        hash.update(content)
        return hash.digest('hex')
    },
    sign: (data, key, ts) => {
        let timestamp = ts ? ts : (new Date()).getTime()
        let buf = ''
        if(data) {
            let ks = Object.keys(data).sort()
            for(let i=0; i<ks.length; i++) {
                buf = buf + data[ks[i]]
            }
        }
        buf = buf + timestamp + key
        logger.debug(buf)
        return ShuXue.md5(buf)
    },
    tofix2: f => {
        return Math.round(f * 100) / 100
    },
    tofix3: f => {
        return Math.round(f * 1000) / 1000
    }
}

const WeiXin = {
    joHandle: (jo, resolve, reject) => {
        logger.info(JSON.stringify(jo.data))
        if(jo.data.errcode === undefined || jo.data.errcode === 0) resolve(jo.data)
        else reject(jo.data)
        // if(jo.data.errcode) reject(jo.data)
        // else resolve(jo.data)
    },
    errorHandle: (err, reject) => {
        let msg = err.response ?
            `weixin api response ${err.response.status}` :
            (err.request ? 'request was made but no response' : err.message)
        logger.error(msg)
        if (reject) reject(msg)
    },
    request: (url, pd) => {
        return new Promise((resolve, reject) => {
            if(pd) {
                logger.info(`post ${url} ${JSON.stringify(pd)}`)
                axios.post(url, pd).then(
                    jo => WeiXin.joHandle(jo, resolve, reject),
                    err => WeiXin.errorHandle(err, reject)
                )
            } else {
                logger.info(`get ${url}`)
                axios.get(url).then(
                    jo => WeiXin.joHandle(jo, resolve, reject),
                    err => WeiXin.errorHandle(err, reject)
                )
            }
        })
    },
    checkSign: (token, timestamp, nonce, signature) => {
        let tmpArr = [token, timestamp, nonce]
        tmpArr.sort()
        let tmpStr = tmpArr.join('')
        logger.debug(tmpStr)
        let shasum = createHash('sha1')
        shasum.update(tmpStr)
        let signCheck = shasum.digest('hex')
        logger.debug(`${signature} vs ${signCheck}`)
        return signature === signCheck
    },
    getAccessToken: (appID, appSecret) => {
        let url = `${wxApiCgi}/token?grant_type=client_credential&appid=${appID}&secret=${appSecret}`
        return WeiXin.request(url)
    },
    getH5Token: (appID, appSecret, code) => {
        let url = `${wxApiSns}/oauth2/access_token?appid=${appID}&secret=${appSecret}&code=${code}&grant_type=authorization_code`
        return WeiXin.request(url)
    },
    createMenu: (token, menu) => {
        let url = `${wxApiCgi}/menu/create?access_token=${token}`
        return WeiXin.request(url, menu)
    },
    downloadMenu: token => {
        let url = `${wxApiCgi}/get_current_selfmenu_info?access_token=${token}`
        return WeiXin.request(url)
    },
    lstUser: token => {
        let url = `${wxApiCgi}/user/get?access_token=${token}`
        return WeiXin.request(url)
    },
    getH5User: (token, openid) => {
        let url = `${wxApiSns}/userinfo?access_token=${token}&openid=${openid}&lang=zh_CN`
        return WeiXin.request(url)
    },
    getUserInfo: (token, openids) => {
        let user_list = openids.map(v => {
            return { openid: v, lang: 'zh_CN' }
        })
        let url = `${wxApiCgi}/user/info/batchget?access_token=${token}`
        return WeiXin.request(url, user_list)
    },
    sendTplMsg: (token, msg) => {
        let url = `${wxApiCgi}/message/template/send?access_token=${token}`
        return WeiXin.request(url, msg)
    },
}

const WxOpen = {
    checkSign: (token, timestamp, nonce, encrypt, msgSignature) => {
        let tmpArr = [token, timestamp, nonce, encrypt]
        tmpArr.sort()
        let tmpStr = tmpArr.join('')
        logger.debug(tmpStr)
        let shasum = createHash('sha1')
        shasum.update(tmpStr)
        let signCheck = shasum.digest('hex')
        logger.debug(`${msgSignature} vs ${signCheck}`)
        return msgSignature === signCheck
    },
    getAccessToken: (appid, appsecret, ticket) => {
        let pd = {
            component_appid: appid,
            component_appsecret: appsecret,
            component_verify_ticket: ticket
        }
        let url = `${wxApiCgi}/component/api_component_token`
        return WeiXin.request(url, pd)
    },
    getPreAuthCode: (componentAccessToken, appid) => {
        let pd = { component_appid: appid }
        let url = `${wxApiCgi}/component/api_create_preauthcode?component_access_token=${componentAccessToken}`
        return WeiXin.request(url, pd)
    },
    getAuthInfo: (componentAccessToken, appid, authcode) => {
        let pd = {
            component_appid: appid,
            authorization_code: authcode
        }
        let url = `${wxApiCgi}/component/api_query_auth?component_access_token=${componentAccessToken}`
        return WeiXin.request(url, pd)
    },
    getAuthToken: (componentAccessToken, appid, authAppid, refreshToken) => {
        let pd = {
            component_appid: appid,
            authorizer_appid: authAppid,
            authorizer_refresh_token: refreshToken
        }
        let url = `${wxApiCgi}/component/api_authorizer_token?component_access_token=${componentAccessToken}`
        return WeiXin.request(url, pd)
    },
    getH5Token: (appid, code, componentAppid, componentAccessToken) => {
        let url = `${wxApiSns}/oauth2/component/access_token?appid=${appid}&code=${code}` +
            `&grant_type=authorization_code&component_appid=${componentAppid}` +
            `&component_access_token=${componentAccessToken}`
        return WeiXin.request(url)
    },
}

const Dbo = {
    client: null,
    database: null,
    saveOne: async (coll, doc, filter) => {
        let entity = Dbo.database.collection(coll)
        if(doc._id || filter) {
            if(doc._id) {
                filter = { _id: new ObjectID(doc._id) }
                delete doc._id
            }
            let result = await entity.findOneAndUpdate(
                filter, { $set: doc },
                { upsert: true, returnDocument: 'after', returnOriginal: false }
            )
            if(result.ok) return result.value
            else throw result.lastErrorObject
        } else {
            let result = await entity.insertOne(doc)
            doc._id = result.insertedId
            return doc
        }
    },
    removeOne: async (coll, doc) => {
        if(doc._id) filter = { _id: new ObjectID(doc._id) }
        else filter = doc
        let entity = Dbo.database.collection(coll)
        let result = await entity.findOneAndDelete(filter)
        if(result.ok) return result.value
        else throw result.lastErrorObject
    },
    getOne: async (coll, query, options) => {
        let entity = Dbo.database.collection(coll)
        if(query && query._id) query._id = new ObjectID(query._id)
        return await entity.findOne(query ? query : {}, options ? options : {})
    },
    list: async (coll, query, options) => {
        let entity = Dbo.database.collection(coll)
        let cursor = entity.find(query ? query : {}, options ? options : {})
        return await cursor.toArray()
    },
    connect: async (mongoUrl, dbname) => {
        Dbo.client = new MongoClient(mongoUrl, { useUnifiedTopology: true })
        await Dbo.client.connect()
        Dbo.database = Dbo.client.db(dbname)
        logger.info('mongo connected')
        return true
    },
    close: async () => {
        logger.info('mongo closing...')
        if(Dbo.client) await Dbo.client.close()
        return true
    }
}

const EHttp = {
    resp: (success, data) => {
        return {
            success,
            data: data !== undefined ? data : 'success',
            msg: success ? 'success' : ( data != undefined ? data : '未知错误')
        }
    }
}

module.exports = { ShuXue, WxOpen, WeiXin, Dbo, EHttp }
