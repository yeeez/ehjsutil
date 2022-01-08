const axios = require('axios')
const log4js = require('log4js')
const { createHash } = require('crypto')
const { MongoClient, ObjectID } = require('mongodb')
const mysql = require('mysql')

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
            for(let k of ks) buf = buf + data[k]
        }
        buf = buf + timestamp + key
        logger.debug(buf)
        return ShuXue.md5(buf)
    },
    tofix: (f, n) => {
        return Math.round(f * Math.pow(10, n)) / Math.pow(10, n)
    },
    tofix2: f => {
        return Math.round(f * 100) / 100
    },
    tofix3: f => {
        return Math.round(f * 1000) / 1000
    },
    tofix2s: m => {
        if(m == undefined || m == null || m == 0) return '0.00'
        let prefix = ''
        if(m < 0) {
            m = 0 - m
            prefix = '-'
        }
        let r = `${Math.round(m * 100)}`
        return `${prefix}${r.length > 2 ? r.slice(0, -2) : '0'}.${r.slice(-2)}`
    },
    tofix3s: m => {
        if(m == undefined || m == null || m == 0) return '0.000'
        let prefix = ''
        if(m < 0) {
            m = 0 - m
            prefix = '-'
        }
        let r = `${Math.round(m * 1000)}`
        return `${prefix}${r.length > 3 ? r.slice(0, -3) : '0'}.${r.slice(-3)}`
    },
}

const WeiXin = {
    joHandle: jo => {
        logger.info(JSON.stringify(jo.data))
        if(jo.data.errcode === undefined || jo.data.errcode === 0) return jo.data
        else throw new BizError(jo.data)
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
        return EHttp.request(url, WeiXin.joHandle)
    },
    getH5Token: (appID, appSecret, code) => {
        let url = `${wxApiSns}/oauth2/access_token?appid=${appID}&secret=${appSecret}&code=${code}&grant_type=authorization_code`
        return EHttp.request(url, WeiXin.joHandle)
    },
    createMenu: (token, menu) => {
        let url = `${wxApiCgi}/menu/create?access_token=${token}`
        return EHttp.request(url, WeiXin.joHandle, menu)
    },
    downloadMenu: token => {
        let url = `${wxApiCgi}/get_current_selfmenu_info?access_token=${token}`
        return EHttp.request(url, WeiXin.joHandle)
    },
    lstUser: token => {
        let url = `${wxApiCgi}/user/get?access_token=${token}`
        return EHttp.request(url, WeiXin.joHandle)
    },
    getH5User: (token, openid) => {
        let url = `${wxApiSns}/userinfo?access_token=${token}&openid=${openid}&lang=zh_CN`
        return EHttp.request(url, WeiXin.joHandle)
    },
    getUserInfo: (token, openids) => {
        let user_list = openids.map(v => {
            return { openid: v, lang: 'zh_CN' }
        })
        let url = `${wxApiCgi}/user/info/batchget?access_token=${token}`
        return EHttp.request(url, WeiXin.joHandle, { user_list })
    },
    sendTplMsg: (token, msg) => {
        let url = `${wxApiCgi}/message/template/send?access_token=${token}`
        return EHttp.request(url, WeiXin.joHandle, msg)
    },
    updateRemark: (token, openid, remark) => {
        let url = `${wxApiCgi}/user/info/updateremark?access_token=${token}`
        return EHttp.request(url, WeiXin.joHandle, { openid, remark })
    }
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
        return EHttp.request(url, WeiXin.joHandle, pd)
    },
    getPreAuthCode: (componentAccessToken, appid) => {
        let pd = { component_appid: appid }
        let url = `${wxApiCgi}/component/api_create_preauthcode?component_access_token=${componentAccessToken}`
        return EHttp.request(url, WeiXin.joHandle, pd)
    },
    getAuthInfo: (componentAccessToken, appid, authcode) => {
        let pd = {
            component_appid: appid,
            authorization_code: authcode
        }
        let url = `${wxApiCgi}/component/api_query_auth?component_access_token=${componentAccessToken}`
        return EHttp.request(url, WeiXin.joHandle, pd)
    },
    getAuthToken: (componentAccessToken, appid, authAppid, refreshToken) => {
        let pd = {
            component_appid: appid,
            authorizer_appid: authAppid,
            authorizer_refresh_token: refreshToken
        }
        let url = `${wxApiCgi}/component/api_authorizer_token?component_access_token=${componentAccessToken}`
        return EHttp.request(url, WeiXin.joHandle, pd)
    },
    getH5Token: (appid, code, componentAppid, componentAccessToken) => {
        let url = `${wxApiSns}/oauth2/component/access_token?appid=${appid}&code=${code}` +
            `&grant_type=authorization_code&component_appid=${componentAppid}` +
            `&component_access_token=${componentAccessToken}`
        return EHttp.request(url, WeiXin.joHandle)
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
                { upsert: true, returnDocument: 'after' }
            )
            if(result.ok) return result.value
            else throw result.lastErrorObject
        } else {
            let result = await entity.insertOne(doc)
            doc._id = result.insertedId
            return doc
        }
    },
    replace: async (coll, doc) => {
        let entity = Dbo.database.collection(coll)
        if(doc._id) {
            let filter = { _id: new ObjectID(doc._id) }
            let result = await entity.findOneAndReplace(filter, doc,
                { returnDocument: 'after', returnOriginal: false })
            if(result.ok) return result.value
            else throw result.lastErrorObject
        } else {
            throw new BizError('_id needed')
        }
    },
    removeOne: async (coll, doc) => {
        let filter = doc._id ? { _id: new ObjectID(doc._id) } : doc
        let entity = Dbo.database.collection(coll)
        let result = await entity.findOneAndDelete(filter)
        if(result.ok) return result.value
        else throw result.lastErrorObject
    },
    removeMany: async (coll, filter) => {
        let entity = Dbo.database.collection(coll)
        let { result } = await entity.deleteMany(filter)
        if(result.ok) {
            return result.n
        } else {
            throw new BizError('remove many fail')
        }
    },
    getOne: async (coll, query, options) => {
        let entity = Dbo.database.collection(coll)
        if(query && query._id) query._id = new ObjectID(query._id)
        return entity.findOne(query ? query : {}, options ? options : {})
    },
    list: async (coll, query, options) => {
        let entity = Dbo.database.collection(coll)
        let cursor = entity.find(query ? query : {}, options ? options : {})
        return cursor.toArray()
    },
    count: (coll, query) => {
        let entity = Dbo.database.collection(coll)
        return entity.countDocuments(query ? query : {})
    },
    connect: async (mongoUrl, dbname) => {
        Dbo.client = new MongoClient(mongoUrl, { useUnifiedTopology: true })
        await Dbo.client.connect()
        Dbo.database = Dbo.client.db(dbname)
        logger.info(`mongo ${dbname} connected`)
        return true
    },
    close: async () => {
        logger.info('mongo closing...')
        if(Dbo.client) await Dbo.client.close()
        return true
    }
}

const Mysql = {
    connection: null,
    init: mysqlOpt => {
        return new Promise((resolve, reject) => {
            Mysql.connection = mysql.createConnection(mysqlOpt)
            Mysql.connection.connect(err => {
                if(err) reject(err)
                else {
                    logger.info('mysql connected')
                    resolve(Mysql.connection)
                }
            })
        })
    },
    close: () => {
        Mysql.connection.end();
        logger.info('mysql closed');
    },
    execute: sql => {
        return new Promise((resolve, reject) => {
            Mysql.connection.query(sql, (err, rs) => {
                if(err) reject(err)
                else resolve(rs);
            })
        })
    },
    insertOne: async sql => {
        let rs = await Mysql.execute(sql);
        return rs.insertId
    },
    list: async sql => {
        return Mysql.execute(sql)
    },
    getOne: async sql => {
        let rs = await Mysql.execute(sql)
        if(rs.length > 0) return rs[0]
        else return undefined
    },
    getInt: async (sql, name) => {
        let rs = await Mysql.execute(sql)
        if(rs.length <= 0) return undefined
        let r = rs[0]
        if(name) {
            if(!rs[name]) return undefined
            return parseInt(r[name], 0)
        } else {
            for(let i in r) {
                return parseInt(r[i], 0)
            }
        }
    },
}

const EHttp = {
    resp: (success, data) => {
        let msg
        if(success) msg = 'success'
        else if(data != undefined) msg = data
        else msg = '未知错误'
        return {
            success,
            data: data !== undefined ? data : 'success',
            msg,
        }
    },
    ehHandle: jo => {
        logger.info(JSON.stringify(jo.data))
        if(jo.data.success) return jo.data.data
        else throw new BizError(jo.data.msg)
    },
    ehRequest: (url, pd) => {
        return EHttp.request(url, EHttp.ehHandle, pd)
    },
    request: async (url, callback, pd) => {
        try {
            if(pd) {
                logger.info(`post ${url} ${JSON.stringify(pd)}`)
                let jo = await axios.post(url, pd)
                return callback(jo)
            } else {
                logger.info(`get ${url}`)
                let jo = await axios.get(url)
                return callback(jo)
            }
        } catch(err) {
            let msg
            if(err.response) msg = `response status ${err.response.status}`
            else if(err.request) msg = 'request was made but no response'
            else msg = err.message
            logger.error(JSON.stringify(msg))
            throw new BizError(msg)
        }
    },
}

function BizError(message) {
    this.message = message
    this.name = 'BizError'
    Error.captureStackTrace(this, BizError)
}
BizError.prototype = new Error
BizError.prototype.constructor = BizError

const fkSleep = n => {
    return new Promise(resolve => {
        setTimeout(() => {
            resolve()
        }, n)
    })
}

module.exports = { ShuXue, WxOpen, WeiXin, Dbo, Mysql, EHttp, BizError, fkSleep }
