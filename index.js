const axios = require('axios')
const log4js = require('log4js')
const { createHash } = require('crypto')
const { MongoClient, ObjectID } = require('mongodb')

const logger = log4js.getLogger('EJU')
logger.level = 'debug'
const wxApiServer = 'https://api.weixin.qq.com/cgi-bin'
const wxOAuth = 'https://api.weixin.qq.com/sns/oauth2'

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
    errorHandle: (err, reject) => {
        let msg = err.response ?
            `weixin api response ${err.response.status}` :
            (err.request ? 'request was made but no response' : err.message)
        logger.error(msg)
        if (reject) reject(msg)
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
        return new Promise((resolve, reject) => {
            let url = `${wxApiServer}/token?grant_type=client_credential&appid=${appID}&secret=${appSecret}`
            logger.info(url)
            axios.get(url).then(jo => {
                logger.info(JSON.stringify(jo.data))
                if(jo.data.errcode) reject(jo.data)
                else resolve(jo.data)
            }, err => WeiXin.errorHandle(err, reject))
        })
    },
    getH5Token: (appID, appSecret, code) => {
        return new Promise((resolve, reject) => {
            let url = `${wxOAuth}/access_token?appid=${appID}&secret=${appSecret}&code=${code}&grant_type=authorization_code`
            logger.info(url)
            axios.get(url).then(jo => {
                logger.info(JSON.stringify(jo.data))
                if(jo.data.errcode) reject(jo.data)
                else resolve(jo.data)
            }, err => WeiXin.errorHandle(err, reject))
        })
    },
    createMenu: (token, menu) => {
        return new Promise((resolve, reject) => {
            let url = `${wxApiServer}/menu/create?access_token=${token}`
            logger.info(`${url} ${JSON.stringify(menu)}`)
            axios.post(url, menu).then(jo => {
                logger.info(JSON.stringify(jo.data))
                if(jo.data.errcode === 0) resolve(menu)
                else reject(jo.data.errmsg)
            }, err => WeiXin.errorHandle(err, reject))
        })
    },
    downloadMenu: token => {
        return new Promise((resolve, reject) => {
            let url = `${wxApiServer}/get_current_selfmenu_info?access_token=${token}`
            logger.info(url)
            axios.get(url).then(jo => {
                logger.info(JSON.stringify(jo.data))
                if(jo.data.errcode === undefined || jo.data.errcode === 0) resolve(jo.data)
                else reject(jo.data.errmsg)
            }, err => WeiXin.errorHandle(err, reject))
        })
    },
    lstUser: token => {
        return new Promise((resolve, reject) => {
            let url = `${wxApiServer}/user/get?access_token=${token}`
            logger.info(url)
            axios.get(url).then(jo => {
                logger.info(JSON.stringify(jo.data))
                if(jo.data.errcode) reject(jo.data)
                else resolve(jo.data)
            }, err => WeiXin.errorHandle(err, reject))
        })
    },
    getUserInfo: (token, openids) => {
        let user_list = openids.map(v => {
            return { openid: v, lang: 'zh_CN' }
        })
        return new Promise((resolve, reject) => {
            let url = `${wxApiServer}/user/info/batchget?access_token=${token}`
            logger.info(url)
            axios.post(url, { user_list }).then(jo => {
                logger.info(JSON.stringify(jo.data))
                if(jo.data.errcode) reject(jo.data)
                else resolve(jo.data)
            }, err => WeiXin.errorHandle(err, reject))
        })
    }
}

const Dbo = {
    client: null,
    database: null,
    saveOne: async (coll, doc) => {
        let entity = Dbo.database.collection(coll)
        if(doc._id) {
            let filter = { _id: new ObjectID(doc._id) }
            if(doc._id) delete doc._id
            let result = await entity.findOneAndUpdate(
                filter, { $set: doc }, { upsert: true, returnDocument: 'after' }
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
        if(!doc._id) throw 'doc _id property needed'
        let entity = Dbo.database.collection(coll)
        let filter = { _id: new ObjectID(doc._id) }
        let result = await entity.findOneAndDelete(filter)
        if(result.ok) return result.value
        else throw result.lastErrorObject
    },
    getOne: async (coll, query, options) => {
        let entity = Dbo.database.collection(coll)
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

module.exports = { ShuXue, WeiXin, Dbo, EHttp }
