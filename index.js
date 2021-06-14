const axios = require('axios')
const log4js = require('log4js')
const crypto = require('crypto')

const logger = log4js.getLogger('EJU')
logger.level = 'debug'
const wxApiServer = 'https://api.weixin.qq.com/cgi-bin'

const ShuXue = {
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
        let shasum = crypto.createHash('sha1')
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
    }
}

module.exports = { ShuXue, WeiXin }
