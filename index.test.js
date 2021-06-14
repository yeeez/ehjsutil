const { ShuXue, WeiXin, Mongo } = require('./index')

test('ShuXue.md5', () => {
    expect(ShuXue.md5('123456')).toBe('e10adc3949ba59abbe56e057f20f883e')
})

test('ShuXue.sign', () => {
    let data = { a1: 'a1', b: 'b', a2: 'a2' }
    let key = 'iloveu'
    let timestamp = 1623637658255
    expect(ShuXue.sign(data, key, timestamp)).toBe('72627d952f8b7a8fd9c9d009e6d5a407')
})

test('ShuXue.tofix2', () => {
    expect(ShuXue.tofix2(1.2345)).toBe(1.23)
    expect(ShuXue.tofix2(1.2356)).toBe(1.24)
})

test('ShuXue.tofix3', () => {
    expect(ShuXue.tofix3(1.2345)).toBe(1.235)
})

test('WeiXin.checkSign', () => {
    let token = 'iamhuhu'
    let timestamp = 1623637658255
    let nonce = 'abcdefg'
    let signature = '4138318614685ff158715ceec6083c6f0e796833'
    expect(WeiXin.checkSign(token, timestamp, nonce, signature)).toBe(true)
})

// test('WeiXin.getAccessToken', () => {
//     let appID = 'wxf00c49213b432809'
//     let appSecret = '65f2b6a3e572eb3cd3f33ab47c05f30b'
//     return expect(WeiXin.getAccessToken(appID, appSecret)).resolves.toBeTruthy()
// })

test('Mongo.connect', async () => {
    let mongoUrl = 'mongodb://huhu:iloveu@localhost:27017/xmxn'
    let dbname = 'xmxn'
    let r1 = await Mongo.connect(mongoUrl, dbname)
    let r2 = await Mongo.close()
    expect(r1).toBe(true)
    expect(r2).toBe(true)
})
