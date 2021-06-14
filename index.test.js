const { ShuXue, WeiXin } = require('./index')

const appID = 'wxf00c49213b432809'
const appSecret = '65f2b6a3e572eb3cd3f33ab47c05f30b'
const token = 'iamhuhu'
const timestamp = 1623637658255
const nonce = 'abcdefg'
const signature = '4138318614685ff158715ceec6083c6f0e796833'

test('ShuXue.tofix2', () => {
    expect(ShuXue.tofix2(1.2345)).toBe(1.23)
    expect(ShuXue.tofix2(1.2356)).toBe(1.24)
})

test('ShuXue.tofix3', () => {
    expect(ShuXue.tofix3(1.2345)).toBe(1.235)
})

test('WeiXin.checkSign', () => {
    expect(WeiXin.checkSign(token, timestamp, nonce, signature)).toBe(true)
})

test('WeiXin.getAccessToken', () => {
    return expect(WeiXin.getAccessToken(appID, appSecret)).resolves.toBeTruthy()
})
