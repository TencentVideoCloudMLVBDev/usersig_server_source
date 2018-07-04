/**
 * 腾讯云视频通话签名
 */

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");

/**
 * 用于url的base64encode
 * '+' => '*', '/' => '-', '=' => '_'
 * @param string str 需要编码的数据
 * @return string 编码后的base64串
 */
function base64Encode(str) {
    if(typeof str == 'object') {
        return str.toString('base64');
    }
    str = str.replace(/\+/g,'*').replace(/\//g,'-').replace(/\=/g,'_');
    let result = new Buffer(str).toString('base64');
    
    return result;
}

/**
 * 用于url的base64decode
 * '*' => '+', '-' => '/', '_' => '='
 * @param string base64 需要解码的base64串
 * @return string 解码后的数据
 */
function base64Decode(base64) {
    base64 = base64.replace(/\*/g,'+').replace(/-/g,'/').replace(/\_/g,'=');
    let result = new Buffer(base64, 'base64').toString();    
    return result;
}

/**
 * ECDSA-SHA256签名
 * @param string data 需要签名的数据
 * @param string priKey 私钥
 * @return string 返回签名
 */
function sign(data, priKey) {
    let signLib = crypto.createSign('sha256');
    signLib.update(data);
    return signLib.sign(priKey, 'buffer');
}

/**
 * 验证ECDSA-SHA256签名
 * @param string data 需要验证的数据原文
 * @param string sig 需要验证的签名
 * @param string pubKey 公钥
 * @return int 1验证成功 0验证失败
 */
function verify(data, sig, pubKey) {
    let verify = crypto.createVerify('sha256');
    verify.update(data);
    return verify.verify(pubKey, sig);
}

/**
 * 对字符串进行gz压缩
 * @param string str 需要压缩的串
 * @param function callback 压缩后的回调，返回结果base64
 */
function gzcompress(str, callback) {
    
    var input = new Buffer(str, 'binary');
    var compressed = zlib.deflate(input, (err, buffer)=>{
        if(err) {
            callback && callback(err, null);
        }
        else {
            let res = base64Encode(buffer);
            callback && callback(err, res);
        }
    });
}

/**
 * 根据json内容生成需要签名的buf串
 * @param array json 票据json对象
 * @return string 按标准格式生成的用于签名的字符串
 */
function genSignContentForUserSig(json) {
    let members = {
            'TLS.appid_at_3rd': 1,
            'TLS.account_type': 1,
            'TLS.identifier': 1,
            'TLS.sdk_appid': 1,
            'TLS.time': 1,
            'TLS.expire_after': 1
        };
    let content = '';
    for(var k in members) {
        let v = json[k];
        if(typeof v == 'undefined') {
            throw Error(`json need ${k}`);
        }
        content += k+':'+v + "\n";
    }
    return content;
}

/**
 * 根据json内容生成需要签名的buf串
 * @param array json 票据json对象
 * @return string 按标准格式生成的用于签名的字符串
 */
function genSignContentForPrivMapEncrypt(json) {
    let members = {
            'TLS.appid_at_3rd': 1,
            'TLS.account_type': 1,
            'TLS.identifier': 1,
            'TLS.sdk_appid': 1,
            'TLS.time': 1,
            'TLS.expire_after': 1,
            'TLS.userbuf': 1
        };
    let content = '';
    for(var k in members) {
        let v = json[k];
        if(typeof v == 'undefined') {
            throw Error(`json need ${k}`);
        }
        content += k+':'+v + "\n";
    }
    return content;
}

/**
 * 生成userSig 
 * @param string userid 用户名
 * @param uint sdkappid appid
 * @param uint accountType
 * @param string priKey 私钥
 * @param uint expire userSig有效期 默认为300秒
 * @return string 生成的userSig
 */
function genUserSig(userid, sdkappid, accountType, priKey, expire) {
    let json = {
        'TLS.account_type': (accountType||'0').toString(),
        'TLS.identifier': userid,
        'TLS.appid_at_3rd': '0',
        'TLS.sdk_appid': sdkappid.toString(),
        'TLS.expire_after': (expire||'300').toString(),
        'TLS.version': '201512300000',
        'TLS.time': Math.floor(Date.now()/1000).toString()
    };
    let content = genSignContentForUserSig(json);
    //console.log("user sig:");
    //console.log(content);
    let signature = sign(content, priKey);
    json['TLS.sig'] = signature.toString('base64');
    console.log(json['TLS.sig'])
    if(!json['TLS.sig']) {
        throw Error('base64_encode error');
    }
    let json_text = JSON.stringify(json);
    //console.log(json_text);
    return json_text;
}

/**
 * 生成privMapEncrypt
 * @param string userid 用户名
 * @param uint sdkappid appid
 * @param uint accountType accountType
 * @param uint roomid 房间号
 * @param string priKey 私钥
 * @param uint expire privMapEncrypt有效期 默认为300秒
 * @return string 生成的privMapEncrypt
 */
function genPrivMapEncrypt(userid, sdkappid, accountType, roomid, priKey, expire) {
    //视频校验位需要用到的字段
    /*
        cVer    unsigned char/1 版本号，填0
        wAccountLen unsigned short /2   第三方自己的帐号长度
        buffAccount wAccountLen 第三方自己的帐号字符
        dwSdkAppid  unsigned int/4  sdkappid
        dwAuthId    unsigned int/4  群组号码
        dwExpTime   unsigned int/4  过期时间 （当前时间 + 有效期（单位：秒，建议300秒））
        dwPrivilegeMap  unsigned int/4  权限位
        dwAccountType   unsigned int/4  第三方帐号类型
    */
    let accountLength = userid.length;
    let time = Math.floor(Date.now()/1000);
    let expiredTime = time + (expire||300);
    let offset = 0;
    let bytes = new Buffer(1+2+accountLength+4+4+4+4+4);
    bytes[offset++] = 0;
    bytes[offset++] = (accountLength & 0xFF00) >> 8;
    bytes[offset++] = accountLength & 0x00FF;
    
    for (; offset < 3 + accountLength; ++offset) {
        bytes[offset] = userid.charCodeAt(offset - 3);
    }
    bytes[offset++] = (sdkappid & 0xFF000000) >> 24;
    bytes[offset++] = (sdkappid & 0x00FF0000) >> 16;
    bytes[offset++] = (sdkappid & 0x0000FF00) >> 8;
    bytes[offset++] = sdkappid & 0x000000FF;
    
    bytes[offset++] = (roomid & 0xFF000000) >> 24;
    bytes[offset++] = (roomid & 0x00FF0000) >> 16;
    bytes[offset++] = (roomid & 0x0000FF00) >> 8;
    bytes[offset++] = roomid & 0x000000FF;
    
    
    bytes[offset++] = (expiredTime & 0xFF000000) >> 24;
    bytes[offset++] = (expiredTime & 0x00FF0000) >> 16;
    bytes[offset++] = (expiredTime & 0x0000FF00) >> 8;
    bytes[offset++] = expiredTime & 0x000000FF;
    
    bytes[offset++] = (255 & 0xFF000000) >> 24;
    bytes[offset++] = (255 & 0x00FF0000) >> 16;
    bytes[offset++] = (255 & 0x0000FF00) >> 8;
    bytes[offset++] = 255 & 0x000000FF;
    
    bytes[offset++] = (0 & 0xFF000000) >> 24;
    bytes[offset++] = (0 & 0x00FF0000) >> 16;
    bytes[offset++] = (0 & 0x0000FF00) >> 8;
    bytes[offset++] = 0 & 0x000000FF;
    //console.log(bytes);
    let userbufstr = bytes.toString('base64');

    //console.log(bytes);

    let json = {
        'TLS.account_type': '0',
        'TLS.identifier': userid,
        'TLS.appid_at_3rd': '0',
        'TLS.sdk_appid': sdkappid.toString(),
        'TLS.expire_after': (expire||300).toString(),
        'TLS.version': '201512300000',
        'TLS.time': time.toString(),
        'TLS.userbuf': userbufstr
    };

    let content = genSignContentForPrivMapEncrypt(json);

    let signature = sign(content, priKey);
    json['TLS.sig'] = signature.toString("base64");
   
    if (!json['TLS.sig']) {
        throw Error('base64_encode error');
    }
    let json_text = JSON.stringify(json);
    
    return json_text;
}

module.exports = {
    genUserSig: function(opt, cb) {
        //生成userSig
        let userSig = genUserSig(opt.userid, opt.sdkappid, opt.accountType, opt.privateKey);

        gzcompress(userSig, cb);
    },
    genPrivMapEncrypt: function(opt, cb) {
        //生成privMapEncrypt
        let privMapEncrypt = genPrivMapEncrypt(opt.userid, opt.sdkappid, opt.accountType, opt.roomid, opt.privateKey);

        gzcompress(privMapEncrypt, cb);
    },
    gen: function(opt, cb) {        
        var self = this;
        this.genUserSig(opt, function(err1, sig) {
            self.genPrivMapEncrypt(opt, function(err2, enc) {
                cb && cb(err1||err2, {
                    privMapEncrypt: enc,
                    userSig: sig
                })
            });
        });
    }
};

//test
const sdkappid = 14000123345;
const userid = 'test_username';
const roomid = 10000;
const accountType = 12354;
        
//读取私钥的内容
//PS:不要把私钥文件暴露到外网直接下载了哦
let privateKey = fs.readFileSync(path.resolve(__dirname, './private_key'));	
let publicKey = fs.readFileSync(path.resolve(__dirname, './public_key'));

//生成privMapEncrypt
let privMapEncrypt = genPrivMapEncrypt(userid, sdkappid, accountType, roomid, privateKey, 60*60);

gzcompress(privMapEncrypt, function(err,ret){
	if(ret) {
		console.log('privMapEncrypt');
		console.log(ret);
	}
});

//生成userSig
let userSig = genUserSig(userid, sdkappid, accountType, privateKey, 60*60);
		
//打印结果
gzcompress(userSig, function(err,ret){
    if(ret) {
        console.log('userSig');
        console.log(ret);
    }
});