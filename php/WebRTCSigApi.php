<?php

/**
 * 版本检查
 */
if (version_compare(PHP_VERSION, '5.6.0') < 0 &&
    version_compare(PHP_VERSION, '5.5.10') < 0 &&
    version_compare(PHP_VERSION, '5.4.29') < 0) {
    trigger_error('need php 5.4.29|5.5.10|5.6.0 or newer', E_USER_ERROR);
}

if (!extension_loaded('openssl')) {
    trigger_error('need openssl extension', E_USER_ERROR);
}
if (!in_array('sha256', openssl_get_md_methods(), true)) {
    trigger_error('need openssl support sha256', E_USER_ERROR);
}
if (version_compare(PHP_VERSION, '7.1.0') >= 0 && !in_array('secp256k1', openssl_get_curve_names(), true)) {
    trigger_error('not support secp256k1', E_USER_NOTICE);
}


/**
 * WebRTCSigApi 负责生成userSig和privateMapKey
 */
class WebRTCSigApi {
    private $sdkappid = 0;         // 在腾讯云注册的sdkappid
    private $private_key = false;  // 腾讯云sdkappid对应的私钥
    private $public_key = false;   // 腾讯云sdkappid对应的公钥

    /**
     * 设置sdkappid
     * @param type $sdkappid
     */
    public function setSdkAppid($sdkappid) {
        $this->sdkappid = $sdkappid;
    }

    /**
     * 设置私钥 如果要生成userSig和privateMapKey则需要私钥
     * @param string $private_key 私钥文件内容
     * @return bool 是否成功
     */
    public function setPrivateKey($private_key) {
        $this->private_key = openssl_pkey_get_private($private_key);
        if ($this->private_key === false) {
            throw new Exception(openssl_error_string());
        }
        return true;
    }

    /**
     * 设置公钥 如果要验证userSig和privateMapKey则需要公钥
     * @param string $public_key 公钥文件内容
     * @return bool 是否成功
     */
    public function setPublicKey($public_key) {
        $this->public_key = openssl_pkey_get_public($public_key);
        if ($this->public_key === false) {
            throw new Exception(openssl_error_string());
        }
        return true;
    }

    /**
     * 用于url的base64encode
     * '+' => '*', '/' => '-', '=' => '_'
     * @param string $string 需要编码的数据
     * @return string 编码后的base64串，失败返回false
     */
    private function base64Encode($string) {
        static $replace = Array('+' => '*', '/' => '-', '=' => '_');
        $base64 = base64_encode($string);
        if ($base64 === false) {
            throw new Exception('base64_encode error');
        }
        return str_replace(array_keys($replace), array_values($replace), $base64);
    }

    /**
     * 用于url的base64decode
     * '*' => '+', '-' => '/', '_' => '='
     * @param string $base64 需要解码的base64串
     * @return string 解码后的数据，失败返回false
     */
    private function base64Decode($base64) {
        static $replace = Array('*' => '+', '-' => '/', '_' => '=');
        $string = str_replace(array_keys($replace), array_values($replace), $base64);
        $result = base64_decode($string);
        if ($result == false) {
            throw new Exception('base64_decode error');
        }
        return $result;
    }

    /**
     * ECDSA-SHA256签名
     * @param string $data 需要签名的数据
     * @return string 返回签名 失败时返回false
     */
    private function sign($data) {
        $signature = '';
        if (!openssl_sign($data, $signature, $this->private_key, 'sha256')) {
            throw new Exception(openssl_error_string());
        }
        return $signature;
    }

    /**
     * 验证ECDSA-SHA256签名
     * @param string $data 需要验证的数据原文
     * @param string $sig 需要验证的签名
     * @return int 1验证成功 0验证失败
     */
    private function verify($data, $sig) {
        $ret = openssl_verify($data, $sig, $this->public_key, 'sha256');
        if ($ret == -1) {
            throw new Exception(openssl_error_string());
        }
        return $ret;
    }

    /**
     * 根据json内容生成需要签名的buf串
     * @param array $json 票据json对象
     * @return string 按标准格式生成的用于签名的字符串
     * 失败时返回false
     */
    private function genSignContentForUserSig(array $json) {
        static $members = Array(
            'TLS.appid_at_3rd',
            'TLS.account_type',
            'TLS.identifier',
            'TLS.sdk_appid',
            'TLS.time',
            'TLS.expire_after'
        );

        $content = '';
        foreach ($members as $member) {
            if (!isset($json[$member])) {
                throw new Exception('json need ' . $member);
            }
            $content .= "{$member}:{$json[$member]}\n";
        }
        return $content;
    }

    /**
     * 根据json内容生成需要签名的buf串
     * @param array $json 票据json对象
     * @return string 按标准格式生成的用于签名的字符串
     * 失败时返回false
     */
    private function genSignContentForPrivateMapKey(array $json) {
        static $members = Array(
            'TLS.appid_at_3rd',
            'TLS.account_type',
            'TLS.identifier',
            'TLS.sdk_appid',
            'TLS.time',
            'TLS.expire_after',
            'TLS.userbuf'
        );

        $content = '';
        foreach ($members as $member) {
            if (!isset($json[$member])) {
                throw new Exception('json need ' . $member);
            }
            $content .= "{$member}:{$json[$member]}\n";
        }
        return $content;
    }

    /**
     * 生成userSig
     * @param string $userid 用户名
     * @param uint $expire userSig有效期，出于安全考虑建议为300秒，您可以根据您的业务场景设置其他值。
     * @return string 生成的userSig 失败时为false
     */
    public function genUserSig($userid, $expire = 300) {
        $json = Array(
            'TLS.account_type' => '0',
            'TLS.identifier' => (string) $userid,
            'TLS.appid_at_3rd' => '0',
            'TLS.sdk_appid' => (string) $this->sdkappid,
            'TLS.expire_after' => (string) $expire,
            'TLS.version' => '201512300000',
            'TLS.time' => (string) time()
        );

        $err = '';
        $content = $this->genSignContentForUserSig($json, $err);
        $signature = $this->sign($content, $err);
        $json['TLS.sig'] = base64_encode($signature);
        if ($json['TLS.sig'] === false) {
            throw new Exception('base64_encode error');
        }
        $json_text = json_encode($json);
        if ($json_text === false) {
            throw new Exception('json_encode error');
        }
        $compressed = gzcompress($json_text);
        if ($compressed === false) {
            throw new Exception('gzcompress error');
        }
        return $this->base64Encode($compressed);
    }

    /**
     * 生成privateMapKey
     * @param string $userid 用户名
     * @param uint $roomid 房间号
     * @param uint $expire privateMapKey有效期，出于安全考虑建议为300秒，您可以根据您的业务场景设置其他值。
     * @return string 生成的privateMapKey 失败时为false
     */
    public function genPrivateMapKey($userid, $roomid, $expire = 300) {
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
        $userbuf = pack('C1', '0');                     //cVer  unsigned char/1 版本号，填0
        $userbuf .= pack('n',strlen($userid));          //wAccountLen   unsigned short /2   第三方自己的帐号长度
        $userbuf .= pack('a'.strlen($userid),$userid);  //buffAccount   wAccountLen 第三方自己的帐号字符
        $userbuf .= pack('N',$this->sdkappid);          //dwSdkAppid    unsigned int/4  sdkappid
        $userbuf .= pack('N',$roomid);                  //dwAuthId  unsigned int/4  群组号码/音视频房间号
        $userbuf .= pack('N', time() + $expire);        //dwExpTime unsigned int/4  过期时间 （当前时间 + 有效期（单位：秒，建议300秒））
        $userbuf .= pack('N', hexdec("0xff"));          //dwPrivilegeMap unsigned int/4  权限位       
        $userbuf .= pack('N', 0);                       //dwAccountType  unsigned int/4  第三方帐号类型           

        $json = Array(
            'TLS.account_type' => '0',
            'TLS.identifier' => (string) $userid,
            'TLS.appid_at_3rd' => '0',
            'TLS.sdk_appid' => (string) $this->sdkappid,
            'TLS.expire_after' => (string) $expire,
            'TLS.version' => '201512300000',
            'TLS.time' => (string) time(),
            'TLS.userbuf' => base64_encode($userbuf)
        );

        $err = '';
        $content = $this->genSignContentForPrivateMapKey($json, $err);
        $signature = $this->sign($content, $err);
        $json['TLS.sig'] = base64_encode($signature);
        if ($json['TLS.sig'] === false) {
            throw new Exception('base64_encode error');
        }
        $json_text = json_encode($json);
        if ($json_text === false) {
            throw new Exception('json_encode error');
        }
        $compressed = gzcompress($json_text);
        if ($compressed === false) {
            throw new Exception('gzcompress error');
        }
        return $this->base64Encode($compressed);
    }

    /**
     * 验证userSig
     * @param type $userSig userSig
     * @param type $userid 需要验证用户名
     * @param type $init_time usersig中的生成时间
     * @param type $expire_time usersig中的有效期 如：3600秒
     * @param type $error_msg 失败时的错误信息
     * @return boolean 验证是否成功
     */
    public function verifyUserSig($userSig, $userid, &$init_time, &$expire_time, &$error_msg) {
        try {
            $error_msg = '';
            $decoded_sig = $this->base64Decode($userSig);
            $uncompressed_sig = gzuncompress($decoded_sig);
            if ($uncompressed_sig === false) {
                throw new Exception('gzuncompress error');
            }
            $json = json_decode($uncompressed_sig);
            if ($json == false) {
                throw new Exception('json_decode error');
            }
            $json = (array) $json;
            if ($json['TLS.identifier'] !== $userid) {
                throw new Exception("userid error sigid:{$json['TLS.identifier']} id:{$userid}");
            }
            if ($json['TLS.sdk_appid'] != $this->sdkappid) {
                throw new Exception("sdkappid error sigappid:{$json['TLS.sdk_appid']} thisappid:{$this->sdkappid}");
            }
            $content = $this->genSignContentForUserSig($json);
            $signature = base64_decode($json['TLS.sig']);
            if ($signature == false) {
                throw new Exception('userSig json_decode error');
            }
            $succ = $this->verify($content, $signature);
            if (!$succ) {
                throw new Exception('verify failed');
            }
            $init_time = $json['TLS.time'];
            $expire_time = $json['TLS.expire_after'];
            return true;

        } catch (Exception $ex) {
            $error_msg = $ex->getMessage();
            return false;
        }
    }

    /**
     * 验证privateMapKey
     * @param type $privateMapKey privateMapKey
     * @param type $userid 需要验证用户名
     * @param type $init_time privateMapKey中的生成时间
     * @param type $expire_time privateMapKey中的有效期 如：3600秒
     * @param type $userbuf 视频校验位字符串
     * @param type $error_msg 失败时的错误信息
     * @return boolean 验证是否成功
     */
    public function verifyPrivateMapKey($privateMapKey, $userid, &$init_time, &$expire_time, &$userbuf, &$error_msg) {
        try {
            $error_msg = '';
            $decoded_sig = $this->base64Decode($privateMapKey);
            $uncompressed_sig = gzuncompress($decoded_sig);
            if ($uncompressed_sig === false) {
                throw new Exception('gzuncompress error');
            }
            $json = json_decode($uncompressed_sig);
            if ($json == false) {
                throw new Exception('json_decode error');
            }
            $json = (array) $json;
            if ($json['TLS.identifier'] !== $userid) {
                throw new Exception("userid error sigid:{$json['TLS.identifier']} id:{$userid}");
            }
            if ($json['TLS.sdk_appid'] != $this->sdkappid) {
                throw new Exception("sdkappid error sigappid:{$json['TLS.sdk_appid']} thisappid:{$this->sdkappid}");
            }
            $content = $this->genSignContentForPrivateMapKey($json);
            $signature = base64_decode($json['TLS.sig']);
            if ($signature == false) {
                throw new Exception('sig json_decode error');
            }
            $succ = $this->verify($content, $signature);
            if (!$succ) {
                throw new Exception('verify failed');
            }
            $init_time = $json['TLS.time'];
            $expire_time = $json['TLS.expire_after'];
            $userbuf = base64_decode($json['TLS.userbuf']);
            return true;

        } catch (Exception $ex) {
            $error_msg = $ex->getMessage();
            return false;
        }
    }
}



    /* demo */
    try{
        $sdkappid = 1400037025;  //腾讯云云通信sdkappid
        $roomid = 1234;          //音视频房间号roomid
        $userid = "webrtc98";    //用户名userid
        

        $api = new WebRTCSigApi();

        //设置在腾讯云申请的sdkappid
        $api->setSdkAppid($sdkappid);

        //读取私钥的内容
        //PS:不要把私钥文件暴露到外网直接下载了哦
        $private = file_get_contents(dirname(__FILE__).DIRECTORY_SEPARATOR.'private_key');
        //设置私钥(签发usersig需要用到）
        $api->SetPrivateKey($private);

        //读取公钥的内容
        $public = file_get_contents(dirname(__FILE__).DIRECTORY_SEPARATOR.'public_key');
        //设置公钥(校验userSig和privateMapKey需要用到，校验只是为了验证，实际业务中不需要校验）
        $api->SetPublicKey($public);
 

        //生成privateMapKey
        $privateMapKey = $api->genPrivateMapKey($userid, $roomid);

        //生成userSig
        $userSig = $api->genUserSig($userid);

        //校验
        $result = $api->verifyUserSig($userSig, $userid, $init_time, $expire_time, $error_msg);
        $result = $api->verifyPrivateMapKey($privateMapKey, $userid, $init_time, $expire_time, $userbuf, $error_msg);


        //打印结果
        $ret =  array(
            'privateMapKey' => $privateMapKey,
            'userSig' => $userSig
        );
        echo json_encode($ret);
        echo "\n";
        
    }catch(Exception $e){
        echo $e->getMessage();
    }
    
?>