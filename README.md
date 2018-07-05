用于计算 IM、LiveRoom、RTCRoom 以及 WebRTC 等方案中所需要使用的 **UserSig** 和 **privateMapKey** 签名，算法基于 ECDSA-SHA256 实现

有**php**、**java**和**nodejs**版本

计算**privateMapKey**的时候有个参数**dwPrivilegeMap**表示权限位，代码中默认都是0xff，即拥有全部权限，您可以根据需要调整**dwPrivilegeMap**

```
UPB_CREATE, //创建房间，bit0
UPB_ENTER, //进入房间，bit1
UPB_SEND_AUDIO, //播语音，bit2
UPB_RECV_AUDIO, //收语音，bit3
UPB_SEND_VIDEO, //播视频，bit4
UPB_RECV_VIDEO, //收视频，bit5
UPB_SEND_ASSIST, //播辅路，bit6
UPB_RECV_ASSIST, //收辅路，bit7
```
按位来，一个8bit； 如0xff代表8个bit都是1，即都有权限。 0x01，只有bit0为1，即只有创建房间权限。