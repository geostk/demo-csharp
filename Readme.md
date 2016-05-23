使用说明:  
1. 开放平台开发者着重关注消息解密算法，目前需要开发者对接收的消息进行解密，开发者可以参照Sample.cs文件对密文进行解密.
2. Cryptography.cs文件封装了AES加解密过程，用户无须关心具体实现.
3. FSBizMsgCrypt.cs封装了DecryptMsg, EncryptMsg两个接口，分别用于收到消息的解密以及消息加密过程.
4. 加解密协议及原理请参考纷享开放平台官方文档(http://open.fxiaoke.com/wiki.html#artiId=18).