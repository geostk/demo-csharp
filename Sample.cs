using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
namespace MsgCryptTest
{
    /* 消息加解密测试类
    */
    class Sample
    {

        static void Main(string[] args)
        {
            //开放平台上开发者设置的token, appID, EncodingAESKey
            string sToken = "QDG6eK";
            string sAppID = "wx5823bf96d3bd56c7";
            string sEncodingAESKey = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C";

            /*应用接收到开平消息后需要对消息进行解密
             * 测试：
             * 将sEncryptMsg解密测试是否是明文：
             * "我是中文123abc"
             * */
            string stmp = "";
            string sReqTimeStamp = "1409659813";//消息签名使用的时间戳
            string sReqNonce = "1372623149";//消息签名使用的随机数
            string sEncryptMsg = ""; //加密的密文
            string sMsgSigature = "";//签名
            sMsgSigature = "13870fa8b56b7957a981cc7f8e33b505198f707f";
            sEncryptMsg = "4y2ftZf5G+NOPiZsSlBL8s25/nFUMRq8BJuA0a+tHVYF8dGeRVsANz3Q5ibm9YAoMexq8AiQHSR/jCwNDSGDIw==";

            Fshare.FSBizMsgCrypt wxcpt = new Fshare.FSBizMsgCrypt(sToken, sEncodingAESKey, sAppID);
            int ret = 0;
            ret = wxcpt.DecryptMsg(sMsgSigature, sReqTimeStamp, sReqNonce, sEncryptMsg, ref stmp);
            if (ret != 0)
            {
                System.Console.WriteLine("ERR: Decrypt fail, ret: " + ret);
                return;
            }

            System.Console.WriteLine("解密结果：" + ret);
            System.Console.WriteLine("解密后明文："+stmp);
            return;
        }
    }
}
