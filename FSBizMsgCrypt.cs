using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Security.Cryptography;
namespace Fshare
{
    class FSBizMsgCrypt
    {
        string m_sToken;
        string m_sEncodingAESKey;
        string m_sAppID;
        enum FSBizMsgCryptErrorCode
        {
            BizMsgCrypt_OK = 0,
            BizMsgCrypt_ValidateSignature_Error = -40001,         //签名验证错误
            BizMsgCrypt_ComputeSignature_Error = -40003,          //sha加密生成签名失败
            BizMsgCrypt_IllegalAesKey = -40004,                   //AESKey 非法
            BizMsgCrypt_ValidateAppid_Error = -40005,             //appid 校验错误
            BizMsgCrypt_EncryptAES_Error = -40006,                //AES 加密失败
            BizMsgCrypt_DecryptAES_Error = -40007,                //AES 解密失败
            BizMsgCrypt_IllegalBuffer = -40008,                   //解密后得到的buffer非法
            BizMsgCrypt_EncodeBase64_Error = -40009,              //base64加密异常
            BizMsgCrypt_DecodeBase64_Error = -40010               //base64解密异常
        };

        //构造函数
        // @param sToken: 开放平台上，开发者设置的Token
        // @param sEncodingAESKey: 开放平台上，开发者设置的EncodingAESKey
        // @param sAppID: 开放帐号的appid
        public FSBizMsgCrypt(string sToken, string sEncodingAESKey, string sAppID)
        {
            m_sToken = sToken;
            m_sAppID = sAppID;
            m_sEncodingAESKey = sEncodingAESKey;
        }

        // 消息解密算法 (纷享开放平台在回调企业消息接收URL时，会对消息体本身做AES加密，以JSON格式POST到企业应用)
        // 检验消息的来源合法性，并且获取解密后的明文
        // @param sMsgSignature: 签名串，对应消息体中的参数sig
        // @param sTimeStamp: 时间戳，对应消息体中的参数timeStamp
        // @param sNonce: 随机串，对应消息体中的参数nonce
        // @param sPostData: 密文，对应消息体中的参数content
        // @param sMsg: 解密后的原文，当return返回0时有效
        // @return: 成功0，失败返回对应的错误码
        public int DecryptMsg(string sMsgSignature, string sTimeStamp, string sNonce, string sPostData, ref string sMsg)
        {
            if (m_sEncodingAESKey.Length != 43)
            {
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_IllegalAesKey;
            }
            //verify signature
            int ret = 0;
            ret = VerifySignature(m_sToken, sTimeStamp, sNonce, sPostData, sMsgSignature);
            if (ret != 0)
                return ret;
            //decrypt
            string cpid = "";
            try
            {
                sMsg = Cryptography.AES_decrypt(sPostData, m_sEncodingAESKey, ref cpid);
            }
            catch (FormatException)
            {
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_DecodeBase64_Error;
            }
            catch (Exception)
            {
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_DecryptAES_Error;
            }
            if (cpid != m_sAppID)
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_ValidateAppid_Error;
            return 0;
        }

        // 消息签名验证，开平APP跳转或者Web跳转到企业应用，对code消息做签名验证时调用
        // @param sToken: 开放平台上，开发者设置的Token
        // @param sTimeStamp: 时间戳，对应URL中的参数timestamp
        // @param sNonce: 随机串，对应URL中的参数nonce
        // @param sCode: code对应URL中的参数code
        // @param sSigture: 签名串，对应URL中的参数codeSig
        // @return: 成功0，失败返回对应的错误码
        public int VerifyCodeSig(string sToken, string sTimeStamp, string sNonce, string sCode, string sSignature)
        {
			return VerifySignature(sToken, sTimeStamp, sNonce, sCode, sSignature);
        }

        // 消息加密算法(加解密测试调用，纷享开放平台开发者目前仅需要对开放平台推送消息进行解密)
        // @param sReplyMsg: 明文消息
        // @param sTimeStamp: 时间戳
        // @param sNonce: 随机串
        // @param sEncryptMsg: 加密后的密文，当return返回0时有效
        // @param MsgSigature: 生成的消息签名，用于验证消息合法性
        // return：成功0，失败返回对应的错误码
        public int EncryptMsg(string sReplyMsg, string sTimeStamp, string sNonce, ref string sEncryptMsg, ref string MsgSigature)
        {
            if (m_sEncodingAESKey.Length != 43)
            {
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_IllegalAesKey;
            }
            try
            {
                sEncryptMsg = Cryptography.AES_encrypt(sReplyMsg, m_sEncodingAESKey, m_sAppID);
            }
            catch (Exception)
            {
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_EncryptAES_Error;
            }
            int ret = 0;
            ret = GenarateSinature(m_sToken, sTimeStamp, sNonce, sEncryptMsg, ref MsgSigature);
            if (0 != ret)
                return ret;
            return 0;
        }

        public class DictionarySort : System.Collections.IComparer
        {
            public int Compare(object oLeft, object oRight)
            {
                string sLeft = oLeft as string;
                string sRight = oRight as string;
                int iLeftLength = sLeft.Length;
                int iRightLength = sRight.Length;
                int index = 0;
                while (index < iLeftLength && index < iRightLength)
                {
                    if (sLeft[index] < sRight[index])
                        return -1;
                    else if (sLeft[index] > sRight[index])
                        return 1;
                    else
                        index++;
                }
                return iLeftLength - iRightLength;

            }
        }

        // 签名验证
        private static int VerifySignature(string sToken, string sTimeStamp, string sNonce, string sMsgEncrypt, string sSignature)
        {
            string hash = "";
            int ret = 0;
            ret = GenarateSinature(sToken, sTimeStamp, sNonce, sMsgEncrypt, ref hash);
            if (ret != 0)
                return ret;
            if (hash == sSignature)
                return 0;
            else
            {
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_ValidateSignature_Error;
            }
        }

        public static int GenarateSinature(string sToken, string sTimeStamp, string sNonce, string sMsgEncrypt, ref string sMsgSignature)
        {
            ArrayList AL = new ArrayList();
            AL.Add(sToken);
            AL.Add(sTimeStamp);
            AL.Add(sNonce);
            AL.Add(sMsgEncrypt);
            AL.Sort(new DictionarySort());
            string raw = "";
            for (int i = 0; i < AL.Count; ++i)
            {
                raw += AL[i];
            }

            SHA1 sha;
            ASCIIEncoding enc;
            string hash = "";
            try
            {
                sha = new SHA1CryptoServiceProvider();
                enc = new ASCIIEncoding();
                byte[] dataToHash = enc.GetBytes(raw);
                byte[] dataHashed = sha.ComputeHash(dataToHash);
                hash = BitConverter.ToString(dataHashed).Replace("-", "");
                hash = hash.ToLower();
            }
            catch (Exception)
            {
                return (int)FSBizMsgCryptErrorCode.BizMsgCrypt_ComputeSignature_Error;
            }
            sMsgSignature = hash;
            return 0;
        }
    }
}
