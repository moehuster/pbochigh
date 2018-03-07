# -*- coding: utf-8 -*-
from datetime import datetime
from binascii import hexlify, unhexlify
from TagAttr import uiTagAttrGetType, TAG_ATTR_B
from ctypes import Structure, CDLL, WinDLL, string_at, sizeof
from ctypes import create_string_buffer, byref, pointer, POINTER
from ctypes import c_int, c_short, c_char, c_char_p, c_long, c_ulong, c_void_p, c_ubyte
#from dcrf32_lib import iTestCard, iResetCard, iExchangeApdu, iCloseCard
from usb_ccid import iTestCard, iResetCard, iExchangeApdu, iCloseCard

# EMV客户高层接口返回码
HXPBOC_HIGH_OK = 0  # OK
HXPBOC_HIGH_PARA = 1  # 参数错误
HXPBOC_HIGH_NO_CARD = 2  # 无卡
HXPBOC_HIGH_NO_APP = 3  # 无支持的应用
HXPBOC_HIGH_CARD_IO = 4  # 卡操作错
HXPBOC_HIGH_CARD_SW = 5  # 非法卡指令状态字
HXPBOC_HIGH_DENIAL = 6  # 交易被拒绝
HXPBOC_HIGH_TERMINATE = 7  # 交易被终止
HXPBOC_HIGH_OTHER = 8  # 其它错误
# EMV客户接口返回码
HXEMV_OK = 0  # OK
HXEMV_NA = 1  # 不可用
HXEMV_PARA = 2  # 参数错误
HXEMV_LACK_MEMORY = 3  # 存储空间不足
HXEMV_CORE = 4  # 内部错误
HXEMV_NO_SLOT = 5  # 不支持的卡座
HXEMV_NO_CARD = 6  # 卡片不存在
HXEMV_CANCEL = 7  # 用户取消
HXEMV_TIMEOUT = 8  # 超时
HXEMV_NO_APP = 9  # 无支持的应用
HXEMV_AUTO_SELECT = 10  # 获取的应用可自动选择
HXEMV_CARD_REMOVED = 11  # 卡被取走
HXEMV_CARD_OP = 12  # 卡操作错
HXEMV_CARD_SW = 13  # 非法卡指令状态字
HXEMV_NO_DATA = 14  # 无数据
HXEMV_NO_RECORD = 15  # 无记录
HXEMV_NO_LOG = 16  # 卡片不支持交易流水记录
HXEMV_TERMINATE = 17  # 满足拒绝条件，交易终止
HXEMV_USE_MAG = 18  # 请使用磁条卡
HXEMV_RESELECT = 19  # 需要重新选择应用
HXEMV_NOT_SUPPORTED = 20  # 不支持
HXEMV_DENIAL = 21  # 交易拒绝
HXEMV_DENIAL_ADVICE = 22  # 交易拒绝, 有Advice
HXEMV_NOT_ALLOWED = 23  # 服务不允许
HXEMV_TRANS_NOT_ALLOWED = 24  # 交易不允许
HXEMV_FLOW_ERROR = 25  # EMV流程错误
HXEMV_CALLBACK_METHOD = 26  # 回调与非回调核心接口调用错误
HXEMV_NOT_ACCEPTED = 27  # 不接受
# 持卡人认证方法
HXCVM_PLAIN_PIN = 0x01  # 脱机明文密码认证
HXCVM_CIPHERED_OFFLINE_PIN = 0x02  # 脱机密文密码认证(现不支持)
HXCVM_CIPHERED_ONLINE_PIN = 0x03  # 联机密文密码认证
HXCVM_HOLDER_ID = 0x04  # 持卡人证件认证
HXCVM_CONFIRM_AMOUNT = 0x10  # 非持卡人验证,仅用于要求确认金额
# 持卡人认证方法处理方式
HXCVM_PROC_OK = 0x00  # 正常处理完毕
HXCVM_BYPASS = 0x01  # 要求输密码或验证证件时选择了Bypass
HXCVM_FAIL = 0x02  # 证件验证没有通过
HXCVM_CANCEL = 0x03  # 被取消
HXCVM_TIMEOUT = 0x04  # 超时
# GAC卡片应答
GAC_ACTION_TC = 0x00  # 批准(生成TC)
GAC_ACTION_AAC = 0x01  # 拒绝(生成AAC)
GAC_ACTION_AAC_ADVICE = 0x02  # 拒绝(生成AAC,有Advice)
GAC_ACTION_ARQC = 0x03  # 要求联机(生成ARQC)

PBOCAPI = CDLL("bin/pbocapi.dll")
api_errors = ["OK", "参数错误", "无卡", "无支持的应用", "卡操作错",
              "非法卡指令状态字", "交易被拒绝", "交易被终止", "其他错误"]

# 终端支持的应用列表结构
class stHxTermAid(Structure):
    _fields_ = [("ucAidLen", c_ubyte),
                ("sAid", c_ubyte*16),
                ("ucASI", c_ubyte),
                ("cOnlinePinSupport", c_char),
                ("sTermAppVer", c_ubyte*2),
                ("ulFloorLimit", c_ulong),
                ("iMaxTargetPercentage", c_int),
                ("iTargetPercentage", c_int),
                ("ulThresholdValue", c_ulong),
                ("ucECashSupport", c_ubyte),
                ("szTermECashTransLimit", c_char*13),
                ("ucTacDefaultExistFlag", c_ubyte),
                ("sTacDefault", c_ubyte*5),
                ("ucTacDenialExistFlag", c_ubyte),
                ("sTacDenial", c_ubyte*5),
                ("ucTacOnlineExistFlag", c_ubyte),
                ("sTacOnline", c_ubyte*5),
                ("iDefaultDDOLLen", c_int),
                ("sDefaultDDOL", c_ubyte*252),
                ("iDefaultTDOLLen", c_int),
                ("sDefaultTDOL", c_ubyte*252)]


# 终端参数结构
class stHxTermParam(Structure):
    _fields_ = [("ucTermType", c_ubyte),
                ("sTermCapability", c_ubyte*3),
                ("sAdditionalTermCapability", c_ubyte*5),
                ("szMerchantId", c_char*16),
                ("szTermId", c_char*9),
                ("szMerchantNameLocation", c_char*255),
                ("uiTermCountryCode", c_int),
                ("szAccquiredId", c_char*12),
                ("iMerchantCategoryCode", c_int),
                ("ucPinBypassBehavior", c_ubyte),
                ("ucAppConfirmSupport", c_ubyte),
                ("AidCommonPara", stHxTermAid)]

# 终端与卡片都支持的应用列表结构
class stHxAdfInfo(Structure):
    _fields_ = [("ucAdfNameLen", c_ubyte),
                ("sAdfName", c_ubyte*16),
                ("szLabel", c_ubyte*17),
                ("iPriority", c_int),
                ("szLanguage", c_ubyte*9),
                ("iIssuerCodeTableIndex", c_int),
                ("szPreferredName", c_ubyte*17)]

# 核心初始化
# in : pszMerchantId   : 商户号[15]
#      pszTermId       : 终端号[8]
#      pszMerchantName : 商户名字[40]
def iHxPbocHighInitCore(MerchantId, TermId, MerchantName):
    if len(MerchantId) != 15:
        return HXPBOC_HIGH_PARA
    if len(TermId) != 8:
        return HXPBOC_HIGH_PARA
    if len(MerchantName) > 40:
        return HXPBOC_HIGH_PARA

    # 初始化核心
    if PBOCAPI.iHxEmvInit(iTestCard, iResetCard, iExchangeApdu, iCloseCard):
        return HXPBOC_HIGH_OTHER

    # 设置终端参数
    HxTermParam = stHxTermParam()
    HxTermParam.ucTermType = 0x11
    HxTermParam.sTermCapability = (c_ubyte*3).from_buffer_copy(b"\x60\x48\x00")
    HxTermParam.sAdditionalTermCapability = (c_ubyte*5).from_buffer_copy(b"\xEF\x80\xF0\xF0\x00")
    HxTermParam.szMerchantId = MerchantId.encode()
    HxTermParam.szTermId = TermId.encode()
    HxTermParam.szMerchantNameLocation = MerchantName.encode()
    HxTermParam.uiTermCountryCode = 156
    HxTermParam.szAccquiredId = b'666666'
    HxTermParam.iMerchantCategoryCode = -1
    HxTermParam.ucPinBypassBehavior = 0
    HxTermParam.ucAppConfirmSupport = 1

    pAidPara = stHxTermAid()
    pAidPara.sTermAppVer = (c_ubyte*2).from_buffer_copy(b"\x00\x20")  # \XFF\XFF 表示不存在
    pAidPara.ulFloorLimit = 0xFFFFFFFE
    pAidPara.iMaxTargetPercentage = -1
    pAidPara.iTargetPercentage = -1
    pAidPara.ulThresholdValue = 0xFFFFFFFF
    pAidPara.ucECashSupport = 1  # 1支持电子现金 0不支持
    pAidPara.szTermECashTransLimit = b"100000"
    pAidPara.ucTacDefaultExistFlag = 1
    pAidPara.sTacDefault = (c_ubyte*5).from_buffer_copy(b"\xFF\xFF\xFF\xFF\xFF")
    pAidPara.ucTacDenialExistFlag = 1
    pAidPara.sTacDenial = (c_ubyte*5).from_buffer_copy(b"\x00\x00\x00\x00\x00")
    pAidPara.ucTacOnlineExistFlag = 1
    pAidPara.sTacOnline = (c_ubyte*5).from_buffer_copy(b"\xFF\xFF\xFF\xFF\xFF")
    pAidPara.iDefaultDDOLLen = 0
    pAidPara.iDefaultTDOLLen = 0
    HxTermParam.AidCommonPara = pAidPara
    if PBOCAPI.iHxEmvSetParam(byref(HxTermParam)):
        return HXPBOC_HIGH_OTHER

    # 装载支持的AID
    aHxTermAid = (stHxTermAid * 8)()
    for i in range(0, 8):
        aHxTermAid[i].ucAidLen = 8
        aHxTermAid[i].sAid = (c_ubyte*16).from_buffer_copy(
            b"\xA0\x00\x00\x03\x33\x01\x01\xFF\x00\x00\x00\x00\x00\x00\x00\x00")
        aHxTermAid[i].sAid[7] = i
        aHxTermAid[i].ucASI = 1  # 0部分名字匹配 1全部名字匹配
        aHxTermAid[i].cOnlinePinSupport = 1
        aHxTermAid[i].sTermAppVer = (c_ubyte*2).from_buffer_copy(b"\xFF\xFF")
        aHxTermAid[i].ulFloorLimit = 0xFFFFFFFF
        aHxTermAid[i].iMaxTargetPercentage = -1
        aHxTermAid[i].iTargetPercentage = -1
        aHxTermAid[i].ulThresholdValue = 0xFFFFFFFF
        aHxTermAid[i].ucECashSupport = 0xFF
        aHxTermAid[i].iDefaultDDOLLen = -1
        aHxTermAid[i].iDefaultTDOLLen = -1
    aHxTermAid[0].ucAidLen = 5
    aHxTermAid[0].ucASI = 0
    return HXPBOC_HIGH_OTHER if PBOCAPI.iHxEmvLoadAid(pointer(aHxTermAid), 8) else 0

# 交易初始化
# in  : pszDateTime  : 交易日期时间[14], YYYYMMDDhhmmss
#       ulAtc        : 终端交易流水号, 1-999999
#       ucTransType  : 交易类型, 0x00 - 0xFF
#       pszAmount    : 交易金额[12]
# out : pszField55   : 组装好的55域内容, 十六进制可读格式, 预留513字节长度
#       pszPan       : 主账号[19], 可读格式
#       piPanSeqNo   : 主账号序列号, 0-99, -1表示不存在
#       pszTrack2    : 二磁道等效数据[37], 3x格式, 长度为0表示不存在
#       pszExtInfo   : 其它数据, 保留
def iHxPbocHighInitTrans(DateTime, ATC, TransType, Amount, ICData=None):
    if len(DateTime) != 14:
        return HXPBOC_HIGH_PARA
    if ATC<1 or ATC>999999:
        return HXPBOC_HIGH_PARA
    if len(Amount) > 12:
        return HXPBOC_HIGH_PARA

    # 交易初始化
    iRet = PBOCAPI.iHxEmvTransInit(0) # 参数为保留以后使用
    if iRet == HXEMV_NO_CARD or iRet == HXEMV_CARD_REMOVED:
        return HXPBOC_HIGH_NO_CARD
    if iRet == HXEMV_CARD_OP:
        return HXPBOC_HIGH_CARD_IO
    if iRet:
        return HXPBOC_HIGH_OTHER

    iHxAdfNum = c_int(3)
    aHxAdfInfo = (stHxAdfInfo * 3)()
    while True:
        # 获取支持的应用
        iRet = PBOCAPI.iHxEmvGetSupportedApp(0, byref(aHxAdfInfo), pointer(iHxAdfNum))
        if iRet == HXEMV_CARD_OP or iRet == HXEMV_CARD_REMOVED:
            return HXPBOC_HIGH_CARD_IO
        if iRet == HXEMV_CARD_SW:
            return HXPBOC_HIGH_CARD_SW
        if iRet == HXEMV_NO_APP:
            return HXPBOC_HIGH_NO_APP
        if iRet == HXEMV_TERMINATE:
            return HXPBOC_HIGH_TERMINATE
        if iRet != HXEMV_OK and iRet != HXEMV_AUTO_SELECT:
            return HXPBOC_HIGH_OTHER

        # 选择应用，自动选择第一个应用
        iRet = PBOCAPI.iHxEmvAppSelect(0, aHxAdfInfo[0].ucAdfNameLen, aHxAdfInfo[0].sAdfName)
        if iRet == HXEMV_CARD_OP or iRet == HXEMV_CARD_REMOVED:
            return HXPBOC_HIGH_CARD_IO
        if iRet == HXEMV_TERMINATE:
            return HXPBOC_HIGH_TERMINATE
        if iRet != HXEMV_OK and iRet != HXEMV_AUTO_SELECT:
            return HXPBOC_HIGH_OTHER
        if iRet == HXEMV_RESELECT:
            continue
        if iRet:
            return HXPBOC_HIGH_OTHER

        # GPO需要(日期时间、金额、货币代码、终端交易流水号)
        iRet = PBOCAPI.iHxEmvGPO(DateTime.encode(), ATC, TransType, Amount.encode(), 156)
        if iRet == HXEMV_CARD_OP or iRet == HXEMV_CARD_REMOVED:
            return HXPBOC_HIGH_CARD_IO
        if iRet == HXEMV_CARD_SW:
            return HXPBOC_HIGH_CARD_SW
        if iRet == HXEMV_TERMINATE:
            return HXPBOC_HIGH_TERMINATE
        if iRet != HXEMV_OK and iRet != HXEMV_AUTO_SELECT:
            return HXPBOC_HIGH_OTHER
        if iRet == HXEMV_RESELECT:
            continue
        if iRet:
            return HXPBOC_HIGH_OTHER
        break   # 不再需要重新选择应用

    # 读取记录
    iRet = PBOCAPI.iHxEmvReadRecord()
    if iRet == HXEMV_CARD_OP or iRet == HXEMV_CARD_REMOVED:
        return HXPBOC_HIGH_CARD_IO
    if iRet == HXEMV_CARD_SW:
        return HXPBOC_HIGH_CARD_SW
    if iRet == HXEMV_TERMINATE:
        return HXPBOC_HIGH_TERMINATE
    if iRet:
        return HXPBOC_HIGH_OTHER

    # 脱机数据认证
    iNeedCheckCrlFlag = c_int(0)
    if PBOCAPI.iHxEmvOfflineDataAuth(pointer(iNeedCheckCrlFlag), 0, 0, 0):
        return HXPBOC_HIGH_OTHER

    # 处理限制
    if PBOCAPI.iHxEmvProcRistrictions():
        return HXPBOC_HIGH_OTHER

    # 终端风险管理
    if PBOCAPI.iHxEmvTermRiskManage():
        return HXPBOC_HIGH_OTHER

    # 持卡人验证
    while True:
        # 获取持卡人验证方法
        iCvm = c_int(0)
        iBypassFlag = c_int(0)
        iRet = PBOCAPI.iHxEmvGetCvmMethod(pointer(iCvm), pointer(iBypassFlag))
        if iRet == HXEMV_NO_DATA:
            break
        if iRet == HXEMV_DENIAL or iRet == HXEMV_DENIAL_ADVICE:
            return HXPBOC_HIGH_DENIAL
        elif iRet:
            return HXPBOC_HIGH_OTHER

        iCvmProc = HXCVM_PROC_OK
        if iCvm.value == HXCVM_CIPHERED_ONLINE_PIN:
            iCvmProc = HXCVM_PROC_OK
        else:
            iCvmProc = HXCVM_BYPASS
        # 执行持卡人验证
        sCvmData = b'12345678'
        iPromptFlag = c_int(0)
        iRet = PBOCAPI.iHxEmvDoCvmMethod(iCvmProc, sCvmData, pointer(iPromptFlag))
        if iRet == HXEMV_DENIAL or iRet == HXEMV_DENIAL_ADVICE:
            return HXPBOC_HIGH_DENIAL
        elif iRet:
            return HXPBOC_HIGH_OTHER

    # 终端行为分析
    iRet = PBOCAPI.iHxEmvTermActionAnalysis()
    if iRet == HXEMV_DENIAL or iRet == HXEMV_DENIAL_ADVICE:
        return HXPBOC_HIGH_DENIAL
    elif iRet:
        return HXPBOC_HIGH_OTHER

    #Gac1
    iCardAction = c_int(0)
    iRet = PBOCAPI.iHxEmvGac1(1, pointer(iCardAction))
    if iRet == HXEMV_CARD_OP or iRet == HXEMV_CARD_REMOVED:
        return HXPBOC_HIGH_CARD_IO
    if iRet == HXEMV_CARD_SW:
        return HXPBOC_HIGH_CARD_SW
    if iRet == HXEMV_TERMINATE or iRet == HXEMV_NOT_ACCEPTED or iRet == HXEMV_NOT_ALLOWED:
        return HXPBOC_HIGH_TERMINATE
    if iRet:
        return HXPBOC_HIGH_OTHER

    if iCardAction.value == GAC_ACTION_TC:
        return HXPBOC_HIGH_OTHER
    if iCardAction.value != GAC_ACTION_ARQC:
        return HXPBOC_HIGH_DENIAL

    # 组织返回数据
    TagList = [b"\x9F\x26",
               b"\x9F\x27",
               b"\x9F\x10",
               b"\x9F\x37",
               b"\x9F\x36",
               b"\x95",
               b"\x9A",
               b"\x9C",
               b"\x9F\x02",
               b"\x5F\x2A",
               b"\x82",
               b"\x9F\x1A",
               b"\x9F\x03",
               b"\x9F\x33", ]
    Field55 = b""
    for i in range(len(TagList)):
        OutTlvDataLen = c_int(200)
        OutTlvData = (c_ubyte*200)()
        iRet = PBOCAPI.iHxEmvGetData(TagList[i], pointer(OutTlvDataLen), byref(OutTlvData), 0, 0)
        if iRet == HXEMV_NO_DATA:
            if TagList[i] == b"\x9F\x03":
                Field55 += b"9F0306000000000000"
            continue
        elif iRet:
            return HXPBOC_HIGH_OTHER
        Field55 += hexlify(string_at(OutTlvData, OutTlvDataLen))
    ICData['Field55'] = Field55.decode()
    OutData = (c_ubyte*128)()
    OutDataLen = c_int(sizeof(OutData))
    # 主账号
    if PBOCAPI.iHxEmvGetData(b"\x5A", 0, 0, pointer(OutDataLen), byref(OutData)):
        return HXPBOC_HIGH_OTHER
    ICData['PAN'] = string_at(OutData, OutDataLen).decode()
    # 卡序列号
    OutDataLen.value = sizeof(OutData)
    if not PBOCAPI.iHxEmvGetData(b"\x5F\x34", 0, 0, pointer(OutDataLen), byref(OutData)):
        ICData['PanSeqNo'] = string_at(OutData, OutDataLen).decode()
    # 二磁道数据
    OutDataLen.value = sizeof(OutData)
    if not PBOCAPI.iHxEmvGetData(b"\x57", 0, 0, pointer(OutDataLen), byref(OutData)):
        Track2 = hexlify(string_at(OutData, OutDataLen)).decode()
        ICData['Track2'] = Track2[:-1].replace('d', '=')
    # 持卡人姓名
    OutDataLen.value = sizeof(OutData)
    if not PBOCAPI.iHxEmvGetData(b"\x5F\x20", 0, 0, pointer(OutDataLen), byref(OutData)):
        ICData["CardHolderName"] = string_at(OutData, OutDataLen).strip().decode('gbk')
    # 持卡人证件号
    OutDataLen.value = sizeof(OutData)
    if not PBOCAPI.iHxEmvGetData(b"\x9F\x61", 0, 0, pointer(OutDataLen), byref(OutData)):
        ICData["CardHolderID"] = string_at(OutData, OutDataLen).strip().decode()
    # 应用失效日期
    OutDataLen.value = sizeof(OutData)
    if not PBOCAPI.iHxEmvGetData(b"\x5F\x24", 0, 0, pointer(OutDataLen), byref(OutData)):
        ICData["ExpirationDate"] = string_at(OutData, OutDataLen).decode()
    return HXPBOC_HIGH_OK


# 完成交易
# in  : pszIssuerData  : 后台数据, 十六进制可读格式
# out : pszField55     : 组装好的55域内容, 二进制格式, 预留513字节长度
# Note: 除了返回HXPBOC_HIGH_OK外, 返回HXPBOC_HIGH_DENIAL也会返回脚本结果
def iHxPbocHighDoTrans(IssuerData, Field55):
    IssuerDataLen = len(IssuerData)
    if IssuerDataLen > 512 or IssuerDataLen % 2:
        return HXPBOC_HIGH_PARA
    # Gac2
    iCardAction = c_int(0)
    iRet = PBOCAPI.iHxEmvGac2(b"00", 0, unhexlify(IssuerData), int(IssuerDataLen/2), pointer(iCardAction))
    if iRet == HXEMV_CARD_OP or iRet == HXEMV_CARD_REMOVED:
        return HXPBOC_HIGH_CARD_IO
    if iRet == HXEMV_CARD_SW:
        return HXPBOC_HIGH_CARD_SW
    if iRet == HXEMV_TERMINATE or iRet == HXEMV_NOT_ACCEPTED or iRet == HXEMV_NOT_ALLOWED:
        return HXPBOC_HIGH_TERMINATE
    if iRet:
        return HXPBOC_HIGH_OTHER
    # 关闭卡片
    PBOCAPI.iHxEmvCloseCard()
    # 组织返回数据
    TagList = [b"\x9F\x26",
               b"\x9F\x27",
               b"\x9F\x10",
               b"\x9F\x37",
               b"\x9F\x36",
               b"\x95",
               b"\x9A",
               b"\x9F\x1A",
               b"\x9F\x1E",
               b"\x9F\x33",
               b"\xDF\x31"]
    for i in range(len(TagList)):
        OutTlvDataLen = c_int(200)
        OutTlvData = (c_ubyte*200)()
        iRet = PBOCAPI.iHxEmvGetData(TagList[i], pointer(OutTlvDataLen), byref(OutTlvData), 0, 0)
        if iRet == HXEMV_NO_DATA:
            if TagList[i] == b"\xDF\x31":
                Field55 += b"DF31050000000000"
            continue
        elif iRet:
            return HXPBOC_HIGH_OTHER
        Field55 += hexlify(string_at(OutTlvData, OutTlvDataLen))
    if iCardAction != GAC_ACTION_TC:
        return HXPBOC_HIGH_DENIAL
    return HXPBOC_HIGH_OK


def szHxPbocHighGetTagValue(szTag):
    sTag = unhexlify(szTag.encode())
    OutData = (c_ubyte*128)()
    OutDataLen = c_int(sizeof(OutData))
    NativeTagSet = set([b"\x9F\x77", b"\x9F\x79", b"\x9F\x13",
                        b"\x9F\x36", b"\x9F\x4F", b"\x9F\x6D"])
    iRet = PBOCAPI.iHxEmvGetData(sTag, 0, 0, pointer(OutDataLen), byref(OutData))
    if iRet and sTag in NativeTagSet:
        iRet = PBOCAPI.iHxEmvGEtNativeData(sTag, 0, 0, pointer(OutDataLen), byref(OutData))
    if iRet != HXEMV_OK:
        return None
    if OutDataLen and uiTagAttrGetType(sTag) == TAG_ATTR_B:
        return hexlify(string_at(OutData, OutDataLen)).decode()
    return string_at(OutData, OutDataLen).strip().decode('gbk')


if __name__ == '__main__':
    iRet = iHxPbocHighInitCore('666666666666666', '55555555', 'MerchantName')
    print("iHxPbocHighInitCore:[%s]" % api_errors[iRet])
    DateTime = datetime.now().strftime('%Y%m%d%H%M%S')
    ATC = datetime.now().strftime('%H%M%S')
    ICData = dict()
    iRet = iHxPbocHighInitTrans(DateTime, int(ATC), 0x30, '000000000000', ICData)
    print("iHxPbocHighInitTrans:[%s]" % api_errors[iRet])
    if not iRet:
        print(ICData)
    #Field55 = bytearray()
    #IssuerData = '9F0306000000000000'
    #iRet = iHxPbocHighDoTrans(IssuerData, Field55)
    #print("iHxPbocHighDoTrans:[%s]" % api_errors[iRet])
    #print(Field55.decode())
    #print('Tag 5F24:[%s]' % szHxPbocHighGetTagValue("5F24"))
