# -*- coding: utf-8 -*-
from binascii import hexlify

TAG_ATTR_N = 0    # compacted, right aligned
TAG_ATTR_CN = 1    # compacted number, left aligned
TAG_ATTR_B = 2    # binary, var 类型也归到此类
TAG_ATTR_A = 3    # Alpha
TAG_ATTR_AN = 4    # Alpha Numeric
TAG_ATTR_ANS = 5    # Alpha Numeric Special
TAG_ATTR_UNKNOWN = 0xff  # unknown tag

TAG_FROM_CARD = 0    # 来自卡片
TAG_FROM_TERM = 1    # 来自终端
TAG_FROM_ISSUER = 2    # 来自发卡行
TAG_FROM_UNKNOWN = 0xff  # unknown tag

aTagAttr = {
#   Tag      Attr          From             L   M    Description
    0x4200: (TAG_ATTR_N,   TAG_FROM_CARD,   6,  6  , "IIN"), # Issuer Identification Number (IIN)
    0x4F00: (TAG_ATTR_B,   TAG_FROM_CARD,   5 , 16 , "AID"), # Application Identifier(AID)
    0x5000: (TAG_ATTR_ANS, TAG_FROM_CARD,   1 , 16 , "Application label"), # Application label
    0x5700: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 19 , "Track2 equivalent data"), # Track 2 Equivalent Data
    0x5A00: (TAG_ATTR_CN,  TAG_FROM_CARD,   1 , 19 , "PAN"), # Application Primary Account Number(PAN)
    0x5F20: (TAG_ATTR_ANS, TAG_FROM_CARD,   2 , 26 , "Cardholder name"), # Cardholder Name
    0x5F24: (TAG_ATTR_N,   TAG_FROM_CARD,   6 , 6  , "Expire date"), # Application Expiration Date
    0x5F25: (TAG_ATTR_N,   TAG_FROM_CARD,   6 , 6  , "Effective date"), # Application Effective Date
    0x5F28: (TAG_ATTR_N,   TAG_FROM_CARD,   3 , 3  , "Issuer country code"), # Issuer Country Code
    0x5F2A: (TAG_ATTR_N,   TAG_FROM_TERM,   3 , 3  , "Transaction currency code"), # Transaction Currency Code
    0x5F2D: (TAG_ATTR_AN,  TAG_FROM_CARD,   2 , 8  , "Language preference"), # Language Preference
    0x5F30: (TAG_ATTR_N,   TAG_FROM_CARD,   3 , 3  , "Service code"), # Service Code
    0x5F34: (TAG_ATTR_N,   TAG_FROM_CARD,   2 , 2  , "PAN seqno"), # Application Primary Account Number Sequence Number
    0x5F36: (TAG_ATTR_N,   TAG_FROM_TERM,   1 , 1  , "Transaction Currency Exponent"), # Transaction Currency Exponent
    0x5F50: (TAG_ATTR_ANS, TAG_FROM_CARD,   0 , 255, "Issuer Script Identifier"), # Issuer Script Identifier
    0x5F53: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 34,  "IBAN"), # International Bank Account Number (IBAN)
    0x5F54: (TAG_ATTR_B,   TAG_FROM_CARD,   8 , 11,  "BIC"), # Bank Identifier Code (BIC)
    0x5F55: (TAG_ATTR_A,   TAG_FROM_CARD,   2 , 2,   "Issuer Country Code(a2)"), # Issuer Country Code (alpha2 format)
    0x5F56: (TAG_ATTR_A,   TAG_FROM_CARD,   3 , 3,   "Issuer Country Code(a3)"), # Issuer Country Code (alpha3 format)
    0x5F57: (TAG_ATTR_N,   TAG_FROM_TERM,   2 , 2,   "Account Type"), # Account Type
    0x6100: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "Application Template"), # Application Template
    0x6F00: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "FCI"), # File Control Infomation Template
    0x7000: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "AEF data template"), # Application Elementary File Data Template
    0x7100: (TAG_ATTR_B,   TAG_FROM_ISSUER, 0 , 255, "Issuer Script Template 1"), # Issuer Script Template 1
    0x7200: (TAG_ATTR_B,   TAG_FROM_ISSUER, 0 , 255, "Issuer Script Template 2"), # Issuer Script Template 2
    0x7300: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "Directory Discretionary Template"), # Directory Discretionary Template
    0x7700: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 255, "Response Message Template Format 2"), # Response Message Template Format 2
    0x8000: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 255, "Response Message Template Format 1"), # Response Message Template Format 1
    0x8100: (TAG_ATTR_B,   TAG_FROM_TERM,   4 , 4  , "Amount(B)"), # Amount, Authorised(Binary)
    0x8200: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "AIP"), # Application Interchange Profile
    0x8300: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 255, "Command Template"), # Command Template
    0x8400: (TAG_ATTR_B,   TAG_FROM_CARD,   5 , 16 , "DF name"), # Dedicated File(DF) Name
    0x8600: (TAG_ATTR_B,   TAG_FROM_ISSUER, 0 , 255, "Issuer Script command"), # Issuer Script command # 文档规定最大261 ????
    0x8700: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "Application priority indicator"), # Application Priority Indicator
    0x8800: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "SFI"), # Short File Identifier
    0x8900: (TAG_ATTR_AN,  TAG_FROM_ISSUER, 6 , 6  , "Authorisation Code"), # Authorisation Code, 规范未定义类型, 根据具体支付系统定, 因此设为AN型
    0x8A00: (TAG_ATTR_AN,  TAG_FROM_ISSUER, 2 , 2  , "Authorisation Response Code"), # Authorisation Response Code(规范定义为Issuer/Terminal)
    0x8C00: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "CDOL1"), # Card Risk Management Data Object List 1(CDOL1)
    0x8D00: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "CDOL2"), # Card Risk Management Data Object List 2(CDOL2)
    0x8E00: (TAG_ATTR_B,   TAG_FROM_CARD,   8,  252, "CVM list"), # Cardholder Verification Method(CVM) List
    0x8F00: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "CA public key index"), # Certification Authority Public Key Index
    0x9000: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 248, "Issuer public key cert"), # Issuer Public Key Certificate
    0x9100: (TAG_ATTR_B,   TAG_FROM_ISSUER, 8 , 16 , "Issuer Authentication Data"), # Issuer Authentication Data
    0x9200: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "Issuer public key remainder"), # Issuer Public Key Remainder
    0x9300: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 248, "Signed Static Application Data"), # Signed Static Application Data
    0x9400: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "AFL"), # Application File Locator(AFL)
    0x9500: (TAG_ATTR_B,   TAG_FROM_TERM,   5 , 5  , "TVR"), # Terminal Verification Results
    0x9700: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "TDOL"), # Transaction Certificate Data Object List(TDOL)
    0x9800: (TAG_ATTR_B,   TAG_FROM_TERM,   20, 20 , "TC hash value"), # Transaction Certificate(TC) Hash Value
    0x9900: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 255, "Transaction PIN data"), # Transaction Personal Identification Number(PIN) Data
    0x9A00: (TAG_ATTR_N,   TAG_FROM_TERM,   6 , 6  , "Transaction date"), # Transaction Date
    0x9B00: (TAG_ATTR_B,   TAG_FROM_TERM,   2 , 2  , "TSI"), # Transaction Status Information
    0x9C00: (TAG_ATTR_N,   TAG_FROM_TERM,   2 , 2  , "Transaction type"), # Transaction Type
    0x9D00: (TAG_ATTR_B,   TAG_FROM_CARD,   5 , 16 , "DDF name"), # Directory Definition File(DDF) Name
    0x9F01: (TAG_ATTR_N,   TAG_FROM_TERM,   6 , 11 , "Acquirer Identifier"), # Acquirer Identifier
    0x9F02: (TAG_ATTR_N,   TAG_FROM_TERM,   12, 12 , "Amount(N)"), # Amount, Authorised(Numeric)
    0x9F03: (TAG_ATTR_N,   TAG_FROM_TERM,   12, 12 , "Amount, Other(N)"), # Amount, Other(Numeric)
    0x9F04: (TAG_ATTR_B,   TAG_FROM_TERM,   4 , 4  , "Amount, Other(B)"), # Amount, Other(Binary)
    0x9F05: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 32 , "Application Discretionary Data"), # Application Discretionary Data
    0x9F06: (TAG_ATTR_B,   TAG_FROM_TERM,   5 , 16 , "AID"), # Application Identifier(AID)
    0x9F07: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "AUC"), # Application Usage Control
    0x9F08: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "Card application version number"), # Application Version Number, Card
    0x9F09: (TAG_ATTR_B,   TAG_FROM_TERM,   2 , 2  , "Terminal application version number"), # Application Version Number, Terminal
    0x9F0B: (TAG_ATTR_ANS, TAG_FROM_CARD,   27, 45 , "Cardholder Name Extended"), # Cardholder Name Extended
    0x9F0D: (TAG_ATTR_B,   TAG_FROM_CARD,   5 , 5  , "IAC-default"), # Issuer Action Code - Default
    0x9F0E: (TAG_ATTR_B,   TAG_FROM_CARD,   5 , 5  , "IAC-denial"), # Issuer Action Code - Denial
    0x9F0F: (TAG_ATTR_B,   TAG_FROM_CARD,   5 , 5  , "IAC-online"), # Issuer Action Code - online
    0x9F10: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 32 , "Issuer application data"), # Issuer Application Data
    0x9F11: (TAG_ATTR_N,   TAG_FROM_CARD,   2 , 2  , "Issuer Code Table Index"), # Issuer Code Table Index
    0x9F12: (TAG_ATTR_ANS, TAG_FROM_CARD,   1 , 16 , "Application preferred name"), # Application Preferred Name
    0x9F13: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "Last ATC"), # Last Online Application Transaction Counter(ATC) Register
    0x9F14: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "Lower consecutive offline limit"), # Lower Consecutive Offline Limit
    0x9F15: (TAG_ATTR_N,   TAG_FROM_TERM,   4 , 4  , "Merchant Category Code"), # Merchant Category Code
    0x9F16: (TAG_ATTR_ANS, TAG_FROM_TERM,   15, 15 , "MID"), # Merchant Identifier
    0x9F17: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "PIN try counter"), # Personal Identification Number(PIN) Try Counter
    0x9F18: (TAG_ATTR_B,   TAG_FROM_ISSUER, 4 , 4  , "Issuer Script Identifier"), # Issuer Script Identifier
    0x9F1A: (TAG_ATTR_N,   TAG_FROM_TERM,   3 , 3  , "Terminal country code"), # Terminal Country Code
    0x9F1B: (TAG_ATTR_B,   TAG_FROM_TERM,   4 , 4  , "Terminal floor limit"), # Terminal Floor Limit
    0x9F1C: (TAG_ATTR_AN,  TAG_FROM_TERM,   8 , 8  , "TID"), # Terminal Identification
    0x9F1D: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 8  , "Terminal Risk Management Data"), # Terminal Risk Management Data
    0x9F1E: (TAG_ATTR_AN,  TAG_FROM_TERM,   8 , 8  , "IFD Serial Number"), # Interface Device(IFD) Serial Number
    0x9F1F: (TAG_ATTR_ANS, TAG_FROM_CARD,   0 , 252, "Track 1 Discretionary Data"), # Track 1 Discretionary Data
    0x9F20: (TAG_ATTR_CN,  TAG_FROM_CARD,   0 , 252, "Track 2 Discretionary Data"), # Track 2 Discretionary Data
    0x9F21: (TAG_ATTR_N,   TAG_FROM_TERM,   6 , 6  , "Transaction time"), # Transaction Time
    0x9F22: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1  , "CA public key index"), # Certification Authority Public Key Index
    0x9F23: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "Upper consecutive offline limit"), # Upper Consecutive Offline Limit
    0x9F26: (TAG_ATTR_B,   TAG_FROM_CARD,   8 , 8  , "AC"), # Application Cryptogram
    0x9F27: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "CID"), # Cryptogram information Data
    0x9F2D: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 248, "ICC PIN Public Key Certificate"), # ICC PIN Encipherment Public Key Certificate
    0x9F2E: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 3  , "ICC PIN Public Key Exponent"), # ICC PIN Encipherment Public Key Exponent
    0x9F2F: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 255, "ICC PIN Public Key Remainder"), # ICC PIN Encipherment Public Key Remainder
    0x9F32: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 3  , "Issuer Public Key Exponent"), # Issuer Public Key Exponent
    0x9F33: (TAG_ATTR_B,   TAG_FROM_TERM,   3 , 3  , "Terminal Capabilities"), # Terminal Capabilities
    0x9F34: (TAG_ATTR_B,   TAG_FROM_TERM,   3 , 3  , "CVM result"), # Cardholder Verification Method(CVM) Results
    0x9F35: (TAG_ATTR_N,   TAG_FROM_TERM,   2 , 2  , "Terminal Type"), # Terminal Type
    0x9F36: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "ATC"), # Application Transaction Counter(ATC)
    0x9F37: (TAG_ATTR_B,   TAG_FROM_TERM,   4 , 4  , "RAND"), # Unpredictable Number
    0x9F38: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 255, "PDOL"), # Processing Options Data Object List(PDOL)
    0x9F39: (TAG_ATTR_N,   TAG_FROM_TERM,   2 , 2  , "POS Entry Mode"), # Point-of-Service(POS) Entry Mode
    0x9F3A: (TAG_ATTR_B,   TAG_FROM_TERM,   4 , 4  , "Amount, Reference Currency"), # Amount, Reference Currency
    0x9F3B: (TAG_ATTR_N,   TAG_FROM_CARD,   3 , 15 , "Appilcation Reference Currency"), # Appilcation Reference Currency
    0x9F3C: (TAG_ATTR_N,   TAG_FROM_TERM,   3 , 3  , "Transaction Reference Currency"), # Transaction Reference Currency
    0x9F3D: (TAG_ATTR_N,   TAG_FROM_TERM,   1 , 1  , "Transaction Reference Currency Exponent"), # Transaction Reference Currency Exponent
    0x9F40: (TAG_ATTR_B,   TAG_FROM_TERM,   5 , 5  , "Additional Terminal Capabilities"), # Additional Terminal Capabilities
    0x9F41: (TAG_ATTR_N,   TAG_FROM_TERM,   4 , 8  , "Transaction Sequence Counter"), # Transaction Sequence Counter
    0x9F42: (TAG_ATTR_N,   TAG_FROM_CARD,   3 , 3  , "Application currency code"), # Application Currency Code
    0x9F43: (TAG_ATTR_N,   TAG_FROM_CARD,   1 , 7  , "Application Reference Currency Exponent"), # Application Reference Currency Exponent
    0x9F44: (TAG_ATTR_N,   TAG_FROM_CARD,   1 , 1  , "Application Currency Exponent"), # Application Curerncy Exponent
    0x9F45: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "DAC"), # Data Authentication Code
    0x9F46: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 248, "Icc public key cert"), # ICC Public Key Certificate
    0x9F47: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 3  , "Icc public key exp"), # ICC Public Key Exponent
    0x9F48: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "Icc public key remainder"), # ICC Public Key Remainder
    0x9F49: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "DDOL"), # Dynamic Data Object List(DDOL)
    0x9F4A: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 252, "Static data Authentication tag list"), # Static Data Authentication Tag List
    0x9F4B: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 248, "Signed Dynamic Application Data"), # Signed Dynamic Application Data
    0x9F4C: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 8  , "ICC Dynamic Number"), # ICC Dynamic Number
    0x9F4D: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "Log Entry"), # Log Entry
    0x9F4E: (TAG_ATTR_ANS, TAG_FROM_TERM,   0 , 255, "Merchant Name and Location"), # Merchant Name and Location
    0x9F4F: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 255, "Log format"), # Log Format

# Tag9F51-Tag9F7B只在pboc2.0规范上有描述，行首标有/**/注释的Tag为卡片内部数据，核心不必关心此类Tag
    0x9F51: ((TAG_ATTR_N,  TAG_FROM_CARD,   3 , 3  , "Application currency code")), # Application Currency Code
    0x9F5A: (TAG_ATTR_ANS, TAG_FROM_CARD,   0 , 255, "Issuer URL2"), # Issuer URL2
    0x9F5D: (TAG_ATTR_N,   TAG_FROM_CARD,   12, 12 , "available offline amount"), # qPBOC: Available Offline spending Amount
    0x9F61: (TAG_ATTR_AN,  TAG_FROM_CARD,   1 , 40 , "holder id"), # pboc2.0 Holder Id
    0x9F62: (TAG_ATTR_B,   TAG_FROM_CARD,   1 , 1  , "holder id type"), # pboc2.0 Holder Id Type
    0x9F63: (TAG_ATTR_B,   TAG_FROM_CARD,   16, 16 , "pboc2.0 card product id"), # pboc2.0 卡产品标识信息
    0x9F66: (TAG_ATTR_B,   TAG_FROM_TERM,   4 , 4  , "contactless support"), # pboc2.0 contactless support flag
    0x9F69: (TAG_ATTR_B,   TAG_FROM_CARD,   8 , 16 , "Card Authentication Related Data"), # 卡片认证相关数据
    0x9F6C: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2  , "Card Transaction Qualifiers"), # 用于向设备指明卡片要求哪一个CVM
    0x9F6D: (TAG_ATTR_N,   TAG_FROM_CARD,   12, 12 , "EC Reset Threshold"), # eCash: Reset Threshold
    0x9F74: (TAG_ATTR_A,   TAG_FROM_CARD,   6 , 6  , "EC Issuer Authorization Code"), # EC Issuer Authorization Code
    0x9F77: (TAG_ATTR_N,   TAG_FROM_CARD,   12, 12 , "EC Balance Limit"), # EC Balance Limit
    0x9F78: (TAG_ATTR_N,   TAG_FROM_CARD,   12, 12 , "EC Single Transaction Limit"), # EC Single Transaction Limit
    0x9F79: (TAG_ATTR_N,   TAG_FROM_CARD,   12, 12 , "EC Balance"), # EC Balance
    0x9F7A: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1  , "EC Terminal Support Indicator"), # EC Terminal Support Indicator, 与卡片交互
    0x9F7B: (TAG_ATTR_N,   TAG_FROM_TERM,   12, 12 , "EC Terminal Transaction Limit"), # EC Terminal Transaction Limit
    0xA500: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 255, "FCI template"), # File Control Information(FCI) Proprietary Template
    0xBF0C: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 222, "FCI Issuer Discretionary Data"), # File Control Information(FCI) Issuer Discretionary Data
# Pboc2.0自定义Tag
    0xDF31: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 80,  "Script result"), #  Script result, 5字节一组，最多支持16个脚本标识(71&72)
# Pboc3.0 EC自定义Tag
    0xDF4D: (TAG_ATTR_B,   TAG_FROM_CARD,   2 , 2,   "Load Log Entry"), # Load Log Entry(圈存日志入口)
    0xDF4F: (TAG_ATTR_B,   TAG_FROM_CARD,   0 , 255, "Load Log Format"), # Load Log Format(圈存日志格式)
    0xDF71: (TAG_ATTR_N,   TAG_FROM_CARD,   3 , 3,   "Application second currency code"), # Application Second Currency Code(Pboc3.0 双币电子现金卡内部数据)
    0xDF79: (TAG_ATTR_N,   TAG_FROM_CARD,   12, 12,  "Second EC Balance"), # EC Balance(第二货币)
# 本核心自定义Tag
# 为防止与Pboc2.0或Emv冲突, 自定义Tag使用两字节Tag, 且第二字节的最高位设为1, 此约定限制了Tag长度不能超过2字节
    0xDF81: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 252, "Default DDOL"), # default ddol
    0xDF82: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 252, "Default TDOL"), # default tdol
    0xDF83: (TAG_ATTR_B,   TAG_FROM_TERM,   8 , 8,   "Enciphered online PIN"), # enciphered online pin
    0xDF84: (TAG_ATTR_B,   TAG_FROM_TERM,   1,  1,   "Online PIN support"), # online pin support flag, 1:支持 0:不支持
    0xDF87: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Max target percentage"), # Maximum Target Percentage to be used for Biased Random Selection
    0xDF88: (TAG_ATTR_B,   TAG_FROM_TERM,   4 , 4,   "Threshold value"), # Threshold Value for Biased Random Selection
    0xDF8A: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Target percentage"), # Target Percentage to be Used for Random
    0xDF8C: (TAG_ATTR_B,   TAG_FROM_TERM,   5 , 5,   "Tac-default"), # TAC-default
    0xDF8D: (TAG_ATTR_B,   TAG_FROM_TERM,   5 , 5,   "Tac-denial"), # TAC-denial
    0xDF8E: (TAG_ATTR_B,   TAG_FROM_TERM,   5 , 5,   "Tac-online"), # TAC-online
    0xDF90: (TAG_ATTR_A,   TAG_FROM_TERM,   2 , 2,   "Local language"), # 本地语言(操作员), ISO-639-1
    0xDF91: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Reader capability"), # 1:只支持磁卡 2:只支持IC卡 3:支持组合式Mag/IC读卡器 4:支持分离式Mag/IC读卡器
    0xDF92: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Voice referral support"), # 1:支持 2:不支持,缺省approve 3:不支持,缺省decline
    0xDF93: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Force online support"), # 1:支持 0:不支持
    0xDF94: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Force Accept support"), # 1:支持 0:不支持
    0xDF95: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Transaction log support"), # 1:终端支持交易流水记录 0:不支持
    0xDF96: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Blacklist support"), # 1:终端支持黑名单检查 0:不支持
    0xDF97: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Separate sale support"), # 1:支持分开消费检查 0:不支持
    0xDF98: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Application confirm support"), # 1:支持应用确认 0:不支持应用确认
    0xDF99: (TAG_ATTR_A,   TAG_FROM_TERM,   2 , 32,  "Pinpad language"), # ISO-639-1, Pinpad支持的语言
    0xDF9A: (TAG_ATTR_A,   TAG_FROM_TERM,   2 , 2,   "Language to be used"), # 最终使用的语言(持卡人)，iso-639-1
    0xDF9B: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1  , "EC Terminal Support Indicator"), # EC Terminal Support Indicator, 终端设置
    0xDF9C: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 255, "Pdol data block"), # PDOL数据块, CDA使用
    0xDF9D: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 255, "Cdol1 data block"), # CDOL1数据块, CDA使用
    0xDF9E: (TAG_ATTR_B,   TAG_FROM_TERM,   0 , 255, "Cdol2 data block"), # CDOL2数据块, CDA使用
    0xDF9F: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "ASI"), # 应用选择指示 0:部分名字匹配，1:全部名字匹配
    0xDFA0: (TAG_ATTR_B,   TAG_FROM_TERM,   32, 248, "CA public key modulus"), # CA公钥模数
    0xDFA1: (TAG_ATTR_B,   TAG_FROM_TERM,   1,  3,   "CA public key exponent"), # CA公钥指数
    0xDFA2: (TAG_ATTR_B,   TAG_FROM_TERM,   5,  5,   "CA public key RID"), # CA公钥所属RID
    0xDFA3: (TAG_ATTR_B,   TAG_FROM_TERM,   1,  1,   "CA public key hash algo"), # CA公钥Hash算法
    0xDFA4: (TAG_ATTR_B,   TAG_FROM_TERM,   1,  1,   "CA public key algo"), # CA公钥算法
    0xDFA5: (TAG_ATTR_N,   TAG_FROM_TERM,   8,  8,   "CA public key expire date"), # CA公钥有效期
    0xDFA6: (TAG_ATTR_B,   TAG_FROM_TERM,   20, 20,  "CA pub key hash value"), # CA公钥Hash值
    0xDFA7: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Ramdom number for biased random select"), # Ramdom number for biased random select
    0xDFA8: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "PIN bypass behavior"), # PIN bypass特性 0:每次bypass只表示该次bypass 1:一次bypass,后续都认为bypass
    0xDFAA: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "EC transaction flag"), # EC交易标志 0:非EC交易 1:EC交易 2:GPO卡片返回EC授权码,但未走EC通道
    0xDFAB: (TAG_ATTR_N,   TAG_FROM_TERM,   4 , 4  , "Native transaction type"), # 内部用交易类型, 低位等于T9C值, 高位用于区分商品/服务 IC/Mag
    0xDFAC: (TAG_ATTR_N,   TAG_FROM_TERM,   6,  6,   "EC Balance Original"), # 交易前EC余额
    0xDFE6: (TAG_ATTR_B,   TAG_FROM_TERM,   4,  4,   "Terminal Ctls Capabilities Mask"), # 终端非接能力屏蔽位, 9F66映像, 表示终端有其中相应位表示的能力
    0xDFE7: (TAG_ATTR_N,   TAG_FROM_TERM,   12, 12,  "Terminal Ctls Amount Limit"), # 终端非接交易限额
    0xDFE8: (TAG_ATTR_N,   TAG_FROM_TERM,   12, 12,  "Terminal Ctls Offline Amount Limit"), # 终端非接脱机交易限额
    0xDFE9: (TAG_ATTR_N,   TAG_FROM_TERM,   12, 12,  "Terminal Ctls CVM Limit"), # 终端非接CVM限额
    0xDFEA: (TAG_ATTR_B,   TAG_FROM_TERM,   1 , 1,   "Transaction Route"), # 交易走的路径, 0:接触Pboc(标准DC或EC) 1:非接触Pboc(标准DC或EC) 2:qPboc联机 3:qPboc脱机 4:qPboc拒绝
    0xDFF1: (TAG_ATTR_B,   TAG_FROM_ISSUER, 0,  255, "Issuer Script 71 Package"), # 71脚本包, 内存若干71脚本, 注意,不要修改Tag值, 必须为DFF1
    0xDFF2: (TAG_ATTR_B,   TAG_FROM_ISSUER, 0,  255, "Issuer Script 72 Package"), # 72脚本包, 内存若干72脚本, 注意,不要修改Tag值, 必须为DFF2
}

# function : get attribute of the Tag
# In  : psTag : tag
# Ret : TAG_ATTR_N or TAG_ATTR_CN or TAG_ATTR_B or TAG_ATTR_A or TAG_ATTR_AN or TAG_ATTR_ANS
#       or TAG_ATTR_UNKNOWN
def uiTagAttrGetType(psTag):
    uiTag = psTag[0] << 8
    if (uiTag & 0x1F00) == 0x1F00:
        uiTag += psTag[1]
    item = aTagAttr.get(uiTag, None)
    if item is None:
        return TAG_ATTR_UNKNOWN
    return item[0]


# function : get origin of the Tag
# In  : psTag : tag
# Ret : TAG_FROM_CARD or TAG_FROM_TERM or TAG_FROM_ISSUER
#       or TAG_FROM_UNKNOWN
def uiTagAttrGetFrom(psTag):
    uiTag = psTag[0] << 8
    if (uiTag & 0x1F00) == 0x1F00:
        uiTag += psTag[1]
    item = aTagAttr.get(uiTag, None)
    if item is None:
        return TAG_FROM_UNKNOWN
    return item[1]


# function : get attribute of the Tag
# In  : psTag   : tag
# Ret : Range available, 以指定的数据类型计算的范围
def uiTagAttrGetRange(psTag):
    uiTag = psTag[0] << 8
    if (uiTag & 0x1F00) == 0x1F00:
        uiTag += psTag[1]
    item = aTagAttr.get(uiTag, None)
    if item is None:
        return (0, 0)
    return (item[2], item[3])


# function : get description of the Tag
# In  : psTag : tag
# Ret : description or "UNKNOWN Tag"
def uiTagAttrGetDesc(psTag):
    uiTag = psTag[0] << 8
    if (uiTag & 0x1F00) == 0x1F00:
        uiTag += psTag[1]
    item = aTagAttr.get(uiTag, None)
    if item is None:
        return "UNKNOWN Tag"
    return item[4]


if __name__ == '__main__':
    attr_name = [
        "compacted, right aligned",
        "compacted number, left aligned",
        "binary, variable",
        "Alpha",
        "Alpha Numeric",
        "Alpha Numeric Special",
        "unknown tag"]
    from_name = [
        "来自卡片",
        "来自终端",
        "来自发卡行",
        "unknown tag"]

    print('Tag 9F03 Type: %s' % attr_name[uiTagAttrGetType(b'\x9F\x03')])
    print('Tag 9F03 From: %s' % from_name[uiTagAttrGetFrom(b'\x9F\x03')])
    print('Tag 9F03 Desc: %s' % uiTagAttrGetDesc(b'\x9F\x03'))
    print('Tag 9F03 Range: ', end='')
    print(uiTagAttrGetRange(b'\x9F\x03'))
