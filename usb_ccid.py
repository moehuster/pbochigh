# -*- coding: utf-8 -*-
from ctypes import WinDLL, CFUNCTYPE, POINTER, cast, string_at
from ctypes import c_int, c_short, c_char, c_char_p, c_ubyte, pointer
CCID_LIB = WinDLL("bin/ccid_lib.dll")


def PowerOn(atr):
    atrlen = c_int(0)
    iRet = CCID_LIB.PowerOn(2, atr, pointer(atrlen))
    print("PowerOn:[%s]" % (string_at(atr, atrlen.value).hex()))
    return 1 if not iRet else 0


def Apdu(sendlen, sendbcd, recvlen, recvbcd):
    iRet = CCID_LIB.Apdu(2, sendbcd, sendlen, recvbcd, recvlen)
    print("sendbcd:[%s]; recvbcd:[%s]" % (string_at(sendbcd, sendlen).hex(), string_at(recvbcd, recvlen[0]).hex()))
    return iRet


def PowerOff():
    print("PowerOff")
    return CCID_LIB.PowerOff(2)


def GetCardStatus():
    iRet = (0x20 & CCID_LIB.GetCardStatus(2))
    print("GetCardStatus:[%d]" % iRet)
    return 0 if not iRet else 1


iTestCard = CFUNCTYPE(c_int)(GetCardStatus)
iResetCard = CFUNCTYPE(c_int, POINTER(c_ubyte))(PowerOn)
iCloseCard = CFUNCTYPE(c_int)(PowerOff)
iExchangeApdu = CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), POINTER(c_int), POINTER(c_ubyte))(Apdu)
