# -*- coding: utf-8 -*-
from ctypes import WinDLL, CFUNCTYPE, POINTER, byref, string_at
from ctypes import c_int, c_short, c_char, c_char_p, c_ubyte, pointer
dcrf32_lib = WinDLL("bin/dcrf32.dll")
icdev = dcrf32_lib.dc_init(100, 9600)
dcrf32_lib.dc_setcpu(icdev, 0x0c)


def dc_cpureset(atr):
    atrlen = c_int(0)
    dcrf32_lib.dc_cpureset.restype = c_short
    iRet = dcrf32_lib.dc_cpureset(icdev, pointer(atrlen), atr)
    print("dc_cpureset:[%s]" % (string_at(atr, atrlen.value).hex()))
    return 1 if not iRet else 0


def dc_cpuapdu(sendlen, sendbcd, recvlen, recvbcd):
    dcrf32_lib.dc_cpuapdu.restype = c_short
    iRet = dcrf32_lib.dc_cpuapdu(icdev, sendlen, sendbcd, recvlen, recvbcd)
    print("sendbcd:[%s]; recvbcd:[%s]" % (string_at(sendbcd, sendlen).hex(), string_at(recvbcd, recvlen[0]).hex()))
    return 0 if not iRet else 1


def dc_cpudown():
    print("dc_cpudown")
    dcrf32_lib.dc_cpudown.restype = c_short
    return dcrf32_lib.dc_cpudown(icdev)


def dc_CheckCard():
    dcrf32_lib.dc_CheckCard.restype = c_short
    iRet = dcrf32_lib.dc_CheckCard(icdev)
    print("dc_CheckCard:[%d]" % iRet)
    return 1 if iRet == 30 else 0


iTestCard = CFUNCTYPE(c_int)(dc_CheckCard)
iResetCard = CFUNCTYPE(c_int, POINTER(c_ubyte))(dc_cpureset)
iCloseCard = CFUNCTYPE(c_int)(dc_cpudown)
iExchangeApdu = CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), POINTER(c_int), POINTER(c_ubyte))(dc_cpuapdu)
