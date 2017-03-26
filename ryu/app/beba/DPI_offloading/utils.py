import time


def nowMillisec():
    return int(time.time() * 1000)


def append32bitTimeStampToNow(timestamp):
    now = nowMillisec()
    now &= 0xFFFFFFFF00000000
    now += timestamp
    return now