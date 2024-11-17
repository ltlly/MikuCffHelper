from binaryninja import *

mikuLogger = Logger(0, "MikuCffHelper")


def log_info(msg):
    mikuLogger.log_info(msg)


def log_warn(msg):
    mikuLogger.log_warn(msg)


def log_error(msg):
    mikuLogger.log_error(msg)
