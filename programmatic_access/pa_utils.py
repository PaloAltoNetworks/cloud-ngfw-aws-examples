"""
This module contains utilities for CloudNGFW programmatic access
"""
import logging

# Constants
HTTP_VERB_GET = "GET"
PROGRAMMATIC_ACCESS_LOGGER = "PROG_ACC_LOGGER"
ROLE_SESSION_NAME_DEFAULT = "access_cloudngfw"


prog_acc_logger = logging.getLogger(PROGRAMMATIC_ACCESS_LOGGER)
prog_acc_logger.setLevel(logging.INFO)

logFormatter = logging.Formatter(
    fmt='%(name)s : [%(levelname)s]  %(asctime)s.%(msecs)03dZ\t%(message)s\t|- %(module)s:%(lineno)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)

streamHandler = logging.StreamHandler()
streamHandler.setFormatter(logFormatter)

prog_acc_logger.addHandler(streamHandler)

pa_logger = prog_acc_logger
