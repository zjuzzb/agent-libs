import logging
import logging.handlers

my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.DEBUG)

handler = logging.handlers.SysLogHandler(address = '/dev/log')

my_logger.addHandler(handler)

my_logger.error('root: This is an error message from ptyhon')
my_logger.warning('root: This is a warning message from ptyhon')
my_logger.debug('root: This is a debug message from ptyhon')
