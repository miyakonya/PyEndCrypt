class PyEndCryptError(Exception):
    """PyEndCrypt 所有异常的基类"""
    pass
class DataFormatError(PyEndCryptError):
    """数据格式错误异常"""
    pass
class ReplayAttackError(PyEndCryptError):
    pass
class DecryptionError(PyEndCryptError):
    pass
class PaddingError(PyEndCryptError):
    pass
class PacketTooLargeError(PyEndCryptError):
    pass
class SocketNotInitializedError(PyEndCryptError):
    pass
class ConnectionLostError(PyEndCryptError):
    pass
class HandshakeError(PyEndCryptError):
    pass
class ProvisionError(PyEndCryptError):
    pass