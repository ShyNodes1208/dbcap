"""MySQL protocol decoder stub."""

from dbcap.protocols.base import ProtocolDecoder


class MysqlDecoder(ProtocolDecoder):
    name = "mysql"
