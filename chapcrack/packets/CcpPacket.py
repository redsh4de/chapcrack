"""
A class to encapsulate and parse a PPP Compression Control packet.
"""

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class CcpPacket:

    def __init__(self, data, sourceIp, destinationIp):
        self.data          = data
        self.sourceIp      = sourceIp
        self.destinationIp = destinationIp

    def isConfigurationRequest(self):
        return self.data[0] == 1

    def isConfigurationAck(self):
        return self.data[0] == 2

    def isConfigurationNack(self):
        return self.data[0] == 3

    def isStateless(self):
        return self.data[6] & 0x01 > 0

    def is128bit(self):
        return self.data[9] == 0x40

    def getSourceAddress(self):
        return self.sourceIp

    def getDestinationAddress(self):
        return self.destinationIp
