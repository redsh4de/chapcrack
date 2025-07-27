"""
The decrypt command. Accepts an input file, output file, and NT hash.

Parses a PPTP capture, searchers for CHAPv2 handshakes which the
supplied NT hash can decrypt, and writes the decrypted PPTP traffic
to the specified output file.
"""

import binascii
import hashlib
import sys
from dpkt import pcap

from chapcrack.commands.Command import Command
from chapcrack.readers.PppPacketReader import PppPacketReader
from chapcrack.state.PppStateManager import PppStateManager

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class DecryptCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "ionp", "")
        self.inputFile  = self._getInputFile()
        self.outputFile = self._getOutputFile()
        self.nthash     = self._getNtHash()
        self.nthash     = binascii.unhexlify(self.nthash)

    def execute(self):
        capture = open(self.inputFile, "rb")
        output  = open(self.outputFile, "wb")
        reader  = PppPacketReader(capture)
        writer  = pcap.Writer(output)
        state   = PppStateManager(self.nthash)
        count   = 0

        for packet in reader:
            decryptedPacket = state.addPacket(packet)

            if decryptedPacket:
                writer.writepkt(decryptedPacket)
                count += 1

        if count == 0:
            print("Error: No packets were decrypted. The NT hash or password may be incorrect.")
            sys.exit(1)

        print("Wrote %d packets." % count)

    def _getNtHash(self):
        nthash = self._getOptionValue("-n")
        password = self._getOptionValue("-p")

        if not nthash:
            if not password:
                self.printError("No NT hash (-n) or password (-p) specified")
            else:
                nthash = hashlib.new('md4', password.encode('utf-16le')).hexdigest().upper()

        return nthash

    def _getOutputFile(self):
        output = self._getOptionValue("-o")

        if not output:
            self.printError("No output path specified (-o)")

        return output

    @staticmethod
    def printHelp():
        print(
            """Decrypts a PPTP capture with a cracked NT hash or plaintext password.

            decrypt

            Arguments:
              -i <input>     : The capture file
              -o <output>    : The output file to write the decrypted capture to.
              -n <hash> / -p <password> : The base16-encoded cracked NT hash or plaintext password.
            """)

        sys.exit(-1)