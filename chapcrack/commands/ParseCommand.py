"""
The parse command.  Accepts a pcap file containing a PPTP capture.

Parses a packet capture for CHAPv2 handshakes, and prints details
of the handshake necessary for cracking.  These include the client
and server IP addresses, the username, and the plaintext/ciphertext
pairs.
"""
import base64
import sys

from chapcrack.commands.Command import Command
from chapcrack.crypto.K3Cracker import K3Cracker
from chapcrack.readers.ChapPacketReader import ChapPacketReader
from chapcrack.state.MultiChapStateManager import MultiChapStateManager

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class ParseCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "i", "n")

    def execute(self):
        inputFile  = self._getInputFile()
        handshakes = MultiChapStateManager()
        capture    = open(inputFile, "rb")
        reader     = ChapPacketReader(capture)

        for packet in reader:
            handshakes.addHandshakePacket(packet)

        complete = handshakes.getCompletedHandshakes()

        for server in complete:
            for client in complete[server]:
                handshake = complete[server][client]
                print("Got completed handshake [%s --> %s]" % (client, server))

                c1, c2, c3 = handshake.getCiphertext()
                plaintext = handshake.getPlaintext()
                username = handshake.getUserName()
                k3         = self._getK3(plaintext, c3)

                authenticator_challenge = handshake.handshake['challenge'].getChallenge()
                nt_response = handshake.getNtResponse()
                peer_challenge = handshake.handshake['response'].getPeerChallenge()

                user = username.decode() if isinstance(username, bytes) else username


                self._printParameters(username, plaintext, c1, c2, c3, k3)
                print(f"                   John The Ripper = {user}:::{authenticator_challenge.hex()}:{nt_response.hex()}:{peer_challenge.hex()}")

    def _printParameters(self, username, plaintext, c1, c2, c3, k3):
        if username is not None:
            print("                   User = %s" % username)

        print("                     C1 = %s" % c1.hex())
        print("                     C2 = %s" % c2.hex())
        print("                     C3 = %s" % c3.hex())
        print("                      P = %s" % plaintext.hex())

        if k3 is not None:
            print("                   Crack.sh Submission = $99$%s" % base64.b64encode(plaintext + c1 + c2 + k3[0:2]).decode())
            
    def _getK3(self, plaintext, ciphertext):
        if not self._containsOption("-n"):
            sys.stdout.write("Cracking K3...")
            k3 = K3Cracker().crack(plaintext, ciphertext, True)
            print()

            return k3

        return None

    @staticmethod
    def printHelp():
        print(
            """Parses a PPTP capture and prints the ciphertext/plaintext pairs and John The Ripper hash for decrypting.

              parse

            Arguments:
              -i <input> : The capture file
              -n         : If specified, doesn't crack K3
            """)
