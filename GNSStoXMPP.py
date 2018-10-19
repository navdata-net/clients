#!/usr/bin/python -u

import sys
import optparse
import binascii
import logging
import time
import sleekxmpp

domain='navdata.net'


class RTCM3toXMPP(sleekxmpp.ClientXMPP):

  def __init__(self, name, password):
    sleekxmpp.ClientXMPP.__init__(self, name+'@'+domain, password)
    self.nick=name
    self.navdata = 'navdata@'+domain
    self.room = name+'@conference.'+domain

    self.register_plugin('xep_0045') # MUC
    self.register_plugin('xep_0231') # BOB

    self.add_event_handler("ssl_invalid_cert", self.discard)
    self.add_event_handler("session_start", self.session_start)
    self.add_event_handler("message", self.rcvMsg)


  def discard(self, event):
    return


  def session_start(self, event):
    self.send_presence()

    try:
      self.get_roster()
    except IqError as err:
      logging.error('There was an error getting the roster')
      logging.error(err.iq['error']['condition'])
      self.disconnect()
    except IqTimeout:
      logging.error('Server is taking too long to respond')
      self.disconnect()

    self.plugin['xep_0045'].joinMUC(self.room, self.nick, wait=True)


  def rcvMsg(self, msg):
    if msg['type'] in ('chat', 'normal'):
      logging.debug("Received: " + msg['body'])
      #msg.reply("Thanks for sending\n%(body)s" % msg).send()


  def xmit(self,msgbody):
    logging.debug(msgbody)
    self.send_message(mto=self.room, mbody=msgbody, mtype='groupchat')


  def xmitbin(self,msgbody,msgbinary):
    msg = self.Message()
    msg['to'] = self.room
    msg['type'] = 'groupchat'
    msg['body'] = msgbody
    msg['bob']['type'] = 'application/octet-stream'
    msg['bob']['data'] = msgbinary
    msg.send()


def bytes2int( tb, order='big'):
    seq=range(len(tb))
    if order == 'little': seq=list(reversed(seq))
    i = 0
    for j in seq: i = (i<<8)+tb[j]
    return i


def getSTDIN(nrBytes = 1):
    logging.debug("Read " + str(nrBytes) + "Byte(s)")

    try:
        STDINbyte = bytearray(sys.stdin.read(nrBytes))
    except EOFError:
        return False

    return STDINbyte


def getMessage_RTCM3():
    RTCM3_Preamble = 0xD3;
    RTCM3_First_Data_Location = 3 # Zero based
    RTCM3_Min_Size       = 6;
    RTCM3_Max_Data_Length = 4095;
    RTCM3_Max_Message_Length = RTCM3_Min_Size + RTCM3_Max_Data_Length;
    RTCM3_Length_Location = 1 # Zero Based
    data={}

    while True:
        byte_preamble = getSTDIN(1)
        if not byte_preamble : return False

        logging.debug("byte_preamble " + binascii.hexlify(byte_preamble))

        if byte_preamble[0] != RTCM3_Preamble : continue

        byte_length = bytearray(sys.stdin.read(2))
        MSG_LENGTH = bytes2int(byte_length)
        logging.debug("MSG_LENGTH " + str(MSG_LENGTH))

        if MSG_LENGTH > RTCM3_Max_Data_Length : continue

        byte_header = bytearray(sys.stdin.read(3))
        data["MSG_ID"]=(byte_header[0] << 4) + (byte_header[1] >> 4)
        logging.debug("Message ID " + str(data["MSG_ID"]))

        data["MSG_StationID"]=((byte_header[1] & 0x0F) << 8) + (byte_header[2])
        logging.debug("Station ID " + str(data["MSG_StationID"]))

        byte_header[1] = byte_header[1] & 0xF0
        byte_header[2] = 0x00

        byte_data = bytearray(sys.stdin.read(MSG_LENGTH))
        logging.debug("Message " + binascii.hexlify(byte_data))
        data["MSG"] = byte_data
        data["RAW"] = byte_preamble + byte_length + byte_header + byte_data
        return data


def getMessage_UBX():
    UBX_Preamble1 = 0xB5
    UBX_Preamble2 = 0x62
    data={}

    while True:
        byte_preamble1 = getSTDIN(1)
        if not byte_preamble1 : return False

        logging.debug("byte_preamble1 " + binascii.hexlify(byte_preamble1))

        if byte_preamble1[0] != UBX_Preamble1 : continue

        byte_preamble2 = getSTDIN(1)
        if not byte_preamble2 : return False

        logging.debug("byte_preamble2 " + binascii.hexlify(byte_preamble2))

        if byte_preamble2[0] != UBX_Preamble2 : continue

        byte_msg = getSTDIN(2)
        if not byte_msg : return False
        [data["MSG_CLASS"],data["MSG_ID"]] = byte_msg
        logging.debug("Message Class " + str(data["MSG_CLASS"]))
        logging.debug("Message ID " + str(data["MSG_ID"]))

        byte_length = getSTDIN(2)
        if not byte_length : return False
        MSG_LENGTH = bytes2int(byte_length,order='little')
        logging.debug("MSG_LENGTH " + str(MSG_LENGTH))

        byte_data = bytearray(sys.stdin.read(MSG_LENGTH))
        logging.debug("Message " + binascii.hexlify(byte_data))

        byte_chksum = bytearray(sys.stdin.read(2))
        logging.debug("Checksum " + binascii.hexlify(byte_chksum))
        data["MSG"] = byte_data
        data["RAW"] = byte_preamble1 + byte_preamble2 + byte_msg + byte_length + byte_data + byte_chksum
        return data


if __name__ == "__main__":
  parser = optparse.OptionParser()
  parser.add_option("-u", "--user", type="string", dest="user", default="anonymous", help="XMPP logon user name (without domain)")
  parser.add_option("-p", "--password", type="string", dest="pwd", default="anonymous", help="XMPP logon password")
  parser.add_option("-f", "--format", type="string", dest="fmt", default="rtcm3", help="GNSS message format")
  parser.add_option("-d", "--debug", action="store_true", dest="dbg", help="enable debug mode")
  parser.add_option("-n", "--nosending", action="store_true", dest="noxmit", help="dont send messages")

  (options, args) = parser.parse_args()

  if options.dbg:
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')

  logging.debug("Startup user: "+options.user+" pwd: "+options.pwd)
  if not options.noxmit: xmpp = RTCM3toXMPP(options.user, options.pwd)
  if not options.noxmit: xmpp.connect(address=('xmpp.'+domain,5222))
  if not options.noxmit: xmpp.process()
  #last=time.now()
  delta=0

  while True:
    if options.fmt == "rtcm3": GNSSmsg = getMessage_RTCM3()
    elif options.fmt == "ubx": GNSSmsg = getMessage_UBX()
    else:
      logging.error("Unknow message format specified in options.")
      break

    logging.info("Sending messge:\n" + str(GNSSmsg["MSG_ID"]) + ':' + binascii.hexlify(GNSSmsg["RAW"]))
    if not options.noxmit: xmpp.xmitbin(str(GNSSmsg["MSG_ID"]),GNSSmsg["RAW"])

