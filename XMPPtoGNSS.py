#!/usr/bin/python -u

import sys
import optparse
import logging
import sleekxmpp
import binascii


domain='navdata.net'


class XMPPtoGNSS(sleekxmpp.ClientXMPP):

  def __init__(self, name, password, source, sid):
    sleekxmpp.ClientXMPP.__init__(self, name+'@'+domain, password)
    self.use_signals(signals=['SIGHUP', 'SIGTERM', 'SIGINT'])
    self.nick = name
    self.recipient = 'admin@navdata.net'
    self.navdata = 'navdata@'+domain
    self.room = source+'@conference.'+domain
    self.stationHI = sid >> 4
    self.stationLO = sid & 0xFF
    logging.debug(self.stationLO)

    self.register_plugin('xep_0045') # MUC
    self.register_plugin('xep_0231') # BOB
    
    self.add_event_handler("ssl_invalid_cert", self.discard)
    self.add_event_handler("session_start", self.session_start)
    self.add_event_handler("message", self.rcvMessage)


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


  def rcvMessage(self, msg):
    if msg['type'] in ('chat', 'normal'):
      logging.debug("Body " + msg['body'])
      #msg.reply("Thanks for sending\n%(body)s" % msg).send()
      #if msg['bob']['data']:

    if msg['type'] in ('groupchat'):
      if msg['bob']['data']:
        data = bytearray(msg['bob']['data'])
        logging.debug (str(data[0]))
        logging.debug ("In Binary " + binascii.hexlify(data))
        logging.debug (str(data[5]))
        data[4] = data[4] | self.stationHI
        data[5] = data[5] | self.stationLO
        logging.debug (str(data[5]))
        logging.debug("Out Binary " + binascii.hexlify(data))
        try:
          sys.stdout.write(data)
        except:
          logging.error("Error sending data to STDOUT.")
          self.disconnect()
          return
        sys.stdout.flush()



if __name__ == '__main__':
  parser = optparse.OptionParser()
  parser.add_option("-u", "--user", type="string", dest="user", default="anonymous", help="XMPP logon user name (without domain)")
  parser.add_option("-p", "--password", type="string", dest="pwd", default="anonymous", help="XMPP logon password")
  parser.add_option("-c", "--channel", type="string", dest="muc", default="navdata-0", help="XMPP muc channel")
  parser.add_option("-s", "--station", type="int", dest="sid", default="0", help="RTCM station ID")
  parser.add_option("-d", "--debug", action="store_true", dest="dbg", help="enable debug mode")
  (options, args) = parser.parse_args()

  if options.dbg:
      logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')

  if (options.sid > 4095) :
    logging.error("Error: Max station ID 4095")
    sys.exit()

  logging.debug("Startup user: "+options.user+" pwd: "+options.pwd)
  logging.debug("Broadcast channel: "+options.muc)
  logging.debug("Station ID: "+str(options.sid))
  xmpp = XMPPtoGNSS(options.user, options.pwd, options.muc, options.sid)
  if xmpp.connect(address=('xmpp.'+domain,5222)):
    xmpp.process(block=True)

