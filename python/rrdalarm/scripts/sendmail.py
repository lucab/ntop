# coding: utf-8
###############################################################################
# user configuration settings for various email programs (pymail version);
# email scripts get their server names and other email config options from
# this module: change me to reflect your machine names, sig, and preferences;
###############################################################################
import sys
#------------------------------------------------------------------------------
# (required for send) SMTP email server machine name
# see Python smtpd module for a SMTP server class to run locally;
# note: your ISP may require that you be directly connected to their system:
# I can email through Earthlink on dial-up, but cannot via Comcast cable
#------------------------------------------------------------------------------
smtpservername = ''     #REMEBER TO SET THIS PARAMETER TO YOUR LINKING es. 'smtp.mindspring.com', 'localhost'

#------------------------------------------------------------------------------
# (may be required for send) SMTP user/password if authenticated
# set user to None or '' if no login/authentication is required
# set pswd to name of a file holding your SMTP password, or an
# empty string to force programs to ask (in a console, or GUI)
#------------------------------------------------------------------------------

#smtpuser  = ''                           # per your ISP
#smtppasswdfile  = ''                       # set to '' to be asked

###############################################################################
# send messages, add attachments (see __init__ for docs, test)
###############################################################################

#import mailconfig                                       # client's mailconfig
import smtplib, os, mimetypes                              # mime: name to type
import email.Encoders                                    # date string, base64   email.utils,

from email.Message       import Message                # general message
from email.MIMEMultipart import MIMEMultipart          # type-specific messages
from email.MIMEAudio     import MIMEAudio
from email.MIMEImage     import MIMEImage
from email.MIMEText      import MIMEText
from email.MIMEBase      import MIMEBase

class MailSender(object):
    """
    send mail: format message, interface with SMTP server
    works on any machine with Python+Inet, doesn't use cmdline mail
    a nonauthenticating client: see MailSenderAuth if login required
    """
    global smtpservername, myaddress, mysignature, smtpuser, smtppasswdfile
    
    def __init__(self, smtpserver=None):
        self.smtpServerName  = smtpserver or smtpservername

    def sendMessage(self, From, To, Subj, extrahdrs, bodytext, attaches,
                                            saveMailSeparator=(('='*80)+'PY\n')):
        """
        format,send mail: blocks caller, thread me in a GUI
        bodytext is main text part, attaches is list of filenames
        extrahdrs is list of (name, value) tuples to be added
        raises uncaught exception if send fails for any reason
        saves sent message text in a local file if successful

        assumes that To, Cc, Bcc hdr values are lists of 1 or more already
        stripped addresses (possibly in full name+<addr> format); client
        must split these on delimiters, parse, or use multiline input;
        note that SMTP allows full name+<addr> format in recipients
        """
        if not attaches:
            msg = Message( )
            msg.set_payload(bodytext)
        else:
            msg = MIMEMultipart( )
            self.addAttachments(msg, bodytext, attaches)

        recip = To.split(',')
        msg['From']    = From
        msg['To']      = To#', '.join(To)              # poss many: addr list
        msg['Subject'] = Subj                       # servers reject ';' sept
        msg['Date']    = email.Utils.formatdate( )      # curr datetime, rfc2822 utc
        for name, value in extrahdrs:               # Cc, Bcc, X-Mailer, etc.
            if value:
                if name.lower( ) not in ['cc', 'bcc']:
                    msg[name] = value
                else:
                    msg[name] = ', '.join(value)     # add commas between
                    recip += value                   # some servers reject ['']
        fullText = msg.as_string( )                  # generate formatted msg

        # sendmail call raises except if all Tos failed,
        # or returns failed Tos dict for any that failed

        print>>sys.stderr,'Sending to...'+ str(recip)
        #print>>sys.stderr,fullText[:256]
        server = smtplib.SMTP(self.smtpServerName,timeout=10) #lib.SMTP(self.smtpServerName)           # this may fail too
        #self.getPassword( )                                       # if srvr requires
        #self.authenticateServer(server)                      # login in subclass
        try:
            failed = server.sendmail(From, recip, fullText)  # except or dict
        finally:
            server.quit( )                                    # iff connect OK
        if failed:
            class SomeAddrsFailed(Exception): pass
            raise SomeAddrsFailed('Failed addrs:%s\n' % failed)
        #self.saveSentMessage(fullText, saveMailSeparator)
        print>>sys.stderr,'Send exit'

    def addAttachments(self, mainmsg, bodytext, attaches):
        # format a multipart message with attachments
        msg = MIMEText(bodytext)                 # add main text/plain part
        mainmsg.attach(msg)
        for filename in attaches:                # absolute or relative paths
            if not os.path.isfile(filename):     # skip dirs, etc.
                continue

            # guess content type from file extension, ignore encoding
            contype, encoding = mimetypes.guess_type(filename)
            if contype is None or encoding is not None:  # no guess, compressed?
                contype = 'application/octet-stream'     # use generic default
            print>>sys.stderr,'Adding ' + contype

            # build sub-Message of appropriate kind
            maintype, subtype = contype.split('/', 1)
            if maintype == 'text':
                data = open(filename, 'r')
                msg  = MIMEText(data.read( ), _subtype=subtype)
                data.close( )
            elif maintype == 'image':
                data = open(filename, 'rb')
                msg  = MIMEImage(data.read( ), _subtype=subtype)
                data.close( )
            elif maintype == 'audio':
                data = open(filename, 'rb')
                msg  = MIMEAudio(data.read( ), _subtype=subtype)
                data.close( )
            else:
                data = open(filename, 'rb')
                msg  = MIMEBase(maintype, subtype)
                msg.set_payload(data.read( ))
                data.close( )                            # make generic type
                email.Encoders.encode_base64(msg)         # encode using base64

            # set filename and attach to container
            basename = os.path.basename(filename)
            msg.add_header('Content-Disposition',
                           'attachment', filename=basename)
            mainmsg.attach(msg)

        # text outside mime structure, seen by non-MIME mail readers
        mainmsg.preamble = 'A multi-part MIME format message.\n'
        mainmsg.epilogue = ''  # make sure message ends with a newline
'''
    def saveSentMessage(self, fullText, saveMailSeparator):
        # append sent message to local file if worked
        # client: pass separator used for your app, splits
        # caveat: user may change file at same time (unlikely)
        try:
            sentfile = open(self.sentmailfile, 'a')
            if fullText[-1] != '\n': fullText += '\n'
            sentfile.write(saveMailSeparator)
            sentfile.write(fullText)
            sentfile.close( )
        except:
            print>>sys.stderr,'Could not save sent message'    # not a show-stopper

    def authenticateServer(self, server):
        pass  # no login required for this server/class

    def getPassword(self):
        pass  # no login required for this server/class


################################################################################
# specialized subclasses
################################################################################

class MailSenderAuth(MailSender):
    """
    use for servers that require login authorization;
    client: choose MailSender or MailSenderAuth super
    class based on mailconfig.smtpuser setting (None?)
    """
    def __init__(self, smtpserver=None, smtpuser=None):
        MailSender.__init__(self, smtpserver)
        self.smtpUser = smtpuser or self.smtpuser
        self.smtpPassword = None

    def authenticateServer(self, server):
        server.login(self.smtpUser, self.smtpPassword)

    def getPassword(self):
        """
        get SMTP auth password if not yet known;
        may be called by superclass auto, or client manual:
        not needed until send, but don't run in GUI thread;
        get from client-side file or subclass method
        """
        if not self.smtpPassword:
            try:
                localfile = open(self.smtppasswdfile)
                self.smtpPassword = localfile.readline( )[:-1]
                print>>sys.stderr,'local file password' + repr(self.smtpPassword)
            except:
                self.smtpPassword = self.askSmtpPassword( )

    def askSmtpPassword(self):
        assert False, 'Subclass must define method'

class MailSenderAuthConsole(MailSender):
    def askSmtpPassword(self):
        import getpass
        prompt = 'Password for %s on %s?' % (self.smtpUser, self.smtpServerName)
        return getpass.getpass(prompt)
'''
def main( ):
    import socket
    print>>sys.stderr, '[Pymail email client]'
    if len(sys.argv)!=5 or sys.argv[1]!= '-p' or not sys.argv[2] or sys.argv[3]!= '-t' or not sys.argv[4]:
        print>>sys.stderr, 'USAGE %s -p <parameter> -t "<text>"' % sys.argv[0]
    else:
        sender = MailSender()
            
        try:
            From='rrdAlarm@noreply.org'
            To=sys.argv[2]
            
            Subj='RRDALARM Report: %s' % socket.gethostname()
            text=sys.argv[4]
            sender.sendMessage(From, To, Subj, [], text, attaches=None)
        except:
            raise
            print>>sys.stderr, 'Error - mail not sent'
        
'''The script starts here'''
main( )





