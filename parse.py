#!/usr/bin/python2
import sys
import email
import email.parser
from email.mime.text import MIMEText
import smtplib
import logging
import logging.handlers
import time
import re
import os
import subprocess
import ConfigParser


## TODO
## - reformat to look better
## - less confusing names 'SpamLogger' even for whitelist
## - code reuse
## instructions for setup (mail forwarding, script execution, etc.)

scriptdir = '/etc/postfix/mailscript'
## postfix runs as nobody user, which cant do shell things apparently
#scriptdir = os.getcwd()

logger = logging.getLogger('SpamLogger')
handler = logging.handlers.SysLogHandler(address='/dev/log')
CONFIG = ConfigParser.ConfigParser()

logger.setLevel(logging.INFO)
logger.addHandler(handler)

CONFIG.read(scriptdir + '/config.ini')

def ConfigSectionMap(section):
    dict1 = {}
    options = CONFIG.options(section)
    for option in options:
        try:
            dict1[option] = CONFIG.get(section, option)
        except:
            dict1[option] = None
    return dict1

server = ConfigSectionMap("Mail")['server']
blacklist = ConfigSectionMap("Mail")['blacklist']

send_as = ConfigSectionMap("Identity")['sendas']
reply_to = ConfigSectionMap("Identity")['replyto']
allowed_from = ConfigSectionMap("Identity")['allowedfrom']
alert_on = ConfigSectionMap("Identity")['alerton']

block = ConfigSectionMap("Logging")['block']
stats = ConfigSectionMap("Logging")['stats']

logstr = ""
ret = ""
def logprint(msg):
    global logstr
    logger.info(msg)
    logstr += msg + "\n"
    with open(block, "a") as logfile:
            logfile.write(msg+"\n")

def sendlog(toaddr, subj):
    reply = MIMEText(logstr, 'plain')
    reply['Subject'] = subj
    reply['From'] = reply_to
    reply['To'] = toaddr
    s = smtplib.SMTP(server)
    s.sendmail(send_as, toaddr, reply.as_string())
    s.quit()
	

logprint("SpamLogger: Started")

parser = email.parser.Parser()
msg = parser.parse(sys.stdin, headersonly=False)

report_from = msg['Return-Path'].lower()
report_to = msg['To'].split('@')[0].lower()

## TODO validate by IP? MTA IP?
ok_paths = allowed_from.split(',')
if report_from in ok_paths:
    if report_to == 'spam':
        logprint("SpamLogger: Parsing Email for Blacklist...")
        spam = msg.get_payload()[-1]  # load (last) attachment
        if spam.is_multipart():
            spam = spam.get_payload()[0]  # load first part (might be plaintext/html)
        else:
            spam = parser.parsestr(spam.get_payload(decode=True))  # decode if needed
        addr = spam['Return-Path']

        if addr is None:
            logprint("SpamLogger: Error Parsing Email (couldn't find email to blacklist).")
            logprint("SpamLogger: Quitting.")
            sendlog(report_from, "Blacklisting Failure")
            sys.exit()

        addr = addr.lower()[1:-1]

        for alert_str in alert_on.split(','):
            if alert_str in addr:
                logprint("SpamLogger: Are you sure you want to blacklist: {}? If so, ask mail server admin.".format(addr))
                logprint("SpamLogger: Quitting.")
                sendlog(report_from, "Blacklisting Failure")
                sys.exit()

        with open(blacklist, "a") as spamfile:
            spamfile.write("header BLOCK_RETURN Return-Path =~ /{}/\n".format(re.escape(addr)))
            spamfile.write("score BLOCK_RETURN 100\n")
            spamfile.write("describe BLOCK_RETURN auto-added by {} on {}\n".format(report_from, time.strftime("%a, %d %b %Y %H:%M:%S")))
            logprint("SpamLogger: Added <{}> to blacklist".format(addr))

        try:
            ret = subprocess.check_output(["spamassassin", "--lint"])
        except subprocess.CalledProcessError:
            logprint("SpamLogger: SpamAssassin lint error!  Something went wrong!")
            logstr += "\n\n" + ret + "\n\n"
            logprint("SpamLogger: Quitting.")
            sendlog(report_from, "Blacklisting Failure")
            sys.exit()

        logprint("SpamLogger: SpamAssassin lint passed.")

        logprint("SpamLogger: <{}> successfully blacklisted!".format(addr))
        logprint("SpamLogger: Quitting.")

        # insert stats here
        #logwatch --detail Med --service amavis --format text --range 'between -7 days and -1 days' | pcregrep -M '(?s)\d+\s+Spam blocked \-.+?\n\s+\n'
        stats = open(stats, "r").read()
        m = re.search(r"\d+\s+Spam blocked \-.+?\n(.+?)\n\s+\n", stats, re.DOTALL)
        ext = m.group(1)
        mail = report_from[1:-1]
        m2 = re.search(r".+?(\d+).+?" + mail, ext)
        if m2 is None:
            logstr += "\n\nBlocked {} spam mails to {} in the past 7 days.".format(0, report_from)
        else:
            numspam = m2.group(1)
            logstr += "\n\nBlocked {} spam mails to {} in the past 7 days.".format(numspam, report_from)

        sendlog(report_from, "Blacklisting Success")
    elif report_to == 'whitelist':
        logprint("SpamLogger: Parsing Email for Whitelist...")
        ham = msg.get_payload()[-1]
        if ham.is_multipart():
            ham = ham.get_payload()[0]
        else:
            ham = parser.parsestr(ham.get_payload(decode=True))
        addr = ham['From']  # spamassassin only checks 'From' when whitelisting not 'Return-Path'

        if addr is None:
            logprint("SpamLogger: Error Parsing Email (couldn't find email to whitelist).")
            logprint("SpamLogger: Quitting.")
            sendlog(report_from, "Whitelisting Failure")
            sys.exit()

        addr = addr.lower()[1:-1]

        with open(blacklist, "a") as spamfile:
            spamfile.write("whitelist_from {}  # auto-added by {} on {}\n".format(re.escape(addr), report_from, time.strftime("%a, %d %b %Y %H:%M:%S")))
            logprint("SpamLogger: Added <{}> to whitelist".format(addr))

        try:
            ret = subprocess.check_output(["spamassassin", "--lint"])
        except subprocess.CalledProcessError:
            logprint("SpamLogger: SpamAssassin lint error!  Something went wrong!")
            logstr += "\n\n" + ret + "\n\n"
            logprint("SpamLogger: Quitting.")
            sendlog(report_from, "Whitelisting Failure")
            sys.exit()

        logprint("SpamLogger: SpamAssassin lint passed.")

        logprint("SpamLogger: <{}> successfully whitelisted!".format(addr))
        logprint("SpamLogger: Quitting.")
        sendlog(report_from, "Whitelisting Success")
    else:
        logger.info("SpamLogger: Invalid Recipient ({})".format(msg['To']))
else:
    logger.info("SpamLogger: Invalid Sender ({})".format(msg['Return-Path']))
