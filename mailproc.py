import email
import sys
import os
import re
import fcntl
import quopri

import config

def check(msg, keyfile):
    if msg.is_multipart():
        # we have to go deeper!
        if msg.get_content_subtype() != 'signed':
            for sub in msg.get_payload():
                x = check(sub, keyfile)
                if x is not False:
                    return x
            print >> sys.stderr, "error, no signed data found"
            return False

        # this is a signed subtype thing
        if msg.get_payload(0).get_content_maintype() != 'text':
            print >> sys.stderr, "error, expected text got", msg.get_payload(0).get_content_subtype()
            return False

        if msg.get_payload(1).get_content_subtype() != 'pgp-signature':
            print >> sys.stderr, "error, expected pgp-signature"
            return False

        # aight we have a proper file here
        text = str(msg.get_payload(0)).split("\n", 1)[1]
        sig = msg.get_payload(1).get_payload()
        state = None

        # if there is a +1 on a singular line
        if re.search('^\+1\s$', text.strip(), re.MULTILINE):
            state = +1
        elif re.search('^\-1\s$', text.strip(), re.MULTILINE):
            state = -1
        elif re.search('^\~0\s$', text.strip(), re.MULTILINE):
            state = 0

        # only verify if we have some kind of result
        if state is None:
            return (text, sig, None, False)

        lockfile = open("/tmp/verifying.lock", "w")
        fcntl.lockf(lockfile, fcntl.LOCK_EX)
        file(os.path.join(config.datadir, "mail_text"), "w+").write(text)
        file(os.path.join(config.datadir, "mail_sig"), "w+").write(sig)
        # todo shellescape()
        verified = os.system("gpgv --keyring {} mail_sig mail_text 2> /dev/null".format(keyfile)) == 0
        os.unlink(os.path.join(config.datadir, "mail_text"))
        os.unlink(os.path.join(config.datadir, "mail_sig"))
        fcntl.lockf(lockfile, fcntl.LOCK_UN)
        os.unlink("verifying.lock")

        return (text, sig, state, verified)

    # not multipart? try to parse as plaintext, then
    else:
        # this is a signed subtype thing
        if msg.get_content_maintype() != 'text' or msg.get_content_subtype() != 'plain':
            print >> sys.stderr, "error, expected text/plain got", msg.get_content_subtype(), '/', msg.get_content_subtype()
            return False

        # aight we have a proper text here
        text = msg.get_payload(decode=True)
        text = text.decode(msg.get_content_charset('utf-8'))

        state = None

        # if there is a +1 on a singular line
        if re.search('^\+1$', text, re.MULTILINE):
            state = +1
        elif re.search('^\-1$', text, re.MULTILINE):
            state = -1
        elif re.search('^\~0$', text, re.MULTILINE):
            state = 0

        # only verify if we have some kind of result
        if state is None:
            return False

        lockfile = open("verifying.lock", "w")
        fcntl.lockf(lockfile, fcntl.LOCK_EX)
        file("mail_text", "w").write(text.encode(msg.get_content_charset('utf-8')))
        # todo shellescape()
        verified = os.system("gpgv --keyring {} mail_text 2> /dev/null".format(keyfile)) == 0
        # stupid hack, check out test larsan & chrissi cleartext test cases :(
        if not verified:
            file("mail_text", "w").write(text.encode(sys.stdout.encoding))
            verified = os.system("gpgv --keyring {} mail_text 2> /dev/null".format(keyfile)) == 0
        os.unlink("mail_text")
        fcntl.lockf(lockfile, fcntl.LOCK_UN)
        os.unlink("verifying.lock")

        return (text, '', state, verified)

    return False

if __name__ == "__main__":

    # data = file("test/chrissitest").read()
    data = file("test/1398164079.M658267P22090V0000000000000803I00000000000C40BE.mail.mugenguild.com:2,S").read()
    mail = email.message_from_string(data)

    print check(mail, "keys/larsan.gpg")

