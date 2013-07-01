#!/usr/bin/env python
import uuid
import pprint
import cups
import hashlib
import time
import urllib2
import tempfile
import shutil
import os
import json
import stat
import sys
import getopt
import requests
import logging
import logging.handlers
import requests_oauth2


SOURCE = 'Armooo-PrintProxy-1'
PRINT_CLOUD_SERVICE_ID = 'cloudprint'
CLIENT_LOGIN_URL = '/accounts/ClientLogin'
PRINT_CLOUD_URL = 'https://www.google.com/cloudprint/'

LOGGER = logging.getLogger('cloudprint')
LOGGER.setLevel(logging.INFO)


CLIENT_ID = '607830223128-rqenc3ekjln2qi4m4ntudskhnsqn82gn.apps.googleusercontent.com'
CLIENT_KEY = 'T0azsx2lqDztSRyPHQaERJJH'


class CloudPrintAuth(object):
    def __init__(self, auth_path):
        self.auth_path = auth_path
        self.guid = None
        self.email = None
        self.xmpp_jid = None
        self.refresh_token = None
        self.access_token = None
        self.oauth2_handler = requests_oauth2.OAuth2(
            CLIENT_ID,
            CLIENT_KEY,
            'https://accounts.google.com',
            'oob',
            token_url='/o/oauth2/token',
        )

    @property
    def session(self):
        s = requests.session()
        s.params['access_token'] = self.access_token
        s.headers['X-CloudPrint-Proxy'] = 'ArmoooIsAnOEM'
        return s

    def no_auth(self):
        return not os.path.exists(self.auth_path)

    def login(self, name, description, ppd):
        self.guid = str(uuid.uuid4())
        reg_data = requests.post(
            PRINT_CLOUD_URL + 'register',
            {
                'output': 'json',
                'printer': name,
                'proxy':  self.guid,
                'capabilities': ppd.encode('utf-8'),
                'defaults': ppd.encode('utf-8'),
                'status': 'OK',
                'description': description,
                'capsHash': hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
            },
            headers={'X-CloudPrint-Proxy': 'ArmoooIsAnOEM'},
        ).json()
        print 'Goto {} to clame this printer'.format(reg_data['complete_invite_url'])

        end = time.time() + int(reg_data['token_duration'])
        while time.time() < end:
            time.sleep(10)
            print 'trying for the win'
            poll = requests.get(
                reg_data['polling_url'] + CLIENT_ID,
                headers={'X-CloudPrint-Proxy': 'ArmoooIsAnOEM'},
            ).json()
            if poll['success']:
                break
        else:
            print 'The login request timedout'

        pprint.pprint(poll)
        self.xmpp_jid = poll['xmpp_jid']
        self.email = poll['user_email']

        token = self.oauth2_handler.get_token(
            poll['authorization_code'],
            grant_type='authorization_code',
            scope='https://www.googleapis.com/auth/cloudprint',
        )

        self.access_token = token['access_token']
        self.refresh_token = token['refresh_token']

        self.save()

    def load(self):
        if os.path.exists(self.auth_path):
            with open(self.auth_path) as auth_file:
                auth_data = json.load(auth_file)
            self.guid = auth_data['guid']
            self.xmpp_jid = auth_data['xmpp_jid']
            self.email = auth_data['email']
            self.refresh_token = auth_data['refresh_token']
            self.access_token = auth_data['access_token']

    def delete(self):
        if os.path.exists(self.auth_path):
            os.unlink(self.auth_path)

    def save(self):
            if not os.path.exists(self.auth_path):
                with open(self.auth_path, 'w') as auth_file:
                    os.chmod(self.auth_path, stat.S_IRUSR | stat.S_IWUSR)
            with open(self.auth_path, 'w') as auth_file:
                json.dump({
                    'guid':  self.guid,
                    'email': self.email,
                    'xmpp_jid': self.xmpp_jid,
                    'refresh_token': self.refresh_token,
                    'access_token': self.access_token,
                    },
                    auth_file
                )


class CloudPrintProxy(object):

    def __init__(self, auth, verbose=True):
        self.auth = auth
        self.verbose = verbose

    def get_printers(self):
        printers = self.auth.session.post(
            PRINT_CLOUD_URL + 'list',
            {
                'output': 'json',
                'proxy': self.auth.guid,
            },
            params={'access_token': self.auth.access_token},
        ).json()
        return [PrinterProxy(self, p['id'], p['name']) for p in printers['printers']]

    def delete_printer(self, printer_id):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'delete',
            {
                'output': 'json',
                'printerid': printer_id,
           },
        )
        if self.verbose:
            LOGGER.info('Deleted printer ' + printer_id)

    def add_printer(self, name, description, ppd):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'register',
            {
                'output': 'json',
                'printer': name,
                'proxy':  self.auth.guid,
                'capabilities': ppd.encode('utf-8'),
                'defaults': ppd.encode('utf-8'),
                'status': 'OK',
                'description': description,
                'capsHash': hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
           },
        )
        if self.verbose:
            LOGGER.info('Added Printer ' + name)

    def update_printer(self, printer_id, name, description, ppd):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'update',
            {
                'output': 'json',
                'printerid': printer_id,
                'printer': name,
                'proxy': self.auth.guid,
                'capabilities': ppd.encode('utf-8'),
                'defaults': ppd.encode('utf-8'),
                'status': 'OK',
                'description': description,
                'capsHash': hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
           },
        )
        if self.verbose:
            LOGGER.info('Updated Printer ' + name)

    def get_jobs(self, printer_id):
        docs = self.auth.session.post(
            PRINT_CLOUD_URL + 'fetch',
            {
                'output': 'json',
                'printerid': printer_id,
           },
        ).json()

        if not 'jobs' in docs:
            return []
        else:
            return docs['jobs']

    def finish_job(self, job_id):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'control',
            {
                'output': 'json',
                'jobid': job_id,
                'status': 'DONE',
           },
        )

    def fail_job(self, job_id):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'control',
            {
                'output': 'json',
                'jobid': job_id,
                'status': 'ERROR',
           },
        )


class PrinterProxy(object):
    def __init__(self, cpp, printer_id, name):
        self.cpp = cpp
        self.id = printer_id
        self.name = name

    def get_jobs(self):
        return self.cpp.get_jobs(self.id)

    def update(self, description, ppd):
        return self.cpp.update_printer(self.id, self.name, description, ppd)

    def delete(self):
        return self.cpp.delete_printer(self.id)


class App(object):
    def __init__(self, cups_connection=None, cpp=None, printers=None, pidfile_path=None):
        self.cups_connection = cups_connection
        self.cpp = cpp
        self.printers = printers
        self.pidfile_path = pidfile_path
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_timeout = 5

    def run(self):
        process_jobs(self.cups_connection, self.cpp, self.printers)


def get_printer_info(cups_connection, printer_name):
        with open(cups_connection.getPPD(printer_name)) as ppd_file:
            ppd = ppd_file.read()
        #This is bad it should use the LanguageEncoding in the PPD
        #But a lot of utf-8 PPDs seem to say they are ISOLatin1
        ppd = ppd.decode('utf-8')
        description = cups_connection.getPrinterAttributes(printer_name)['printer-info']
        return ppd, description


def sync_printers(cups_connection, cpp):
    local_printer_names = set(cups_connection.getPrinters().keys())
    remote_printers = dict([(p.name, p) for p in cpp.get_printers()])
    remote_printer_names = set(remote_printers)

    #New printers
    for printer_name in local_printer_names - remote_printer_names:
        try:
            ppd, description = get_printer_info(cups_connection, printer_name)
            cpp.add_printer(printer_name, description, ppd)
        except (cups.IPPError, UnicodeDecodeError):
            LOGGER.info('Skipping ' + printer_name)

    #Existing printers
    for printer_name in local_printer_names & remote_printer_names:
        ppd, description = get_printer_info(cups_connection, printer_name)
        remote_printers[printer_name].update(description, ppd)

    #Printers that have left us
    for printer_name in remote_printer_names - local_printer_names:
        remote_printers[printer_name].delete()


def process_job(cups_connection, cpp, printer, job):
    request = urllib2.Request(job['fileUrl'], headers={
        'X-CloudPrint-Proxy': 'ArmoooIsAnOEM',
        'Authorization': 'GoogleLogin auth=%s' % cpp.get_auth()
   })

    try:
        pdf = urllib2.urlopen(request)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        shutil.copyfileobj(pdf, tmp)
        tmp.flush()

        request = urllib2.Request(job['ticketUrl'], headers={
            'X-CloudPrint-Proxy': 'ArmoooIsAnOEM',
            'Authorization': 'GoogleLogin auth=%s' % cpp.get_auth()
       })
        options = json.loads(urllib2.urlopen(request).read())
        if 'request' in options:
            del options['request']

        options = dict((str(k), str(v)) for k, v in options.items())

        cpp.finish_job(job['id'])

        cups_connection.printFile(printer.name, tmp.name, job['title'], options)
        os.unlink(tmp.name)
        LOGGER.info('SUCCESS ' + job['title'].encode('unicode-escape'))

    except:
        cpp.fail_job(job['id'])
        LOGGER.error('ERROR ' + job['title'].encode('unicode-escape'))


def process_jobs(cups_connection, cpp):
    while True:
        printers = cpp.get_printers()
        try:
            for printer in printers:
                for job in printer.get_jobs():
                    process_job(cups_connection, cpp, printer, job)
            wait_for_new_job(cpp.auth)
        except Exception:
            LOGGER.exception('ERROR: Could not Connect to Cloud Service. Will Try again in 60 Seconds')
            time.sleep(60)


def wait_for_new_job(auth):
    # https://developers.google.com/cloud-print/docs/rawxmpp
    import ssl
    import socket
    from xml.etree.ElementTree import iterparse, tostring
    import base64
    xmpp = ssl.wrap_socket(socket.socket())
    xmpp.connect(('talk.google.com', 5223))
    parser = iterparse(xmpp, ('start', 'end'))

    print auth.xmpp_jid, auth.access_token, repr('\0{}\0{}'.format(auth.xmpp_jid, auth.access_token))
    auth_string = base64.b64encode('\0{}\0{}'.format(auth.xmpp_jid, auth.access_token))

    def msg(msg=' '):
        print msg
        xmpp.write(msg.encode('utf-8'))
        stack = 0
        for event, el in parser:
            if event == 'start' and el.tag.endswith('stream'):
                continue
            stack += 1 if event == 'start' else -1
            if stack == 0:
                print tostring(el)
                assert not el.tag.endswith('failure') and not el.tag.endswith('error') and not el.get('type') == 'error', tostring(el)
                return el

    msg('<stream to="gmail.com" version="1.0" xmlns="http://etherx.jabber.org/streams">')
    msg('<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="X-OAUTH2" auth:service="chromiumsync" auth:allow-generated-jid="true" auth:client-uses-full-bind-result="true" xmlns:auth="http://www.google.com/talk/protocol/auth">%s</auth>' % auth_string)
    msg('<s:stream to="gmail.com" version="1.0" xmlns:s="http://etherx.jabber.org/streams" xmlns="jabber:client">')
    iq = msg('<iq type="set"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>Armooo</resource></bind></iq>')
    bare_jid = iq[0][0].text.split('/')[0]
    msg('<iq type="set" to="%s"><subscribe xmlns="google:push"><item channel="cloudprint.google.com" from="cloudprint.google.com"/></subscribe></iq>' % bare_jid)
    return msg()


def usage():
    print sys.argv[0] + ' [-d][-l][-h] [-p pid_file] [-a account_file]'
    print '-d\t\t: enable daemon mode (requires the daemon module)'
    print '-l\t\t: logout of the google account'
    print '-p pid_file\t: path to write the pid to (default cloudprint.pid)'
    print '-a account_file\t: path to google account ident data (default ~/.cloudprintauth)'
    print '\t\t account_file format:\t <Google username>'
    print '\t\t\t\t\t <Google password>'
    print '-h\t\t: display this help'


def main():
    opts, args = getopt.getopt(sys.argv[1:], 'dlhp:a:')
    daemon = False
    logout = False
    pidfile = None
    auth_file = None
    for o, a in opts:
        if o == '-d':
            daemon = True
        elif o == '-l':
            logout = True
        elif o == '-p':
            pidfile = a
        elif o == '-a':
            auth_file = a
        elif o == '-h':
            usage()
            sys.exit()

    if not auth_file:
        auth_file = os.path.expanduser('~/.cloudprintauth')

    auth = CloudPrintAuth(auth_file)
    if logout:
        auth.delete()
        LOGGER.info('logged out')
        return

    if not pidfile:
        pidfile = 'cloudprint.pid'
    # if daemon, log to syslog, otherwise log to stdout
    if daemon:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        handler.setFormatter(logging.Formatter(fmt='cloudprint.py: %(message)s'))
    else:
        handler = logging.StreamHandler(sys.stdout)
    LOGGER.addHandler(handler)

    cups_connection = cups.Connection()
    cpp = CloudPrintProxy(auth)

    printers = cups_connection.getPrinters().keys()

    if not printers:
        LOGGER.error('No printers found')
        return

    if auth.no_auth():
        name = printers[0]
        ppd, description = get_printer_info(cups_connection, name)
        auth.login(name, description, ppd)
    else:
        auth.load()

    sync_printers(cups_connection, cpp)

    if daemon:
        try:
            from daemon import runner
        except ImportError:
            print 'daemon module required for -d'
            print '\tyum install python-daemon, or apt-get install python-daemon, or pip install python-daemon'
            sys.exit(1)

        # XXX printers is the google list
        app = App(
            cups_connection=cups_connection,
            cpp=cpp,
            pidfile_path=os.path.abspath(pidfile)
        )
        sys.argv = [sys.argv[0], 'start']
        daemon_runner = runner.DaemonRunner(app)
        daemon_runner.do_action()
    else:
        process_jobs(cups_connection, cpp)

if __name__ == '__main__':
    main()
