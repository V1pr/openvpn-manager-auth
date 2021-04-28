#!/usr/bin/env python3

#
# OpenVPN static/dynamic challenge response AUTH handler script
#
# written by Tamas Dajka, 2020.03
#
# based on an example script by:
# 2015-2016 Selva Nair <selva.nairATgmail.com>
#

import logging
import socket
import sys
import os
import time
import base64
import random
import errno
import pam
import radius
import uuid
import re
import signal
try:
    import systemd.daemon
except ImportError:
    print("python-systemd not installed")
    sys.exit(2)
import atexit
import datetime

################################################
#
# CONFIGURATION
#
################################################

# use python's logging options: DEBUG, INFO, WARNING, ERROR, CRTITICAL
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!!!!! IN DEBUG IT WILL OMIT USER PASSWORDS TO THE LOG !!!!!!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
log_level=logging.DEBUG

pid_file = '/run/openvpn-auth-daemon-simple.pid'
log_file = '/var/log/openvpn-auth.log'
#error_log_file = '/var/log/openvpn-auth-error.log'

openvpn_unix_socket = '/etc/openvpn/server/.server-auth-socket'

# PAM service to use for first layer auth
user_auth_pam_service = "openvpn-ad-radius"

################################################

################################################
#
# Internal vars
#
################################################

CONNECT     = 1
REAUTH      = 2
ESTABLISHED = 3
ADDRESS     = 4
DISCONNECT  = -1

# RegExp for matching valid username chars
abc_regex = re.compile('([a-zA-Z0-9\.\-\@\\\]+)')

# signal handling
quit_signal_recvd = 0

# ilyet nem szabad, mert akkor ures lesz..
auth_handler = (object)

################################################
#
# Class definitions
#
################################################


class AuthVerify(object):
    """OpenVPN client-auth via the management interface"""

    def __init__(self, openvpn_socket_path):
        """Initializes the unix socket for communicating with the server."""
        self.set_defaults()
        self.ovpn_socket_path = openvpn_socket_path;
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.pam = pam.pam()

    def set_defaults(self):
        self.new_client = 0
        self.user = ''
        self.saved_user = ''
        self.passwd = ''
        self.user_ip = ''
        self.ckid = ("-1","-1")

    def connect(self):
        # Connect to the management interface. Waits if the server is not up
        logging.info('Trying to connect to OpenVPN management socket: {}'.format(self.ovpn_socket_path))
        connected = False
        while not connected:
            try:
                self.sock.connect(self.ovpn_socket_path)
                # if non-blocking is set, than the logic of socket reading must be changed a bit!
                self.sock.setblocking(True)
                connected = True
                # use file interface for reading line by line
                self.sfd = self.sock.makefile('r') #was r+ but that's not supported in python 3.6
                self.sfdw = self.sock.makefile('w')
                logging.info('[{}] Connected.'.format(os.getpid()))
                #time.sleep(3)
                #logging.debug(self.sfd)
                #logging.debug(self.sock)
            except OSError as exc:
                if exc.errno == errno.EISCONN:
                   return
            except Exception as e:
            #    print('.', end="")
                logging.debug(e)
                time.sleep(1)
                self.sock.close();
            finally:
                if not connected: time.sleep(1)
                self.sock.close();
                self.__init__(self.ovpn_socket_path)

    def run(self):
        global quit_signal_recvd
        # Parse messages from server and process when a new client connects
        self.states = dict()
        self.rad_attrs = dict()
        while True:
            if quit_signal_recvd > 0:
                logging.info('[{}] QUIT signal received'.format(os.getpid()))
                break
            logging.debug('Initiating connection')
            self.connect()
            while True:
                if quit_signal_recvd > 0:
                    logging.debug('QUIT signal received')
                    break
                try:
                    line = self.sfd.readline()
                except socket.timeout as e:
                    logging.debug("Sock timeout")
                    time.sleep(0.25)
                    continue
                except socket.error as e:
                    logging.debug("Socket error")
                    break
                except Exception as e:
                    logging.debug("[{}] Exception - can be from interrupt!".format(os.getpid()))
                    break
                if not line:
                    # non-blocking read! Sleep some then reprocess
                    #time.sleep(0.05)
                    #continue
                    break
                line = line.rstrip()

                line_strip = re.sub(r'password=.*','password=[...]',line)

                logging.debug('got: %s' % line_strip)

                if not line.startswith(">CLIENT:"):
                    continue
                line = line[8:]
                if not line: continue
                words = line.split(',')

                # this will omit password parts
                #logging.debug('split into: %s' % ' '.join(words))

                if words[0] == 'CONNECT' and len(words) == 3:
                    self.ckid = words[1:]
                    logging.info('New client {} {}'.format(words[1], words[2]))
                    self.new_client = CONNECT
                    self.user = ''
                    self.passwd = ''
                    self.user_ip = ''
                elif words[0] == 'REAUTH' and len(words) == 3:
                    self.ckid = words[1:]
                    logging.info('New client (reauth) {} {}'.format(words[1], words[2]))
                    self.new_client = REAUTH
                    self.user = ''
                    self.passwd = ''
                    self.user_ip = ''
                elif words[0] == 'ESTABLISHED' and len(words) == 2:
                    self.new_client = ESTABLISHED
                    logging.info('Client {} connection ESTABLISHED'.format(words[1]))
                elif words[0] == 'DISCONNECT' and len(words) == 2:
                    self.new_client = DISCONNECT
                    logging.info('Client {} DISCONNECTED'.format(words[1]))
                elif words[0] == 'ADDRESS':
                    self.new_client = ADDRESS
                    logging.info('Client {} associated subnet {} - {}'.format(words[1],words[2],words[3]))
                elif line.startswith('ENV,END') and self.new_client:
                    if self.new_client == CONNECT or self.new_client == REAUTH:
                        logging.info('Processing new client')
                        self.process_client()
                    elif self.new_client == ADDRESS:
                        self.info("ADDRESS END")
                    elif self.new_client == ESTABLISHED:
                        logging.info("User {}/{} is now CONNECTED.".format(self.user,self.user_ip))
                    elif self.new_client == DISCONNECT:
                        logging.info("Cleanup after {}".format(self.user))
                        # don't free it up, we'll need it upon next connect
                        #self.states.pop(self.user,'None')
                        #self.rad_attrs.pop(self.user,'None')
                    self.new_client = 0
                elif not self.new_client or not words[0] == 'ENV' or len(words) < 2:
                    continue

                # Processing ENV variables
                if words[1].startswith('username='):
                    self.user = words[1][9:]
                    logging.debug('got user = %s' % self.user)
                elif words[1].startswith('password='):
                    self.passwd = words[1][9:]
                    logging.debug('got pass = [...]')
                elif words[1].startswith('untrusted_ip='):
                    self.user_ip = words[1][13:]
                    logging.debug('got user_ip = %s' % self.user_ip)

            try:
                if self.sfd:
                    self.sfd.close()
                if self.sfdw:
                    self.sfdw.close()
                if self.sock:
                    self.sock.close()
            except Exception as e:
                logging.debug('Failed to close instances')
                pass
        # exit gracefully
        sys.exit(0)

    def process_client(self):
        # Verify dynamic challenge response or prompt a new challenge

        reason = 'User/Password/Token is in invalid format'

        msg = ''

        user_cleaned = abc_regex.match(self.user).group(0)
        self.user = "".join(user_cleaned)
        #logging.debug(self.user)
        #logging.debug(abc_regex.match(self.user).group(0))
        #logging.debug("User cleaned: "+user_cleaned)
        #current_state = user_cleaned + str(uuid.uuid4())
        current_state = self.user + '|' + str(uuid.uuid4()) # ez mar tisztitott lesz

        # this is not good, the password is encoded
        #if self.states.get(self.user) == None:
        #    self.states[self.user] = current_state + '|' + self.passwd

        # don't enable this!!!
        #logging.debug('Password received from mgmt: %s' % self.passwd)

        # Reauth happens during renegotiation. If the client is running with
        # cached credentials renegotiation will fail if full user
        # authentication is performed. Here we just pass the client with no
        # checks in case of reauth.

        if self.new_client == REAUTH:
            # TODO: fixme - lehet, hogy nem lesz jo, mert auth-nocache van
            # lehet, hogy kene bele egy 12h limit vagy hasonlo!!
            # we should check just the username/password, not the OTP
            msg = 'client-auth ' + ' '.join(self.ckid)
            logging.info('Client reauth ({}/{}): allowing without checks'.format(self.user,self.user_ip))

        elif not self.user:
            reason = 'Empty username'

        # running in simple mode, NO REAL AUTHENTICATION is done, clients are accepted!
        else:
            test_sleep_in_s = 5
            logging.warning('NO REAL AUTHENTICATION IS DONE! ACCEPTING client! Test sleeping {}s'.format(test_sleep_in_s))
            time.sleep(test_sleep_in_s)
            msg = 'client-auth-nt ' + ' '.join(self.ckid)

        #
        # Process auth result
        #

        if not msg:
            logging.info("Access DENIED to {}/{} with reason '{}'".format(self.user,self.user_ip,reason))
            msg =  ('client-deny '
                    + ' '.join(self.ckid)
                    + ' reason "' + reason + '"')
        else:
            logging.info('Access ACCEPT to {}/{}'.format(self.user,self.user_ip))

        try:
            msg = msg + '\r\n'
            self.sfdw.write(msg)
            #self.sfdw.write('cipher AES-256-GCM\r\n')
            #self.sfdw.write('hold release\r\n')
            #self.sfdw.write('END\r\n')
            self.sfdw.flush()
        except Exception as e:
            logging.debug(e)
            return

        logging.debug('replied: %s' % msg)
        logging.debug('replied: END')
        self.set_defaults()

class Daemon(object):
    """ Linux Daemon boilerplate. """
    def __init__(self, pid_file='/run/openvpn-auth.pid',
                 stdout='/var/log/openvpn-auth.log',
                 stderr='/var/log/openvpn-auth-error.log'):
        self.stdout = stdout
        self.stderr = stderr
        self.pid_file = pid_file

    def del_pid(self):
        """ Delete the pid file. """
        os.remove(self.pid_file)

    def daemonize(self):
        """ There shined a shiny daemon, In the middle, Of the road... """

        logging.debug("Startup pid {}".format(os.getpid()))

        # fork 1 to spin off the child that will spawn the deamon.
        if os.fork():
            systemd.daemon.notify('READY=1')
            sys.exit()

        # This is the child.
        # 1. cd to root for a guarenteed working dir.
        # 2. clear the session id to clear the controlling TTY.
        # 3. set the umask so we have access to all files created by the daemon.
        os.chdir("/")
        os.setsid()
        os.umask(0)

        logging.debug("First child pid {}".format(os.getpid()))

        # if we detach further more, logging will stop working!
        # fork 2 ensures we can't get a controlling ttd.
#        if os.fork():
#            sys.exit()

        logging.debug("Final pid {}".format(os.getpid()))

        # This is a child that can't ever have a controlling TTY.
        # Now we shut down stdin and point stdout/stderr at log files.

        # stdin
        with open('/dev/null', 'r') as dev_null:
            os.dup2(dev_null.fileno(), sys.stdin.fileno())

        # we use logging, this is not needed
        # stderr - do this before stdout so that errors about setting stdout write to the log file.
        #
        # Exceptions raised after this point will be written to the log file.
        #sys.stderr.flush()
        #with open(self.stderr, 'a+') as stderr:
        #    os.dup2(stderr.fileno(), sys.stderr.fileno())

        # stdout
        #
        # Print statements after this step will not work. Use sys.stdout
        # instead.
        #sys.stdout.flush()
        #with open(self.stdout, 'a+') as stdout:
        #    os.dup2(stdout.fileno(), sys.stdout.fileno())

        # Write pid file
        # Before file creation, make sure we'll delete the pid file on exit!
        atexit.register(self.del_pid)
        pid = str(os.getpid())
        with open(self.pid_file, 'w+') as pid_file:
            pid_file.write('{0}'.format(pid))

    def get_pid_by_file(self):
        """ Return the pid read from the pid file. """
        try:
            with open(self.pid_file, 'r') as pid_file:
                pid = int(pid_file.read().strip())
            return pid
        except IOError:
            return

    def check_pid(self,pid):
        """ Check For the existence of a unix pid. """
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True

    def start(self):
        """ Start the daemon. """
        logging.info("Starting...")
        pid = self.get_pid_by_file()
        if pid:
            logging.warning('PID file {0} exists. Is the deamon already running?'.format(self.pid_file))
            if self.check_pid(pid):
                sys.exit(1)
            else:
                logging.warning("Stale PID file found, removing")
                os.remove(self.pid_file)

        logging.debug("[{}] Daemonizing".format(os.getpid()))
        self.daemonize()
        logging.info("[{}] Startup complete, processing".format(os.getpid()))
        #print("Log restart.".format(datetime.datetime.now()),file=sys.stderr)
        # this does not work from here - we've forked before
        # systemd.daemon.notify('READY=1')
        self.run()

    def stop(self):
        """ Stop the daemon. """

        global quit_signal_recvd

        logging.info("Stopping...")
        pid = self.get_pid_by_file()
        if not pid:
            logging.warning("PID file {0} doesn't exist. Is the daemon not running?".format(self.pid_file))
            return

        if quit_signal_recvd > 0:
            logging.debug("QUIT Signal")
            # signal alapjan lepunk ki, nem fogunk kill-t kuldeni sajat magunknak megint!
            try:
                os.remove(self.pid_file)
                return
            except Exception as e:
                pass
                logging.debug("Failed to remove PID file, maybe someone else did it?")
            return

        # Time to kill.
        try:
            i = 1
            while self.check_pid(pid) and i < 50:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.25)
                i+= 1
            if self.check_pid(pid):
                os.kill(pid, signal.SIGKILL)
        except OSError as err:
            if 'No such process' in err.strerror and os.path.exists(self.pid_file):
                os.remove(self.pid_file)
                return
                pass
            else:
                logging.error(err)
                sys.exit(1)

    def restart(self):
        """ Restart the deamon. """
        self.stop()
        # small sleep to wait for child processes to close
        time.sleep(1.5)
        logging.info("Restarting.")
        # we're not in a quit phase anymore
        quit_signal_recvd = 0
        self.start()

    def run(self):
        global auth_handler
        """ The main loop of the daemon. """
        # Signal handling
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGHUP, signal_handler)
#       signal.signal(signal.CTRL_C_EVENT, signal_handler)
        auth_handler = AuthVerify (openvpn_unix_socket)
        logging.info("Startup completed, starting connection to OpenVPN socket")
        auth_handler.run()
        logging.info("Cleanup completed, exiting.")
#        print(auth_handler)

def signal_handler(sig, frame):
    global quit_signal_recvd, debug, auth_handler, stop_cmd

    logging.debug("[{}] Received signal {}".format(os.getpid(),sig))
    quit_signal_recvd = int(sig)

    valid_siglist = [1,2,3,15]

    if sig not in valid_siglist:
        logging.debug("Not processing signal {}".format(sig))
        return

    logger.debug(auth_handler)
    try:
       if auth_handler:
           logger.debug("Auth handler OK")
           if auth_handler.sfd:
               logger.debug("Closing SFD")
               auth_handler.sfd.close()
           if auth_handler.sock:
               logger.debug("Closing sock")
               auth_handler.sock.close()
    except Exception as e:
        logging.debug("[{}] No auth_handler socket".format(os.getpid()))
        # do nothing
#    this creates a loop
#    print(stop_cmd)
#    if not stop_cmd:
#        daemon.stop()

def usage():
    print("Usage: {0} start|stop|restart".format(sys.argv[0]))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        sys.exit(2)

    logging.basicConfig(filename=log_file, format='[%(asctime)s] [%(levelname)s] %(message)s', level=log_level)

    daemon = Daemon(pid_file,log_file)
    if 'start' == sys.argv[1]:
        daemon.start()
    elif 'stop' == sys.argv[1]:
        daemon.stop()
    elif 'restart' == sys.argv[1]:
        daemon.restart()
    else:
        print("Unknown command '{0}'".format(sys.argv[1]))
        usage()
        sys.exit(2)

