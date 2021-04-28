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
import secrets

################################################
#
# CONFIGURATION
#
################################################

# use python's logging options: DEBUG, INFO, WARNING, ERROR, CRTITICAL
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!!!!! IN DEBUG IT WILL OMIT USER PASSWORDS TO THE LOG !!!!!!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
log_level=logging.INFO

pid_file = '/run/openvpn-auth-daemon.pid'
log_file = '/var/log/openvpn-auth.log'
#error_log_file = '/var/log/openvpn-auth-error.log'

openvpn_unix_socket = '/etc/openvpn/server/.server-auth-socket'

# PAM service to use for first layer auth
user_auth_pam_service = "openvpn-ad-radius"

# RSA Radius server for Token verification
rsa_radius_server_dict = { '10.0.0.1' : 'my-radius-server-secret', '10.0.0.2' : 'my-other-radius-server-secret' }

# User token validity - since we'll use tokens after the first auth, let's give it a validity - in secondy
user_auth_token_validity = 36000

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
username_regex = re.compile('([a-zA-Z0-9\.\-\@\\\]+)')
num_regex = re.compile('([0-9]+)')

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
        self.user_tokens = dict()
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

        user_cleaned = username_regex.match(self.user).group(0)
        self.user = "".join(user_cleaned)
        #logging.debug(self.user)
        #logging.debug(username_regex.match(self.user).group(0))
        #logging.debug("User cleaned: "+user_cleaned)
        #current_state = user_cleaned + str(uuid.uuid4())
        current_state = self.user + '|' + str(uuid.uuid4()) # ez mar tisztitott lesz

        # ez igy nem jo, mert lehet, hogy a jelszo kodolva van!
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
            if len(self.passwd) == 43 and "CRV" not in self.passwd:
                logging.debug("Got auth-token: {}".format(self.passwd))
            # ez valsz csak egy benezes miatt van benne... majd tesztelni kell, de szinte kizart, hogy kene
            if len(self.passwd) >= 40 and '/' in self.passwd:
                logging.debug("Splitting self.passwd by /")
                auth_token, user_passwd = self.passwd.split('/')
            else:
                auth_token = self.passwd
            # van valid token?
            if self.user_tokens.get(self.user) == None or self.user_tokens[self.user].get("token") == None:
                reason = "No stored valid token found."
                logging.info("No stored valid token found for {}".format(self.user))
            elif self.user_tokens[self.user]["token"] != auth_token:
                reason = "Invalid token value."
                logging.info("Invalid token value for user {}.".format(self.user))
                logging.debug("Invalid token value for user {} [{}/{}].".format(self.user,self.user_tokens[self.user]["token"],auth_token))
            elif ( self.user_tokens[self.user]["timestamp"] + user_auth_token_validity ) <= time.time():
                expired_secs = time.time() - self.user_tokens[self.user]["timestamp"] - user_auth_token_validity
                reason = "User token has expired."
                logging.info("User token has expired {}s ago for {}".format(expired_secs,self.user))
            elif self.user_tokens[self.user]["token"] == auth_token and ( self.user_tokens[self.user]["timestamp"] + user_auth_token_validity ) > time.time():
                msg = 'client-auth-nt ' + ' '.join(self.ckid)
                pending_validity = self.user_tokens[self.user]["timestamp"] + user_auth_token_validity - time.time()
                logging.info('Client reauth ({}/{}): valid token found [still valid for {}s]'.format(self.user,self.user_ip,pending_validity))
            else:
                reason = "Unknown faliure upon token validation"
                logging.debug("Unkown failure upon token validation. {} != {} TS: {} Time: {} Validity time: {}".format(auth_token,self.user_tokens[self.user]["token"],self.user_tokens[self.user]["timestamp"],time.time(),user_auth_token_validity))

        elif not self.user:
            reason = 'Empty username'

        # Static-challenge mode, but we can reply with a dynamic challenge

        elif self.passwd.startswith ('SCRV1:') and self.passwd[6:]:
            logging.info('Received static-challenge from {}/{}'.format(self.user,self.user_ip))
            pr64 = self.passwd[6:].split(':')
            p = ''
            r = ''
            if pr64[0]:
                p = base64.b64decode(pr64[0]).decode("utf-8")
            if len(pr64) == 2 and pr64[1]:
                r = base64.b64decode(pr64[1]).decode("utf-8")
            logging.debug("Received PASS length {}".format(len(p)))
            logging.debug("Received OTP TOKEN {}".format(r))
            r_cleaned = num_regex.match(r).group(0)
            if r_cleaned != r:
                if len(r_cleaned) == 8:
                    r = r_cleaned
                else:
                    r = None
            if not p or not r:
                reason = 'Invalid format'
            elif p and not r:
                if self.states.get(self.user) == None:
                    self.states[self.user] = current_state + '|' + p
                # No token data, request it
                b64_user = base64.b64encode(self.user.encode("utf-8")).decode("utf-8")
                reason = ('CRV1:R,E:' + current_state + ':' + b64_user + ':'
                          + 'Welcome ' + self.user + '! Please type in RSA Token:')
                # nem volt egyatalan token, igy nem kell az elmentett attr
                self.rad_attrs.pop(self.user,None)
            else:
                if self.states.get(self.user) == None:
                    self.states[self.user] = current_state + '|' + p
                    #self.rad_attrs.pop(self.user,None)

                # we've to all the data needed for auth, give it a try
                # first factor: username + password
                self.pam.authenticate(self.user,p,service=user_auth_pam_service)
                # indicating success
                if self.pam.code == 0:
                    logging.info("PAM AUTH OK for user '{}'".format(self.user))
                    #print(self.pam.code)
                    #print(self.pam.reason)
                    # radius OK, go for OTP with RSA radius
                    rad = RSARadiusAuth(self.user,r)
                    rad.auth(self.user,r)
                    # ez legyen ures, csak akkor allitsuk, ha kell - lehet, hogy az elozo connect-nel kitoltottuk...
                    # self.rad_attrs.pop(self.user,None)
                    if rad.status == 1:
                        logging.info("RSA AUTH OK for user '{}'".format(self.user))
                        self.user_tokens[self.user] = {}
                        self.user_tokens[self.user]["token"] = secrets.token_urlsafe()
                        self.user_tokens[self.user]["timestamp"] = time.time()
                        msg = 'client-auth ' + ' '.join(self.ckid) + "\r\n"
                        msg += 'push "auth-token ' + self.user_tokens[self.user]["token"] + '"\r\n'
                        msg += "END"
                        self.states.pop(self.user,None)
                        self.rad_attrs.pop(self.user,None)
                    elif rad.status == 2:
                        logging.info("RSA AUTH CHALLENGED for user '{}'".format(self.user))
                        b64_user = base64.b64encode(self.user.encode("utf-8")).decode("utf-8")
                        # kene challenget kuldeni, mert van chanllenge az RSA Radius szervertol
                        reason = ('CRV1:R,E:' + current_state + ':' + b64_user + ':'
                                  + 'Welcome ' + self.user + '! '+rad.message.replace('\n','').replace('\r','').strip())
                        self.states[self.user] = self.states[self.user] + '|' + rad.server
                        self.rad_attrs[self.user] = rad.attrs
                        logging.debug("Challenge attrs: ")
                        logging.debug(rad.attrs)
                    else:
                        logging.info("RSA AUTH UNKNOWN ERROR for user '{}'".format(self.user))
                        #print(self.pam.code)
                        #print(self.pam.reason)
                        reason = "RSA AUTH Failed with Unknown " + rad.message
                else:
                    #print("Failed to authenticate %s %s" % self.pam.code, self.pam.reason)
                    #print(self.pam.code)
                    #print(self.pam.reason)
                    logging.info("PAM AUTH FAILED for user '{}'".format(self.user))
                    reason = self.pam.reason


        elif self.passwd.startswith('CRV1::') and self.passwd[6:]:
            logging.info('Received dynamic-challenge from {}/{}'.format(self.user,self.user_ip))
            # Response to dynamic challenge received.
            # Expect CRV1::state_id::answer
            # The correct answer is embedded in the state_id of the challenge
            # so we just check that it matches response.

            p = self.passwd[6:].split('::')
            #logging.debug(p)
            if len(p) == 2:
                state_id, recvd_response = p
                p = state_id.split('|')
                if len(p) == 2:
                    recvd_user, recvd_uuid = p
                else:
                    recvd_user, recvd_uuid = ('','')
            else:
                recvd_user, recvd_uuid, recvd_response= ('','','')

            logging.debug('recvd uuid, recvd username, recvd response = %s %s %s' % (recvd_uuid, recvd_user, recvd_response))

            if self.states[self.user]:
                logging.debug(self.states[self.user])
            else:
                logging.info("NO STATE INFO for user '{}'".format(self.user))

            sstate = self.states[self.user].split('|')
            # this will emit user passwords!
            #logging.debug(sstate)

            if len(sstate) == 3:
                expected_user, expected_uuid, saved_passwd = sstate
                rad_server = False
            elif len(sstate) == 4:
                # ez egy token response kene legyen
                expected_user, expected_uuid, saved_passwd, rad_server = sstate
            else:
                expected_user, expected_uuid, saved_passwd, rad_server = ('','','','')

            if rad_server:
                rad_attrs = self.rad_attrs[self.user]
            else:
                rad_attrs = None

            logging.debug("Radius server to be used for CR {}".format(rad_server))
            if rad_server: logging.debug(rad_attrs)

            r_cleaned = num_regex.match(recvd_response).group(0)
            if r_cleaned != recvd_response:
                if len(r_cleaned) == 8:
                    recvd_response = r_cleaned
                else:
                    recvd_response = None

            if not recvd_response or not recvd_uuid or not recvd_user:
                reason = 'Dynamic respose in invalid format'
            elif recvd_uuid != expected_uuid:
                reason = 'Wrong security token with dynamic response'
            elif self.user != recvd_user or expected_user != recvd_user:
                reason = 'Wrong username with dynamic response'
            else:
                self.pam.authenticate(self.user,saved_passwd,service=user_auth_pam_service)
                # indicating success
                if self.pam.code == 0:
                    #
                    # Ide tobb esetben kerulhetunk:
                    # - nem adott meg RSA tokent a user az elso ablakban, vagy a GUI nem is kerte, mert re-auth
                    # - megadott, de az RSA Radius szerver kerte a "next tokent"
                    #

                    logging.info("PAM AUTH OK for user '{}'".format(self.user))
                    # a 'p'-ben nincs jelszo, mert ez challenge response! Ott csak token lehet!
                    rad = RSARadiusAuth(self.user,recvd_response)
                    #if rad_server:
                    #self.rad_attrs.pop(self.user,None)
                    if rad_server and rad_attrs:
                        logging.info("Responding to challenge for user '{}' to RSA RADIUS server {}".format(self.user,rad_server))
                        rad.challengeResponse(rad_server,self.user,recvd_response,rad_attrs)
                    else:
                        # radius OK, go for OTP
                        logging.info("No cached radius challenge, trying normal RSA RADIUS auth for user '{}'".format(self.user))
                        rad.auth(self.user,recvd_response)
                    if rad.status == 1:
                        # success
                        logging.info("RSA RADIUS AUTH OK for user '{}'".format(self.user))
                        #msg = 'client-auth-nt ' + ' '.join(self.ckid)
                        self.user_tokens[self.user] = {}
                        self.user_tokens[self.user]["token"] = secrets.token_urlsafe()
                        self.user_tokens[self.user]["timestamp"] = time.time()
                        msg = 'client-auth ' + ' '.join(self.ckid) + "\r\n"
                        msg += 'push "auth-token ' + self.user_tokens[self.user]["token"] + '"\r\n'
                        msg += "END"

                        self.states.pop(self.user,None)
                        self.rad_attrs.pop(self.user,None)

                    elif rad.status == 2:
                        logging.info("RSA RADIUS AUTH challenged for user '{}'".format(self.user))
                        b64_user = base64.b64encode(self.user.encode("utf-8")).decode("utf-8")
                        # kene challenget kuldeni
                        reason = ('CRV1:R,E:' + current_state + ':' + b64_user + ':'
                                  + 'Welcome ' + self.user + '! '+rad.message.replace('\n','').replace('\r','').strip())
                        self.states[self.user] = self.states[self.user] + '|' + rad.server
                        self.rad_attrs[self.user] = rad.attrs
                    else:
                        logging.info("RSA RADIUS AUTH FAILED WITH UNKNOWN ERROR for user '{}'".format(self.user))
                        reason = "RSA AUTH Failed with Unknown"
                        if rad.message:
                            reason = reason + rad.message
                else:
                    #print("Failed to authenticate %s %s" % self.pam.code, self.pam.reason)
                    #print(self.pam.code)
                    #print(self.pam.reason)
                    logging.info("PAM AUTH FAILED for user '{}'".format(self.user))
                    self.rad_attrs.pop(self.user,None)
                    self.states.pop(self.user,None)
                    reason = self.pam.reason

            # ez itt nem lesz jo, mert lehet, hogy meg beszelgetunk a userrel a 'next-token' miatt
            #self.states.pop(self.user,None)
            #self.rad_attrs.pop(self.user,None)

        else:
            logging.info('No OTP received asking for one from {}/{}'.format(self.user,self.user_ip))
            if self.states.get(self.user) == None:
                self.states[self.user] = current_state + '|' + self.passwd

            logging.debug('No token at all, requesting OTP!')
            b64_user = base64.b64encode(self.user.encode("utf-8")).decode("utf-8")
            reason = ('CRV1:R,E:' + current_state + ':' + b64_user + ':'
                      + 'Welcome ' + self.user + '! Please type in RSA Token:')

           # we don't want to allow the client now
            # msg = 'client-auth ' + ' '.join(self.ckid)

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
            #self.sfdw.write('END\r\n')
            self.sfdw.flush()
        except Exception as e:
            logging.debug(e)
            return

        logging.debug('replied: %s' % msg)
        self.set_defaults()

class RSARadiusAuth:
    def __init__(self,user,token):
        self.user = user
        self.token = token

    def auth(self,user,token):
        if len(rsa_radius_server_dict) == 0:
            logging.critical('No RSA radius servers defined')
            sys.exit(-1)

        self.status = -1
        self.attrs = {}
        self.message = ''

        for sk in rsa_radius_server_dict:
            logging.debug('Trying server %s ' % sk)
            logging.debug(user)
            logging.debug(token)

            r = radius.Radius(rsa_radius_server_dict[sk], host=sk, port=1812, retries=1, timeout=3)

            try:
                if r.authenticate(user, token):
                    logging.debug('RSA RADIUS AUTH OK')
                    self.status = 1
                else:
                    logging.debug('RSA RADIUS AUTH FAIL')
                    self.status = 0
                break
                #sys.exit(0)
            except radius.NoResponse as e:
                logging.debug('server timeout, trying next')
                pass
                continue
            except radius.ChallengeResponse as e:
                #print("challenge")
                #print(e)
                #print(radius.ChallengeResponse)
                #print(e.reply-message)
                #print(e.state)
                pass

                # The ChallengeResponse exception has `messages` and `state` attributes
                # `messages` can be displayed to the user to prompt them for their
                # challenge response. `state` must be echoed back as a RADIUS attribute.

                self.status = 2 #waiting for challenge response

                # Send state as an attribute _IF_ provided.
                self.attrs = {'State': e.state} if e.state else {}
                msgs = e.messages if e.messages else {}
                if len(msgs) > 0:
                    msg = msgs.pop()

                self.message = msg.decode('utf-8')
                self.server = sk

                # we'll handle the challenge separatelly
                break

                # Finally authenticate again using the challenge response from the user
                # in place of the password.
                response = input_with_prefill("Next token: ",'')
                logging.debug('success' if r.authenticate(username, response, attributes=attrs) else 'failure')
                break
            except Exception:
                logging.debug("Unknown error in radius modul!")
        logging.debug('RSA Radius check finished done')
        return self.status

    def challengeResponse(self, sk, user, response, attrs):
        logging.debug('Sending challenge response to %s' % sk)
        logging.debug(user)
        logging.debug(response)

        r = radius.Radius(rsa_radius_server_dict[sk], host=sk, port=1812, retries=3, timeout=5)
        try:
            if r.authenticate(user, response, attributes=attrs):
                logging.debug("RSA RADIUS CHALLENGE RESPONSE OK")
                self.status = 1
            else:
                logging.debug("RSA RADIUS CHALLENGE RESPONSE FAILED")
                self.status = 0
        except radius.ChallengeResponse as e:
                logging.debug("RSA RADIUS CHALLENGE RESPONSE FAILED")
                logging.debug(e)
                self.status = 0
        except radius.Error as e:
            logging.debug("Radius challenge-response failed")
            logging.debug(e)
            self.status = 0

        return self.status

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

