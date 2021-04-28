# openvpn-manager-auth
OpenVPN addon for authenticating via the manager socket, using Pam (MS AD) + OTP with both static and dynamic challenge.

OTP is done against a RADIUS (RSA SecurID), since radius implements challenge-response methods, so a dynamic challenge can be used, if needed.

In the OpenVPN server, the following 2 lines are needed to the the auth daemon work:

```
management /etc/openvpn/server/.server-auth-socket unix
management-client-auth
```

You'll need to have a working PAM auth for this (example in pam.d). For pam-radius you'll need to set the server parameters in /etc/pam_radius_auth.conf - for Debian.

System.d service is in system.d; mind the path ;) 

For the OTP step you'll need to configure the auth-daemon's CONFIGURATION section (rsa_radius_server_dict) for the OTP radius servers.

There are multiple versions, one simple for testing, one using etcd (so you can have multiple openvpn servers running parallel, sharing all the auth data) and one standalone.

Please note, that if you're not using any persistent storage - like etcd - if you restart the auth-daemon, than the user's will loose their token, thus having to authenticate again after the reauth time reached (1h by default).
