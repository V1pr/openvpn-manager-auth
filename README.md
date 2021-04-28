# openvpn-manager-auth
OpenVPN addon for authenticating via the manager socket, using Pam (MS AD) + OTP with both static and dynamic challenge.

OTP is done against a RADIUS (RSA SecurID), since radius implements challenge-response methods, so a dynamic challenge can be used, if needed.

In the OpenVPN server, the following 2 lines are needed to the the auth daemon work:

```
management /etc/openvpn/server/.server-auth-socket unix
management-client-auth
```

