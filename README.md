# Python Echo Service

Useful for debugging the source IP and all headers received by a client.

# How to Use

```
$ git clone ...
$ pip install -r requirements.txt
$ cp config.yml.sample config.yml
(edit config.yml)
$ python echo.py -c config.yml
```

# Config.yml

Example:

```
ip: "*"
ports: "80,2000-2001,4000-4001,9999"
tcp: true
udp: false
certfile: "keypair.pem"
```

**ip** The IP address to bind to. "*" = all IP addresses assigned to the system.

**ports** Comma-separated list of ports or port ranges

**tcp** If true, listens on TCP sockets.  Both `tcp` and `udp` can be true.

**udp** If true, listens on UDP sockets.  Both `tcp` and `udp` can be true.

**certfile** The TLS certificate used if TCP port 443 is listed in ports.
