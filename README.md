# quictun

`quictun` is a tool that wraps a TCP session with QUIC to enable the use of QUIC's useful features.  
QUIC has a function called "Connection Migration" that allows communication to continue even if the IP address changes.  
`quictun` was created to use QUIC's Connection Migration in ssh to ensure that communication is not lost when switching between WiFi and Ethernet.  

## Quickstart

### Server setting

- This is an example of a systemd service.

```
$ cat /lib/systemd/system/quictun.service
[Unit]
Description=quictun
Documentation=https://github.com/hrntknr/quictun

[Service]
Restart=on-failure
ExecStart=/usr/local/bin/quictun --no-client-auth

[Install]
After=network.target

$ sudo systemctl daemon-reload
$ sudo systemctl enable --now quictun
```

### Client setting

- Add the following to $HOME/.ssh/config

```
Host *
  ProxyCommand quictun nc --no-client-auth quic://{server_address}:2222 %h:%p
```

## Client Auth

If you disable --no-client-auth and start the server, ca/client certificate will be generated in the config directory.  
Place the generated client certificate in the config directory of the PC you wish to use.  
The config directory is as follows  

| OS    | path                                                   |
| ----- | ------------------------------------------------------ |
| macOS | $HOME/Library/Application Support/net.hrntknr.quictun/ |
| linux | $HOME/.config/quictun/                                 |

## Security notice

Do not expose servers using --no-client-auth to the outside world.  
Your private network will be compromised or used as a stepping server.
