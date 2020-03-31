RAWCOOKIE
=======

RAWCOOKIE is a SYNPROXY module extension which moves initial SYN+ACK conversation into lower levels of kernel. It replaces original `-j CT --notrack` rule in iptables with RAWCOOKIE targes.

Example
---------------

Original rules with SYNPROXY module:
 ```iptables -t raw -A PREROUTING -i tge22 -p tcp -m tcp --syn --dport 80 -j CT --notrack
 iptables -A INPUT -i tge22 -p tcp -m tcp --dport 80 -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
 iptables -A INPUT -i tge22 -p tcp -m tcp --dport 80 -m state --state INVALID -j DROP
 ```

Must be replaced with:
 ```iptables -t raw -A PREROUTING -i tge22 -p tcp -m tcp --syn --dport 80 -j RAWCOOKIE --sack-perm --timestamp --wscale 7 --mss 1460 --senddirect
 iptables -A INPUT -i tge22 -p tcp -m tcp --dport 80 -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
 iptables -A INPUT -i tge22 -p tcp -m tcp --dport 80 -m state --state INVALID -j DROP
 ```


Direct mode
---------------

RAWCOOKIE module supports special mode for sending initial SYN+ACK packet when the packet avoids Linux routing system. The SYN+ACK packet is send directly to the MAC addres (the address of the router)  which we received the original SYN packet from. The direct mode can be enable via `--senddirect` option.

In case when it is necessary to override the destination MAC address there is option `--txmac` which can do it for you.

```--txmac 4c:ae:a3:6a:80:bc```

> NOTE: Please do not set `--txmac` option if you are not sure how this option works. By setting invalid/not existing MAC address you might flood packets to all ethernet ports whet the server is connected to!


Build from sources
---------------

```
# git clone https://github.com/netx-as/xt_RAWCOOKIE.git
# cd xt_RAWCOOKIE
# make
# make install
```

> It is required to have kernel and iptables sources installed.

Sources
---------------

For sources please visit: https://github.com/netx-as/xt_RAWCOOKIE


Licence
---------------

RAWCOKIE module is based on Linux SYNCOKIE module as is provided under same license as the SYNCOOKIE module.
