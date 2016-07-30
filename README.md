# ipt_SYNPROXY

It is an implementation of SYNPROXY based on netfilter of Linux. An iptables raw
target SYNPROXY is implemented. In order to use it, you must get the newest
Linux kernel source code, and follow the following steps:

```bash
cd linux
patch -p1 < path-to-synproxy.diff
/* you need select raw table, ip_conntrack and syncookies */
make && make install modules_install && reboot
cd path-to-synproxy
make
cp libipt_SYNPROXY.so path-to-iptables-shared-module
insmod ipt_SYNPROXY.ko
```

If there isn't any error in the above steps, congratulations, and you can play
with it. For example, you want to protect the local HTTP server from the
SYN-flood attacks:

```bash
iptables -t raw -A PREROUTING -p tcp --dport 80 \
	--tcp-flags SYN,ACK,RST,FIN SYN \
	-m conntrack --ctstate INVALID -j SYNPROXY
```

If you run SYNPROXY on a gateway which does DNAT, you should move the DNAT rules
from PREROUTING to OUTPUT chain, because the second SYN to the server is sent
locally.
