iptables -t mangle -F
rmmod ipt_SYNPROXY
insmod ipt_SYNPROXY.ko
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j SYNPROXY
