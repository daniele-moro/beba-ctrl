#!/usr/bin/python

# Modifying parameter k you can modify the number of host
# The last host is the NAT node
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.topo import SingleSwitchTopo
from mininet.node import UserSwitch, RemoteController
from beba import BebaHost, BebaSwitchDbg

if __name__ == '__main__':
    lg.setLogLevel( 'info')
    topo = SingleSwitchTopo(k=2)
    net = Mininet(topo=topo,
                  host=BebaHost,
                  ipBase='192.168.1.0/24',
                  link=TCLink,
		  switch=UserSwitch,
                  #switch=BebaSwitchDbg,
                  controller=RemoteController,
                  cleanup=True,
                  autoSetMacs=True,
                  listenPort=6634)
    # Add NAT connectivity
    net.addNAT().configDefault()
    net.start()
    for off in ["rx", "tx", "sg"]:
         cmd = "/sbin/ethtool --offload nat0-eth0 %s off" % off
         net.hosts[-1].cmd(cmd)
    CLI( net )
    # Shut down NAT
    net.stop()
