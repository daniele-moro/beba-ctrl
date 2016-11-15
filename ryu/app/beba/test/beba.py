"""
Custom BEBA node

This script enables/disables switch max verbosity and debugging with Valgrind via Mininet CLI parameters.
(NB Mininet's verbosity is not affected and can be configured via --verbosity/-v parameter)

The following command starts Mininet with minimum verbosity level (it's equivalent to --switch user)
sudo mn --topo single,4 --controller remote --mac --arp --custom beba.py --switch beba

The following command starts Mininet with Valgrind and maximum verbosity level
sudo mn --topo single,4 --controller remote --mac --arp --custom beba.py --switch beba_dbg
"""

from mininet.node import UserSwitch

class BebaSwitchDbg( UserSwitch ):
    def start( self, controllers ):
        """Start OpenFlow reference user datapath.
           Log to /tmp/sN-{ofd,ofp}.log.
           controllers: list of controller objects"""
        # Add controllers
        clist = ','.join( [ 'tcp:%s:%d' % ( c.IP(), c.port )
                            for c in controllers ] )
        ofdlog = '/tmp/' + self.name + '-ofd.log'
        ofplog = '/tmp/' + self.name + '-ofp.log'
        intfs = [ str( i ) for i in self.intfList() if not i.IP() ]

        print '[\x1b[31mVALGRIND\x1b[0m]'
        self.cmd( 'valgrind --leak-check=full --show-leak-kinds=all --trace-children=yes --track-origins=yes ofdatapath -v -i ' + ','.join( intfs ) +
                  ' punix:/tmp/' + self.name + ' -d %s ' % self.dpid +
                  self.dpopts +
                  ' 1> ' + ofdlog + ' 2> ' + ofdlog + ' &' )
        self.cmd( 'ofprotocol unix:/tmp/' + self.name +
                  ' ' + clist +
                  ' --fail=closed ' + self.opts +
                  ' 1> ' + ofplog + ' 2>' + ofplog + ' &' )
        if "no-slicing" not in self.dpopts:
            # Only TCReapply if slicing is enable
            sleep(1)  # Allow ofdatapath to start before re-arranging qdisc's
            for intf in self.intfList():
                if not intf.IP():
                    self.TCReapply( intf )

switches = {'beba':UserSwitch , 'beba_dbg':BebaSwitchDbg}
