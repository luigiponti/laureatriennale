#!/usr/bin/python

'''
TOPOLOGY USED IN NETSOFT 2015 TEST

Emulation of l2-scenario for the OpenStack case. Nodes:
- Host  VM-User1: one interface
- Host  VM-User2: one interface
- Host DPI: one interface
- Host WAN Accellerator (WANA): 2 interfaces, both connected to Linux Bridge (eth0 and eth1 are bridged with a LB, br-WANA)
- Host TC: 2 interfaces, both connected to Linux Bridge (eth0 and eth1 are bridged with a LB, br-TC)
- Host VR: 2 interfaces
- Host h1: one interfaces
- An Open vSwitch

1) sudo python test-l2-scenario.py  
'''

from mininet.net import Mininet
from mininet.node import Node
from mininet.node import Host
from mininet.link import TCLink
from mininet.link import Intf
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Controller
from mininet.node import RemoteController
from mininet.util import quietRun

from time import sleep 
import os
import sys

def defineNetwork():
    if len(sys.argv) < 2:
        print "Missing paramenter: python test-l2-scenario.py <debug=1|0>"
        sys.exit()
    #commento
    debug = sys.argv[1] #print some usefull information
    
    info("*** Create an empty network and add nodes and swith to it *** \n")
    net = Mininet(controller=RemoteController, link=TCLink, build=False, xterms=True)
    info("\n*** Adding Controller: Controller will be external *** \n")
    info("\n*** Creating Switch *** \n")    
    s1 = net.addSwitch('s1')
    s1.cmd( 'ovs-vsctl del-br ' + s1.name )
    s1.cmd( 'ovs-vsctl add-br ' + s1.name )
    s1.cmd( 'ovs-vsctl set Bridge '+ s1.name + ' stp_enable=false protocols=OpenFlow13' ) # Disabling STP
    
    info("\n*** Creating VM-User 1 *** \n")
    vmu1 = net.addHost('VMU1')
    info("\n*** Creating VM-User 2 *** \n")
    vmu2 = net.addHost('VMU2')
    info("\n*** Creating DPI *** \n")
    dpi = net.addHost('DPI')
    info("\n*** Creating WAN A. *** \n")
    wana = net.addHost('WANA')
    info("\n*** Creating TC *** \n")
    tc = net.addHost('TC')
    info("\n*** Creating Virtual Router *** \n")
    vr = net.addHost('VR')
    info("\n*** Creating External Host *** \n")
    h1 = net.addHost('H1')
    info("\n*** Creating Links *** \n")
    net.addLink(vmu1, s1, bw=100)
    net.addLink(vmu2, s1, bw=100) 
    net.addLink(dpi, s1, bw=100)
    net.addLink(wana, s1, bw=100)
    net.addLink(wana, s1, bw=100)
    net.addLink(tc, s1, bw=100)
    net.addLink(tc, s1, bw=100)
    net.addLink(vr, s1, bw=100)
    net.addLink(vr, h1, bw=100)
    
    #Trying to assign MAC address to each node of the topology
    vmu1.setMAC("00:00:00:00:00:01", vmu1.name + "-eth0")
    vmu2.setMAC("00:00:00:00:00:02", vmu2.name + "-eth0")
    dpi.setMAC("00:00:00:00:00:03", dpi.name + "-eth0")
    wana.setMAC("00:00:00:00:00:04", wana.name + "-eth0")    
    wana.setMAC("00:00:00:00:00:05", wana.name + "-eth1")
    tc.setMAC("00:00:00:00:00:06", tc.name + "-eth0")
    tc.setMAC("00:00:00:00:00:07", tc.name + "-eth1")
    vr.setMAC("00:00:00:00:00:08", vr.name + "-eth0") 
    vr.setMAC("00:00:00:00:00:09", vr.name + "-eth1")
    h1.setMAC("00:00:00:00:00:0A", h1.name + "-eth0")

    #Disabling IPv6
    info('\n*** Disabling IPv6 ...\n')
    vmu1.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    vmu1.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    vmu1.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
    vmu2.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    vmu2.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    vmu2.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
    dpi.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    dpi.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    dpi.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
    wana.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    wana.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    wana.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
    tc.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    tc.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    tc.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
    vr.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    vr.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    vr.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
    h1.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    h1.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    h1.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')

    for intf in s1.intfs.values():    
        s1.cmd( 'ovs-vsctl add-port ' + s1.name + ' %s' % intf )
        print "Eseguito comando: ovs-vsctl add-port s1 ", intf    
        
    info("\n*** Starting Network using Open vSwitch and remote controller*** \n")
    # Creating a Linux Bridge on each host
    nhosts = len(net.hosts)
    print 'Total number of hosts: ' + str(nhosts)
    count = 1
 
    net.start()
    s1.cmd( 'ovs-vsctl set bridge ' + s1.name + ' protocols=OpenFlow13') #OpenFlow 1.3
    # Set the controller for the switch
    print "Switch name: ", s1.name
    s1.cmd('ovs-vsctl set-controller ' +  s1.name + ' tcp:127.0.0.1:6633')
    info( '\n*** Waiting for switch to connect to controller' )
    while 'is_connected' not in quietRun( 'ovs-vsctl show' ):
        sleep( 1 )
        info( '.' )
    info('\n')

    # Add some static rules (avoid ARP storm - these rules will be moved to Controller code) ...    
    s1.cmd('ovs-ofctl -O OpenFlow13 add-flow ' + s1.name + ' in_port=4,dl_dst=FF:FF:FF:FF:FF:FF,actions=drop')
    s1.cmd('ovs-ofctl -O OpenFlow13 add-flow ' + s1.name + ' in_port=5,dl_dst=FF:FF:FF:FF:FF:FF,actions=drop')
    s1.cmd('ovs-ofctl -O OpenFlow13 add-flow ' + s1.name + ' in_port=6,dl_dst=FF:FF:FF:FF:FF:FF,actions=drop')
    s1.cmd('ovs-ofctl -O OpenFlow13 add-flow ' + s1.name + ' in_port=7,dl_dst=FF:FF:FF:FF:FF:FF,actions=drop')                    
    info('\n*** Going to take down default configuration ...\n')
    info('\n*** ... and creating Linux bridge on WANA and TC, as well as configuring interfaces \n')
    for host in net.hosts:
        print 'Deleting ip address on ' + host.name + '-eth0 interface ...'
        host.cmd('ip addr del ' + host.IP(host.name + '-eth0') + '/8 dev ' + host.name + '-eth0')
        print 'Deleting entry in IP routing table on ' + host.name
        host.cmd('ip route del 10.0.0.0/8')
        print "Going to configure new IP"    
        if host.name == 'WANA' or host.name == 'TC':
            print "Host with 2 interfaces: " + host.name
            host.cmd('brctl addbr br-' + host.name)
            host.cmd('brctl addif br-' + host.name + ' ' + host.name + '-eth0')
            host.cmd('brctl addif br-' + host.name + ' ' + host.name + '-eth1')
            host.cmd('ip addr add 10.10.10.' + str(count) + '/24 dev br-' + host.name)    
            host.cmd('ip link set br-' + host.name + ' up') 
            print "LB configured!"
            host.cmd('sysctl -w net.ipv4.ip_forward=1')
            print "IP Forwarding enabled!"    
        elif host.name == 'H1':    
            host.setIP("10.0.0." + str(count + 2), 30, host.name + '-eth0')    
            net.hosts[count - 2].setIP("10.0.0." + str(count + 3), 30, net.hosts[count - 2].name + "-eth1")
            print net.hosts[count - 2].name + "-eth1 interface has been configured!"
            print "[Checking VR IP] " + net.hosts[count - 2].IP('VR-eth1')
            net.hosts[count - 2].cmd('sysctl -w net.ipv4.ip_forward=1')
            print "On VR node: IP Forwarding enabled!"
        else:    
            host.setIP("10.10.10." + str(count), 24, host.name + "-eth0")
            print "[CURRENT-CHECK] IP: " + net.hosts[count - 1].IP(net.hosts[count - 1].name + '-eth0')            
        count = count + 1    
        print "\n"
    print "Configuring default gw on each host.."
    count = 1    
    for host in net.hosts:
        print "Adding default gw ..."
        if host.name != 'VR' and host.name != 'H1' and host.name != 'WANA' and host.name != 'TC':    
            host.setDefaultRoute('dev ' + host.name + '-eth0 via ' + net.hosts[nhosts - 2].IP(net.hosts[nhosts - 2].name + '-eth0'))
        elif host.name == 'TC' or host.name == 'WANA':
            print "Default GW manually configured"
            host.cmd('route add default gw ' + net.hosts[nhosts - 2].IP(net.hosts[nhosts - 2].name + '-eth0'))    
        else:
            #H1 case    
            host.setDefaultRoute('dev ' + host.name + '-eth0 via ' + net.hosts[nhosts - 2].IP(net.hosts[nhosts - 2].name + '-eth1'))

    #installing TrafficShaper on TC
    info('\n*** Installing TrafficShaper on TC\n')
    tc.cmd('tc qdisc del dev TC-eth1 root')
    tc.cmd('tc qdisc add dev TC-eth1 root handle 1: cbq avpkt 1000 bandwidth 1000mbit')
    tc.cmd('tc class add dev TC-eth1 parent 1: classid 1:1 cbq rate 10mbit allot 1500 prio 5 bounded')
    tc.cmd('tc filter add dev TC-eth1 parent 1: protocol ip prio 16 u32 match ip dst 10.0.0.9 flowid 1:1')
    tc.cmd('tc qdisc add dev TC-eth1 parent 1:1 sfq perturb 10')


    if debug:
        print "******************** DEBUG MODE ON ********************"
        print "[SWITCH] ", s1, " Number of interfaces is ", len(s1.intfs)
        print "List of hosts:"
        for host in net.hosts:
            info( host.name + '\n' )
            print "[HOST " + host.name + " - Interfaces]"
            print host.cmd('ip a')
            print "[HOST " + host.name + " - Routing table]"
            print host.cmd('route -n')
            print "[HOST " + host.name + " - IPv6 status]"
            print host.cmd('cat /proc/sys/net/ipv6/conf/all/disable_ipv6')    
    info('... running CLI \n***')
    CLI(net)
    info('\n')
    info('... stopping Network ***\n')
    net.stop()

#Main
if __name__ == '__main__':
    setLogLevel('info')
    defineNetwork()
