#! /bin/bash

# gettimestamp (see bottom) must be present in the same directory as this script
# ----------------------------------------------------------------------

if [ $# -lt 2 ]
then
	echo "Usage: $0 <OVS switch name> <sampling period in seconds>"
	exit -1
fi

ovsname=$1
period=$2
bwscale=$(echo "scale=6; 1/$period" | bc)

portlist=`ovs-vsctl list-ports $ovsname`

echo "# Sampling received data (in bytes) every $period seconds"
echo "# Bandwidth scale factor = $bwscale"
echo
echo -n "# time			"
for p in $portlist
do
	echo -n "$p-byte-rx	$p-byte-tx	"
done
echo
echo

while true
do
	t=`./gettimestamp`
	echo -n "$t	"
	for p in $portlist
	do
		Brx=`ovs-ofctl dump-ports $ovsname $p | grep rx | cut -d, -f2 | cut -d= -f2`
		Btx=`ovs-ofctl dump-ports $ovsname $p | grep tx | cut -d, -f2 | cut -d= -f2`
		echo -n "$Brx	$Btx	"
	done
	echo

	sleep $period
done

