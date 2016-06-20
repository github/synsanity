## condition match

The condition match resurrects the condition match module that was available in the 2.x series kernel.

This allows a match target that is controlled by a userspace entry in the proc filesystem. For example:
```
iptables -A INPUT -p tcp -m tcp --dport 80 -m condition ! --condition knockknock -j DROP
```

By default, the above rule will match since the condition is default 0, and port 80 will be blocked. This can be toggled via proc:
```
echo 1 > /proc/net/ipt_condition/knockknock
# packets to port 80 go through
echo 0 > /proc/net/ipt_condition/knockknock
# packets to port 80 are blocked again
```

## CONDITION target

In addition to the original condition match, a CONDITION target has been added that can change the same condition values based on a certain other set of xtables matches. For example, to enable the above port 80 condition only after a packet arrives on port 42:
```
iptables -A INPUT -p tcp -m tcp --dport 42 -j CONDITION --condition knockknock
```

This would look like the following:
```
echo 0 > /proc/net/ipt_condition/knockknock
# packets to port 80 are blocked
nc localhost 42
# packets to port 80 are unblocked
echo 0 > /proc/net/ipt_condition/knockknock
# packets to port 80 are blocked again
```