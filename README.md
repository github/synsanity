# synsanity - DEPRECATED

This project has been deprecated. GitHub runs a Linux kernel with [lockless listen sockets](https://lwn.net/Articles/659199/) as of 2017.

---

synsanity is a netfilter (iptables) target for high performance lockless SYN cookies for SYN flood mitigation, as used in production at GitHub.

synsanity allows Linux servers running 3.x kernels to handle SYN floods with minimal (or at least less) performance impact. With default Linux kernel 3.x settings, a very small SYN flood causes complete CPU exhaustion as the kernel spinlocks on the LISTEN socket and in conntrack. synsanity moves much of this work into a netfilter (iptables) target and bypasses locks for this attack scenario, allowing high throughput syncookie generation before the packets hit the TCP stack.

The following components make up synsanity and its supporting setup:
 * [kmod: ipt_SYNSANITY](https://github.com/github/synsanity/blob/master/kmod/ipt_SYNSANITY.c) contains the kernel-side iptables module, where most of the work happens.
 * [kmod: xt_syncookies](https://github.com/github/synsanity/blob/master/kmod/xt_syncookies.c) contains iptables match targets for whether the kernel would generate or accept syncookies for the given packet's LISTEN socket.
 * [kmod: xt_condition](https://github.com/github/synsanity/blob/master/kmod/xt_condition.c) contains a condition match target, allowing dynamic control of a set of iptables rules from the proc filesystem.
 * [iptext](https://github.com/github/synsanity/tree/master/iptext) contains the client side iptables modules to configure the above modules.
 * [scripts](https://github.com/github/synsanity/tree/master/scripts) contains scripts to set up synsanity and its appropriate iptables rules.

## Building

This release is designed to work on Ubuntu 12.04 running the `linux-image-generic-lts-trusty` kernel (3.13.x), though it should also be possible to run on Trusty itself and other systems running 3.x kernels with very little modification.

The following dependencies are required to build synsanity on Ubuntu systems:
```
sudo apt-get install build-essential pkg-config dkms linux-headers-$(uname -r) iptables-dev
```

The simplest way to build and install the modules is using `dkms`:
```
cd .../synsanity
dkms build .
dkms install synsanity/0.1.2
```

To build and install the iptables CLI modules:
```
make -C iptext install
```

Then use the scripts to install the synsanity iptables rules (see Usage below for customisation instructions):
```
scripts/setup_synsanity
```

And check the status of synsanity on a given port:
```
# scripts/nagios_check_synsanity_port 80
SYNSANITY mitigation for port 80 is currently disabled. Everything is OK.
```

## Usage

The scripts provided here will set up synsanity on a specific set of public ports specified. The `setup_synsanity` script includes lines like the following:

```
add_synsanity_rule INPUT synsanity-mitigation-80 eth0 80
```

This hooks synsanity mitigation rules in the iptables `INPUT` chain using a condition called `synsanity-mitigation-80` on packets arriving on the interface `eth0` on port `80`.

In this case, the condition will be available at `/proc/net/ipt_condition/synsanity-mitigation-80` and will defualt to `0`, meaning synsanity is not intercepting packets. By default, when `add_synsanity_rule` sees a watermark of 90% on the SYN receive queue on the receiving socket, it will enable this condition (and the proc file will show `1`), and thus enable synsanity's mitigation on that port.

The scripts provided here don't automatically disable mitigation when an attack is over, but rather a nagios check script called `nagios_check_synsanity_port` is provided which shows how to create an alert based on mitigation. Manually enabling or disabling synsanity mitigation on a port is as simple as changing the condition:

```
echo 0 > /proc/net/ipt_condition/synsanity-mitigation-80 # disable mitigation on port 80
echo 1 > /proc/net/ipt_condition/synsanity-mitigation-80 # enable mitigation on port 80
```

## Contributions

Compatibility improvements, documentation updates and bug fixes are always welcome! Please check out our [Contributing Guidelines](CONTRIBUTING.md) and [Contributor Code of Conduct](CODE_OF_CONDUCT.md).

## License

The synsanity kernel modules and associated iptables CLI modules and build scripts are licensed under the [GPL](LICENSE.GPL) license. synsanity runtime scripts are licensed under the [MIT](LICENSE.MIT) license.
