# q9thrt
Q9Thrt (Quad9 Active Threat Response) is a service that is designed to protect and respond to user requests to malicious domains when browsing the internet. This system integrates with network infrastructure services including DNS, DHCP, and network firewall services to understand, react, and block threats from users attempting, many times completely unknowingly, to access known malicious websites. This capability builds on the [Quad9](https://www.globalcyberalliance.org/quad9/) DNS service provided by [Global Cyber Alliance](https://www.globalcyberalliance.org/) and extends the capability by providing this service that resides in local on-premise equipment to recognize when a malicious domain was requests and implementing additional network defenses to proactively protect the entire network. This service is unique because when a threat is triggered, *both* protections are added to restrict access to all the domain names associated with the threat *and also* restricting access to all direct `IP Addresses associated with the threat`.  

Initial integration has been completed using [OpenWRT platform](https://openwrt.org/) but could be integrated into many networking environments easily.

How this works:
* Installs Quad9 as the default DNS service for all domain name requests. Quad9 ONLY resolves domain name requests where a known threat DOES NOT exist.
* Monitors all DNS traffic on the local network looking ONLY for domain names that Quad9 would not resolve.
* Integrates with Quad9's API to determine if a domain name is associated with a known threat.
* Integrates with compatible threat intelligence providers to securely acquire details on all aspects of the associated threat. (See the discussion on the emerging Manufacturer Usage Description -- MUD -- IETF spec for more information on how this information is communicated.)
* Securely validates the threat intel information and applies policies to both DNS and Firewall network services to protect the entire network from this threat.
  * DNS Sinkhole techniques are used for the associated Internet domain names.
  * Firewall services are used to restrict access to the associated IP addresses.
* A threat configuration will age-off and be removed after 24 hours. The threat mitigation will simply be re-installed if triggered again.

For more information, please see the following contributors at:
* Global Cyber Alliance: https://www.globalcyberalliance.org/quad9/
* ThreatSTOP: https://www.threatstop.com/
* MasterPeace Solutions: https://www.mplaunchpad.com/
* IEFT MUD Specification: https://datatracker.ietf.org/doc/rfc8520/

## Dependencies

The "Q9Thrt" relies on understanding the DNS traffic on the network. It does this using tcpdump to capture specific, and only dns traffic, and route that information to logs for follow processing. If you are installing on OpenWRT using the OPKG artifact, library requirements will be installed automatically. If you are installing manually from GIT, the following packages are needed. (See openwrt_toolchain/Makefile for file locations if installing manually.) This installation has been tested for OpenWRT v18.06.1 (or greater) only at this point. It could easily be extended for other operating system environments.

 - libcurl, curl, ca-bundle, jq, openssl-util, ca-certificates, ipset, logrotate, tcpdump
 
 To install the dependencies manually under OpenWRT:
```
opkg install libcurl curl ca-bundle jq openssl-util ca-certificates ipset logrotate tcpdump
```
 
 ## How to use q9thrt?
Q9thrt is designed to easily build, deploy, and run on the OpenWRT platform. Additionally, there are integrations with the dnsmasq and OpenWRT firewall services. In the OpenWRT deployment, q9thrt is intended to be run as a service and installs to typical locations under the /etc filesystem. There are multiple configuration options, including where downloaded MUD files are stored, that must be configured when the application is run. When q9thrt is installed the service startup script installed under "/etc/init.d/q9thrt" and contains these default locations. These options can be changed depending on the needs of a particular deployment. For example, if the hardware has limited disk space, set the logging to use "/tmp/q9thrt-logs" so any longs are not maintained across reboots and not take persistent storage that may be limited.
 
 ## Building q9thrt
The build process requires creating an OpenWRT build environment and installing the Q9Thrt Makefile into the OpenWRT build environment, and then building the application. See information here on building the environment: https://openwrt.org/docs/guide-developer/build-system/use-buildsystem.

1. Clone https://github.com/osmud/threat_signaling
1. Create an q9thrt directory for OpenWRT within the build system at `lede/package/network/config/q9thrt`
1. Copy `q9thrt/openwrt_toolchain/Makefile` to `openwrt/package/network/config/q9thrt/Makefile`
1. Run `make menuconfig`
1. Select q9thrt in under `Base System -> q9thrt` (move to the q9thrt line and hit "y" to include in the build)
1. Run `make package/network/config/q9thrt/compile` to compile only q9thrt

This last command builds q9thrt into the OPKG artifact (depending on target architecture): 
```
bin/packages/mips_24kc/base/q9thrt_1.0-1_mips_24kc.ipk
```
# Installing

Installing on OpenWRT using the "opkg" infrastructure is very straight forward. To complete, perform these steps:

1. Make sure the OpenWRT router is updated to the base OS v18.06.1 or above before you continue.
1. Place the q9thrt IPK file onto the OpenWRT system into /tmp.
1. Log into the router as root using your root password
1. Issue the command `"opkg update"`. This will download from the internet information on all of the available and installable packages.
1. Execute the command `"opkg install q9thrt_1.0-1_mips_24kc.ipk"`. This will install Q9Thrt and all required dependencies.
1. Edit the file `"/etc/config/dhcp"`. As a sample, use the example file found in `/etc/q9thrt/dhcp.q9sample.conf` as a template. Make the following modifications:
   * Change option `resolvfile` to be '/etc/q9thrt/resolv.conf' in section `config dnsmasq`
   * Add line `list dhcp_option '6,192.168.1.1'` in section `config dhcp 'lan'`
      * Make sure you use the IP address of YOUR NETWORK ROUTER above if the router is using an IP address other than the OpenWRT default router IP.
   * Restart DHCP service using the command: `/etc/init.d/dnsmasq restart`
   * Run the command `ps` and make sure there is a "dnsmasq" process running after the restart.
1. If the router has limited resources, it may be needed to move the log files under /tmp. Edit the file `/etc/init.d/q9thrt` and change the location `Q9_LOG_DIR` and `Q9_ARCHIVE_DIR`. Run the commands to restart the service:
   * /etc/init.d/q9thrt stop
   * /etc/init.d/q9thrt start

### Limitations, deviations and issues

This release is still experimental and there are areas that can be improved:
- Currently, the software only works for OpenWRT and when the software is installed in a single router setup where DNS and Firewall services are all provided on a single router.
- TCPDUMP is used to watch all DNS traffic and create log files that are interpreted by the software. Tighter integration with a DNS service could be more efficient in resource constrained execution environments.
- Currently, the structure of the MUD file is important.
- The system modifies the OpenWRT firewall configuration file directly. If using the OpenWRT web UI, making firewall configuration changes is not supported via the UI.
- IPv6 is not directly supported. Adding IPv6 support should be straight forward, but not included in this initial release.
- The software has been tested on multiple OpenWRT hardware platforms and is expected to run on hardware where tcpdump can be installed. However, it has not been tested across all supported OpenWRT hardware.