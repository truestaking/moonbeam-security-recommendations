#Moonbeam Collator Security Recommendations

*brought to you by TrueStaking*

In this guide, we assume you have followed the [moonbeam collator guidance](https://docs.moonbeam.network/node-operators/networks/collator/)

### Ode to Linux System Administration Generic Best Practices
You can find many good lists of generic best practices for Linux System Administrators to follow.  You can find short lists such as this [Cardano forum entry](https://forum.cardano.org/t/back-to-basics-security-measures-every-cardano-stake-pool-operators-should-know-and-implement/38166), or long and very detailed lists with tools for remediation such as the [CIS security benchmarks](https://ubuntu.com/blog/cis-hardened-ubuntu-cyber-attack-and-malware-prevention-for-mission-critical-systems).  

Here's the key point summary:    

**Minimize attack surfaces** -- *Don't run any services you don't absolutely NEED on your collator (Seriously, your collator should be a dedicated server devoted solely to the task of collating for Moonbeam -- you should literally have only SSHD and the velas service accepting remote connections on your validator)*    

**Avoid weak remote access** -- *run SSHD on a non-standard port. Disable password based authentication and require SSH keys for authentication. Disallow remote root logins.*

**Make escalation of privileges difficult** *Keep tight controls on user and group permissions, and force all administrative activity to use the SUDO mechanism*
  
**Control Incoming Network Connections** -- *Use a hostbased firewall (UFW, IPtables, or NFtables) and tightly control inbound connections*
  
**Address Emerging Vulnerabilities** -- *Keep your server fully patched and updated*
  
**Reduce Impact from Exploitation** -- *Run moonbeam_service from systemd as an un-privileged user*

-----------------------------------------

While instructions for the above items is easily found on the Internet, if you have any questions feel free to reach out.
@perltk (telegram)
 
Ready to go beyond the cyber security basics? 
  
## Advanced Detective/Preventive Control:  AppArmor  

AppArmor is a kernel level mechanism to assign rights to a running process and restrict what files/directories the process can read/write/update.  Using AppArmor addresses two security concerns: 1) the service could be exploited remotely as it is exposed to external connections and 2) the source code could be manipulated. *(Of course, we don't believe either compromise is probable but the Solarwinds debacle of 2020 and the plethora of monthly patches for remote exploits dictates that we take prudent precautions.)*  Thus, it makes sense to secure the service with AppArmor.  

AppArmor is installed and loaded by default in modern Ubuntu. However, we will want to install the optional AppArmor utils package.  

`sudo apt install apparmor-utils`

Next, we create an AppArmor profile for our velas-validator service.  Profiles are simply text files stored in /etc/apparmor.d/ The only trick is, the filename of the profile must match the full path and name of the executable where every "/" in the pathname becomes a "." in the filename.  If you followed the validator installation instructions referenced at the beginning of this document, then your executable should be in /var/lib/moonriver-data. 

Now, convert the full path into a file name by replacing all "/" with "." and  /var/lib/moonriver-data/moonbeam becomes var.lib.moonriver-data.moonbeam  
  
Armed with this knowledge, with the editor of your choice, create /etc/apparmor.d/var.lib.moonriver-data.moonbeam with the following content:  

`vi /etc/apparmor.d/var.lib.moonriver-data.moonbeam`

    #include <tunables/global>
    /var/lib/moon-river-data/moonbeam flags=(complain) {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/openssl>
    /sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us r,
    owner /proc/*/cgroup r,
    owner /proc/*/mountinfo r,
    owner /proc/*/task/** rw,
    owner /var/lib/moonriver-data/** rw,
    }

*Note that we specified "complain" mode*, and thus the system won't block any access but will allow and log all access outside the defined access.* 

Now enable the profile with `sudo aa-complain /var/lib/moonriver-data/moonbeam`  
If no errors, then let this run.  You can see any logs in /var/log/syslog.  

This profile should be effective if you have followed the moonbeam node guidance -- specifically, note the last line of the apparmor config file assumes the location of the data directory. Adjust the config if you need to... 

When you are satisfied with the config, then you let it run for a while and update the profile with:   

`sudo aa-logprof`   (Use "I" for inherit, "A" for allow, and "S" for save.)

We recommend that you leave AppArmor in "complain" mode and monitor /var/log/syslog for any "apparmor=ALLOWED" events. 
*(We'll walk through this alerting scenario in the appendix.)*

## Advanced Perimeter Protections

A foundational tenet of cyber security is, "Always be 2 or more controls away from failure."

A firewall is a key control protecting the server from unwanted or unexpected network connectivity, but as you will see, a firewall can be much more than that!

If you already have a firewall in place, let's remove it. The base firewall that comes with Ubuntu is UFW (Uncomplicated Firewall -- which is just a frontend for the traditional IPtables.) 
`sudo UFW disable`
`sudo UFW remove`
 
 *Note if you have a custom firewall already in place -- then you have the skills to remove it yourself, or evaluate what we propose here and choose what is best for you.

With firewall disabled, let's pause for a moment to implement another key control -- move the default port of SSH. Why do that now? Because with the firewall disabled, you won't accidentally lock yourself out if you get the port wrong.

    sudo vi /etc/ssh/sshd_config* and change the port to some custom port above 1024
    systemctl daemon-reload
    systecmtl restart sshd
 
Now, without closing your existing terminal session, open another terminal session and ssh to your collator.
    ssh -p $CUSTOM_PORT user@collator.yourdomain.com

If it works -- then you have successfully moved SSH to a custom port -- which is a Linux cyber security best practice. Hooray!

Returning to the firewall implementation:
    sudo apt install nftables

Now decide between standard and advanced firewall controls.

"Standard" is ingress controls only, allowing SSH to your custom port and Moonbeam communications. Everything else is blocked.

"Advanced" adds the additional feature of egress monitoring. In this configuration, we monitor and alert on anomalous egress. This is one of the strongest detective controls you can implement on a server as any hacker will need to initate outbound connectivity to pull down code, phone home for command and control, or abscond with your collator keys. In each case, the key is to detect that unusual egress activity.

##To deploy the "standard" firewall ##, based on the moonbeam node guidance and your custom SSH port, do the following:
1. determine the internet interface name `ip link` ![ip_link](https://user-images.githubusercontent.com/19353330/139602725-23bb766c-222e-4ace-8f3f-9fc126845680.jpg) Typically this will be "eth0" or "enp7s0" or similar.
2. recall the custom SSH port you selected above
3. `sudo vi /etc/nftables.conf`

Delete any existing contents in the file and insert the following text:
```

#!/usr/sbin/nft -f

flush ruleset
define IFNAME = IP_LINK
define SSH_PORT = YOUR_CUSTOM_PORT
define MOONBEAM_PORTS = { 9933, 9934, 9944, 9945, 30333, 30334 }
table ip filter {
  chain input {
		type filter hook input priority filter; policy drop;
		ct state invalid drop comment "early drop of invalid packets"
		ct state { established, related } accept comment "accept all connections related to connections made by us"
		iif "lo" accept comment "accept loopback"
		iif != "lo" ip daddr 127.0.0.0/8 drop comment "drop connections to loopback not coming from loopback"
		ip protocol icmp accept comment "accept all ICMP types"
    tcp dport $SSH_PORT accept comment "accept SSH"
	  tcp dport $MOONBEAM_PORTS accept comment "accept moonbeam traffic"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}
table ip6 filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state invalid drop comment "early drop of invalid packets"
		ct state { established, related } accept comment "accept all connections related to connections made by us"
		iif "lo" accept comment "accept loopback"
		iif != "lo" ip6 daddr ::1 drop comment "drop connections to loopback not coming from loopback"
		ip6 nexthdr ipv6-icmp accept comment "accept all ICMP types"
		tcp dport 5660 accept comment "accept SSH"
    tcp dport $MOONBEAM_PORTS accept comment "moonriver"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}

```
4. Be sure and replace IP_LINK with your own interface name that you found using "ip link"
5. Be sure and replace YOUR_CUSTOM_PORT with the port you selected for your SSH connections.
6. Save the file.


