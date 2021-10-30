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

Now we capture all the apparmor complaints and build the profile automatically:   

`sudo aa-logprof`   (Use "I" for inherit, "A" for allow, and "S" for save.)

We recommend that you leave AppArmor in "complain" mode and monitor /var/log/syslog for any "apparmor=ALLOWED" events. 

