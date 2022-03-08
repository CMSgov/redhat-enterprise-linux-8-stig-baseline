# RHEL8 STIG Automated Compliance Validation Profile

<b>RHEL 8.X</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>RHEL8</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>RHEL8</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

<b>**Please note: **</b> This RHEL8 Check Profile performs checks for both the VM Operating System and conatiner based UBI checks. Link [here](https://gitlab.dsolab.io/scv-content/inspec/operating-systems/redhat-enterprise-linux-8-stig-baseline/-/blob/master/README.md#normal-checks) for VM normal checks, and [here](https://gitlab.dsolab.io/scv-content/inspec/operating-systems/redhat-enterprise-linux-8-stig-baseline/-/blob/master/README.md#ubi8-container-applicable-checks) for the UBI list of checks.

## RHEL8 STIG Overview

The <b>RHEL8</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>RHEL8</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the RHEL8 STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:

- RHEL8 Security Technical Implementation Guide

### Update History

| Guidance Name                             | Guidance Version | Guidance Location                         | Profile Version | Profile Release Date | STIG EOL | Profile EOL |
| ----------------------------------------- | ---------------- | ----------------------------------------- | --------------- | -------------------- | -------- | ----------- |
| Red Hat Enterprise Linux 8 STIG Benchmark | v1r3             | https://public.cyber.mil/stigs/downloads/ | 2.0.1           | 09/02/2021           | NA       | NA          |
| Red Hat Enterprise Linux 8 STIG Benchmark | v1r3             | https://public.cyber.mil/stigs/downloads/ | 2.0.2           | 12/08/2021           | NA       | NA          |
| Red Hat Enterprise Linux 8 STIG Benchmark | v1r3             | https://public.cyber.mil/stigs/downloads/ | 2.1.0           | 12/14/2021           | NA       | NA          |

## Getting Started

### Requirements

#### RHEL8  
- Local or remote access to the RHEL8 Operating System
- Account providing appropriate permissions to perform audit scan

#### Required software on RHEL8 OS
- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on RHEL8 OS
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.

#### Ensure InSpec version is at least 4.23.10 
```sh
inspec --version
```

### Update Profile Input Values
Update the following `Inputs` in `inspec.yml` if the default values differ in your platform.

```yml
  - name: disable_slow_controls
    description: Controls that are known to consistently have long run times can be disabled with this attribute
    type: Boolean
    value: false

  #SV-230548
  - name: container_host
    description: Flag to designate if the target is a container host
    type: Boolean
    value: false

  # SV-230368
  - name: min_reuse_generations
    description: Number of reuse generations
    type: Numeric
    value: 5

  # SV-230369, SV-230370
  - name: min_len
    description: Minimum number of characters for a new password
    type: Numeric
    value: 15

  # SV-230234
  - name: grub_uefi_main_cfg
    description: Main grub boot config file
    type: String
    value: "/boot/efi/EFI/redhat/grub.cfg"

  - name: grub_uefi_user_boot_files
    description: Grub boot config files
    type: Array
    value: ["/boot/efi/EFI/redhat/user.cfg"]

  # SV-230317, SV-230321, SV-230322, SV-230325, SV-230328, SV-230309, SV-230320
  - name: exempt_home_users
    description: Users exempt from home directory-based controls in array format
    type: Array
    value: ["vagrant"]

  - name: non_interactive_shells
    description: These shells do not allow a user to login
    type: Array
    value:
      - "/sbin/nologin"
      - "/sbin/halt"
      - "/sbin/shutdown"
      - "/bin/false"
      - "/bin/sync"
      - "/bin/true"

  # SV-230379
  - name: known_system_accounts
    description: System accounts that support approved system activities.
    type: Array
    value:
      - "root"
      - "bin"
      - "daemon"
      - "adm"
      - "lp"
      - "sync"
      - "shutdown"
      - "halt"
      - "mail"
      - "operator"
      - "nobody"
      - "systemd-bus-proxy"
      - "dbus"
      - "polkitd"
      - "postfix"
      - "sssd"
      - "chrony"
      - "systemd-network"
      - "sshd"
      - "ntp"

  - name: user_accounts
    description: Accounts of known managed users
    type: Array
    value: ["vagrant"]

  # SV-230379
  - name: log_pkg_path
    description: The path to the logging package
    type: String
    value: "/etc/rsyslog.conf"

  # SV-230235
  - name: grub_main_cfg
    description: Main grub boot config file
    type: String
    value: "/boot/grub2/grub.cfg"

  - name: grub_user_boot_files
    description: Grub boot config files
    type: Array
    value:
      - "/boot/grub2/user.cfg"

  # SV-230537
  - name: ipv4_enabled
    description: Set to 'true' if IPv4 is enabled on the system.
    type: Boolean
    value: true

  # SV-230537
  - name: ipv6_enabled
    description: Set to 'true' if IPv6 is enabled on the system.
    type: Boolean
    value: true

  # SV-230493
  - name: camera_installed
    description: Device or system does not have a camera installed.
    type: Boolean
    value: true

  # SV-230503
  - name: bluetooth_installed
    description: 'Device or operating system has a Bluetooth adapter installed'
    type: Boolean
    value: true

  # SV-230242
  - name: known_system_accounts
    description: System accounts that support approved system activities.
    type: Array
    value: 
      - 'root'
      - 'bin'
      - 'daemon'
      - 'adm'
      - 'lp'
      - 'sync'
      - 'shutdown'
      - 'halt'
      - 'mail'
      - 'operator'
      - 'nobody'
      - 'systemd-bus-proxy'
      - 'dbus'
      - 'polkitd'
      - 'postfix'
      - 'sssd'
      - 'chrony'
      - 'systemd-network'
      - 'sshd'
      - 'ntp'

  - name: smart_card_status
    description: Smart card status (enabled or disabled)
    type: String
    value: 'enabled'

  # SV-230263
  - name: file_integrity_tool
    description: Name of tool
    type: String
    value: 'aide'
  # SV-230484
  - name: authoritative_timeserver
    description: Timeserver used in /etc/chrony.conf
    type: String
    value: 0.us.pool.ntp.mil

  # SV-230537
  - name: non_removable_media_fs
    description: File systems listed in /etc/fstab which are not removable media devices
    type: Array
    value: ["/", "/tmp", "none", "/home"]

  # SV-230230
  - name: private_key_files
    description: List of full paths to private key files on the system
    type: Array
    value: []

  #SV-230229
  - name: root_ca_file
    description: Path to an accepted trust anchor certificate file (DoD)
    type: String
    value: "/etc/sssd/pki/sssd_auth_ca_db.pem"

  #SV-230333
  - name: unsuccessful_attempts
    description: Maximum number of unsuccessful attempts before lockout
    type: Numeric
    value: 3

  #SV-230353
  - name: system_inactivity_timeout
    description: Maximum system inactivity timeout (time in seconds).
    type: Numeric
    value: 900

  #SV-230356
  - name: max_retry
    description: Maximum number of retry attempts for login
    type: Numeric
    value: 3

  #SV-230363
  - name: difok
    description: Minimum number of characters that must be different from previous password
    type: Numeric
    value: 8

  #SV-230373
  - name: days_of_inactivity
    description: Maximum number of days if account inactivity before account lockout
    type: Numeric
    value: 35

  - name: temporary_accounts
    description: Temporary user accounts
    type: Array
    value: []

  - name: banner_message_text_cli
    description: Banner message text for command line interface logins.
    type: String
    value: "You are accessing a U.S. Government (USG) Information System (IS) that is \
    provided for USG-authorized use only. By using this IS (which includes any \
    device attached to this IS), you consent to the following conditions: -The USG \
    routinely intercepts and monitors communications on this IS for purposes \
    including, but not limited to, penetration testing, COMSEC monitoring, network \
    operations and defense, personnel misconduct (PM), law enforcement (LE), and \
    counterintelligence (CI) investigations. -At any time, the USG may inspect and \
    seize data stored on this IS. -Communications using, or data stored on, this \
    IS are not private, are subject to routine monitoring, interception, and \
    search, and may be disclosed or used for any USG-authorized purpose. -This IS \
    includes security measures (e.g., authentication and access controls) to \
    protect USG interests--not for your personal benefit or privacy. \
    -Notwithstanding the above, using this IS does not constitute consent to PM, \
    LE or CI investigative searching or monitoring of the content of privileged \
    communications, or work product, related to personal representation or \
    services by attorneys, psychotherapists, or clergy, and their assistants. Such \
    communications and work product are private and confidential. See User \
    Agreement for details."


  - name: banner_message_text_ral
    description: Banner message text for remote access logins.
    type: String
    value: "You are accessing a U.S. Government (USG) Information System (IS) that is \
    provided for USG-authorized use only. By using this IS (which includes any \
    device attached to this IS), you consent to the following conditions: -The USG \
    routinely intercepts and monitors communications on this IS for purposes \
    including, but not limited to, penetration testing, COMSEC monitoring, network \
    operations and defense, personnel misconduct (PM), law enforcement (LE), and \
    counterintelligence (CI) investigations. -At any time, the USG may inspect and \
    seize data stored on this IS. -Communications using, or data stored on, this \
    IS are not private, are subject to routine monitoring, interception, and \
    search, and may be disclosed or used for any USG-authorized purpose. -This IS \
    includes security measures (e.g., authentication and access controls) to \
    protect USG interests--not for your personal benefit or privacy. \
    -Notwithstanding the above, using this IS does not constitute consent to PM, \
    LE or CI investigative searching or monitoring of the content of privileged \
    communications, or work product, related to personal representation or \
    services by attorneys, psychotherapists, or clergy, and their assistants. Such \
    communications and work product are private and confidential. See User \
    Agreement for details."

  - name: banner_message_text_gui
    description: Banner message text for graphical user interface logins.
    type: String
    value: "You are accessing a U.S. Government (USG) Information System (IS) that is \
    provided for USG-authorized use only. By using this IS (which includes any \
    device attached to this IS), you consent to the following conditions: -The USG \
    routinely intercepts and monitors communications on this IS for purposes \
    including, but not limited to, penetration testing, COMSEC monitoring, network \
    operations and defense, personnel misconduct (PM), law enforcement (LE), and \
    counterintelligence (CI) investigations. -At any time, the USG may inspect and \
    seize data stored on this IS. -Communications using, or data stored on, this \
    IS are not private, are subject to routine monitoring, interception, and \
    search, and may be disclosed or used for any USG-authorized purpose. -This IS \
    includes security measures (e.g., authentication and access controls) to \
    protect USG interests--not for your personal benefit or privacy. \
    -Notwithstanding the above, using this IS does not constitute consent to PM, \
    LE or CI investigative searching or monitoring of the content of privileged \
    communications, or work product, related to personal representation or \
    services by attorneys, psychotherapists, or clergy, and their assistants. Such \
    communications and work product are private and confidential. See User \
    Agreement for details."

  - name: maxlogins_limit
    description: Amount of max logins allowed
    type: String
    value: '10'

  - name: unsuccessful_attempts
    description: number of unsuccessful attempts
    type: Numeric
    value: 3

  - name: fail_interval
    description: Interval of time in which the consecutive failed logon attempts must occur in order for the account to be locked out (time in seconds)
    type: Numeric
    value: 900

  - name: lockout_time
    description: Minimum amount of time account must be locked out after failed logins. This attribute should never be set greater than 604800 (time in seconds).
    type: Numeric
    value: 604800

  - name: log_directory
    description: Documented tally log directory
    type: String
    value: '/var/log/faillock'
```

### How to execute this instance  
(See: https://www.inspec.io/docs/reference/cli/)




### How to execute this instance  
(See: https://www.inspec.io/docs/reference/cli/

#### Execute a single Control in the Profile 
**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.

```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --controls=<control_id> --show-progress
```

#### Execute a Single Control when password is required for privilege escalation 
```
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo --sudo-password=$SUDO_PASSWORD -i <your_PEM_KEY> --controls=<control_id> --show-progress
```

#### Execute a Single Control and save results as JSON 
```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --controls=<control_id> --show-progress --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
inspec exec <Profile>  -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --show-progress
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --show-progress  --reporter json:results.json
```

## Check Overview:

## **Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.


| Check Number | Description|
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SV-230221 | RHEL 8 must be a vendor-supported release. |
| SV-230222 | RHEL 8 vendor packaged system security patches and updates must be installed and up to date. |
| SV-230223 | RHEL 8 must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. |
| SV-230224 | All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection. |
| SV-230225 | RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a ssh logon. |
| SV-230226 | RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon. |
| SV-230227 | RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon. |
| SV-230228 | All RHEL 8 remote access methods must be monitored. |
| SV-230229 | RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor. |
| SV-230230 | RHEL 8, for certificate-based authentication, must enforce authorized access to the corresponding private key. |
| SV-230231 | RHEL 8 must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm. |
| SV-230232 | RHEL 8 must employ FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords. |
| SV-230233 | The RHEL 8 password-auth file must be configured to use a sufficient number of hashing rounds. |
| SV-230234 | RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user mode and maintenance. |
| SV-230235 | RHEL 8 operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes. |
| SV-230236 | RHEL 8 operating systems must require authentication upon booting into rescue mode. |
| SV-230237 | The RHEL 8 pam_unix.so module must be configured in the password-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication. |
| SV-230238 | RHEL 8 must prevent system daemons from using Kerberos for authentication. |
| SV-230239 | The krb5-workstation package must not be installed on RHEL 8. |
| SV-230240 | RHEL 8 must use a Linux Security Module configured to enforce limits on system services. |
| SV-230241 | RHEL 8 must have policycoreutils package installed. |
| SV-230242 | All RHEL 8 public directories must be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources. |
| SV-230243 | A sticky bit must be set on all RHEL 8 public directories to prevent unauthorized and unintended information transferred via shared system resources. |
| SV-230244 | RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements. |
| SV-230245 | The RHEL 8 /var/log/messages file must have mode 0640 or less permissive. |
| SV-230246 | The RHEL 8 /var/log/messages file must be owned by root. |
| SV-230247 | The RHEL 8 /var/log/messages file must be group-owned by root. |
| SV-230248 | The RHEL 8 /var/log directory must have mode 0755 or less permissive. |
| SV-230249 | The RHEL 8 /var/log directory must be owned by root. |
| SV-230250 | The RHEL 8 /var/log directory must be group-owned by root. |
| SV-230251 | The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms. |
| SV-230252 | The RHEL 8 operating system must implement DoD-approved encryption to protect the confidentiality of SSH server connections. |
| SV-230253 | RHEL 8 must ensure the SSH server uses strong entropy. |
| SV-230254 | The RHEL 8 operating system must implement DoD-approved encryption in the OpenSSL package. |
| SV-230255 | The RHEL 8 operating system must implement DoD-approved TLS encryption in the OpenSSL package. |
| SV-230256 | The RHEL 8 operating system must implement DoD-approved TLS encryption in the GnuTLS package. |
| SV-230257 | RHEL 8 system commands must have mode 0755 or less permissive. |
| SV-230258 | RHEL 8 system commands must be owned by root. |
| SV-230259 | RHEL 8 system commands must be group-owned by root or a system account. |
| SV-230260 | RHEL 8 library files must have mode 0755 or less permissive. |
| SV-230261 | RHEL 8 library files must be owned by root. |
| SV-230262 | RHEL 8 library files must be group-owned by root or a system account. |
| SV-230263 | The RHEL 8 file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency. |
| SV-230264 | RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. |
| SV-230265 | RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. |
| SV-230266 | RHEL 8 must prevent the loading of a new kernel for later execution. |
| SV-230267 | RHEL 8 must enable kernel parameters to enforce discretionary access control on symlinks. |
| SV-230268 | RHEL 8 must enable kernel parameters to enforce discretionary access control on hardlinks. |
| SV-230269 | RHEL 8 must restrict access to the kernel message buffer. |
| SV-230270 | RHEL 8 must prevent kernel profiling by unprivileged users. |
| SV-230271 | RHEL 8 must require users to provide a password for privilege escalation. |
| SV-230272 | RHEL 8 must require users to reauthenticate for privilege escalation. |
| SV-230273 | RHEL 8 must have the packages required for multifactor authentication installed. |
| SV-230274 | RHEL 8 must implement certificate status checking for multifactor authentication. |
| SV-230275 | RHEL 8 must accept Personal Identity Verification (PIV) credentials. |
| SV-230276 | RHEL 8 must implement non-executable data to protect its memory from unauthorized code execution. |
| SV-230277 | RHEL 8 must clear the page allocator to prevent use-after-free attacks. |
| SV-230278 | RHEL 8 must disable virtual syscalls. |
| SV-230279 | RHEL 8 must clear SLUB/SLAB objects to prevent use-after-free attacks. |
| SV-230280 | RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution. |
| SV-230281 | YUM must remove all software components after updated versions have been installed on RHEL 8. |
| SV-230282 | RHEL 8 must enable the SELinux targeted policy. |
| SV-230283 | There must be no shosts.equiv files on the RHEL 8 operating system. |
| SV-230284 | There must be no .shosts files on the RHEL 8 operating system. |
| SV-230285 | RHEL 8 must enable the hardware random number generator entropy gatherer service. |
| SV-230286 | The RHEL 8 SSH public host key files must have mode 0644 or less permissive. |
| SV-230287 | The RHEL 8 SSH private host key files must have mode 0600 or less permissive. |
| SV-230288 | The RHEL 8 SSH daemon must perform strict mode checking of home directory configuration files. |
| SV-230289 | The RHEL 8 SSH daemon must not allow compression or must only allow compression after successful authentication. |
| SV-230290 | The RHEL 8 SSH daemon must not allow authentication using known host‚Äôs authentication. |
| SV-230291 | The RHEL 8 SSH daemon must not allow Kerberos authentication, except to fulfill documented and validated mission requirements. |
| SV-230292 | RHEL 8 must use a separate file system for /var. |
| SV-230293 | RHEL 8 must use a separate file system for /var/log. |
| SV-230294 | RHEL 8 must use a separate file system for the system audit data path. |
| SV-230295 | A separate RHEL 8 filesystem must be used for the /tmp directory. |
| SV-230296 | RHEL 8 must not permit direct logons to the root account using remote access via SSH. |
| SV-230297 | The auditd service must be running in RHEL 8. |
| SV-230298 | The rsyslog service must be running in RHEL 8. |
| SV-230299 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories. |
| SV-230300 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the /boot directory. |
| SV-230301 | RHEL 8 must prevent special devices on non-root local partitions. |
| SV-230302 | RHEL 8 must prevent code from being executed on file systems that contain user home directories. |
| SV-230303 | RHEL 8 must prevent special devices on file systems that are used with removable media. |
| SV-230304 | RHEL 8 must prevent code from being executed on file systems that are used with removable media. |
| SV-230305 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media. |
| SV-230306 | RHEL 8 must prevent code from being executed on file systems that are imported via Network File System (NFS). |
| SV-230307 | RHEL 8 must prevent special devices on file systems that are imported via Network File System (NFS). |
| SV-230308 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS). |
| SV-230309 | Local RHEL 8 initialization files must not execute world-writable programs. |
| SV-230310 | RHEL 8 must disable kernel dumps unless needed. |
| SV-230311 | RHEL 8 must disable the kernel.core_pattern. |
| SV-230312 | RHEL 8 must disable acquiring, saving, and processing core dumps. |
| SV-230313 | RHEL 8 must disable core dumps for all users. |
| SV-230314 | RHEL 8 must disable storing core dumps. |
| SV-230315 | RHEL 8 must disable core dump backtraces. |
| SV-230316 | For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured. |
| SV-230317 | Executable search paths within the initialization files of all local interactive RHEL 8 users must only contain paths that resolve to the system default or the users home directory. |
| SV-230318 | All RHEL 8 world-writable directories must be owned by root, sys, bin, or an application user. |
| SV-230319 | All RHEL 8 world-writable directories must be group-owned by root, sys, bin, or an application group. |
| SV-230320 | All RHEL 8 local interactive users must have a home directory assigned in the /etc/passwd file. |
| SV-230321 | All RHEL 8 local interactive user home directories must have mode 0750 or less permissive. |
| SV-230322 | All RHEL 8 local interactive user home directories must be group-owned by the home directory owner‚Äôs primary group. |
| SV-230323 | All RHEL 8 local interactive user home directories defined in the /etc/passwd file must exist. |
| SV-230324 | All RHEL 8 local interactive user accounts must be assigned a home directory upon creation. |
| SV-230325 | All RHEL 8 local initialization files must have mode 0740 or less permissive. |
| SV-230326 | All RHEL 8 local files and directories must have a valid owner. |
| SV-230327 | All RHEL 8 local files and directories must have a valid group owner. |
| SV-230328 | A separate RHEL 8 filesystem must be used for user home directories (such as /home or an equivalent). |
| SV-230329 | Unattended or automatic logon via the RHEL 8 graphical user interface must not be allowed. |
| SV-230330 | RHEL 8 must not allow users to override SSH environment variables. |
| SV-230331 | RHEL 8 temporary user accounts must be provisioned with an expiration time of 72 hours or less. |
| SV-230332 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur. |
| SV-230333 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur. |
| SV-230334 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230335 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230336 | RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230337 | RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230338 | RHEL 8 must ensure account lockouts persist. |
| SV-230339 | RHEL 8 must ensure account lockouts persist. |
| SV-230340 | RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur. |
| SV-230341 | RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur. |
| SV-230342 | RHEL 8 must log user name information when unsuccessful logon attempts occur. |
| SV-230343 | RHEL 8 must log user name information when unsuccessful logon attempts occur. |
| SV-230344 | RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230345 | RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230346 | RHEL 8 must limit the number of concurrent sessions to ten for all accounts and/or account types. |
| SV-230347 | RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions. |
| SV-230348 | RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for command line sessions. |
| SV-230349 | RHEL 8 must ensure session control is automatically started at shell initialization. |
| SV-230350 | RHEL 8 must prevent users from disabling session control mechanisms. |
| SV-230351 | RHEL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed. |
| SV-230352 | RHEL 8 must automatically lock graphical user sessions after 15 minutes of inactivity. |
| SV-230353 | RHEL 8 must automatically lock command line user sessions after 15 minutes of inactivity. |
| SV-230354 | RHEL 8 must prevent a user from overriding the session lock-delay setting for the graphical user interface. |
| SV-230355 | RHEL 8 must map the authenticated identity to the user or group account for PKI-based authentication. |
| SV-230356 | RHEL 8 must ensure a password complexity module is enabled. |
| SV-230357 | RHEL 8 must enforce password complexity by requiring that at least one uppercase character be used. |
| SV-230358 | RHEL 8 must enforce password complexity by requiring that at least one lower-case character be used. |
| SV-230359 | RHEL 8 must enforce password complexity by requiring that at least one numeric character be used. |
| SV-230360 | RHEL 8 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed. |
| SV-230361 | RHEL 8 must require the maximum number of repeating characters be limited to three when passwords are changed. |
| SV-230362 | RHEL 8 must require the change of at least four character classes when passwords are changed. |
| SV-230363 | RHEL 8 must require the change of at least 8 characters when passwords are changed. |
| SV-230364 | RHEL 8 passwords must have a 24 hours/1 day minimum password lifetime restriction in /etc/shadow. |
| SV-230365 | RHEL 8 passwords for new users or password changes must have a 24 hours/1 day minimum password lifetime restriction in /etc/logins.def. |
| SV-230366 | RHEL 8 user account passwords must have a 60-day maximum password lifetime restriction. |
| SV-230367 | RHEL 8 user account passwords must be configured so that existing passwords are restricted to a 60-day maximum lifetime. |
| SV-230368 | RHEL 8 passwords must be prohibited from reuse for a minimum of five generations. |
| SV-230369 | RHEL 8 passwords must have a minimum of 15 characters. |
| SV-230370 | RHEL 8 passwords for new users must have a minimum of 15 characters. |
| SV-230371 | RHEL 8 duplicate User IDs (UIDs) must not exist for interactive users. |
| SV-230372 | RHEL 8 must implement smart card logon for multifactor authentication for access to interactive accounts. |
| SV-230373 | RHEL 8 account identifiers (individuals, groups, roles, and devices) must be disabled after 35 days of inactivity. |
| SV-230374 | RHEL 8 emergency accounts must be automatically removed or disabled after the crisis is resolved or within 72 hours. |
| SV-230375 | All RHEL 8 passwords must contain at least one special character. |
| SV-230376 | RHEL 8 must prohibit the use of cached authentications after one day. |
| SV-230377 | RHEL 8 must prevent the use of dictionary words for passwords. |
| SV-230378 | RHEL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt. |
| SV-230379 | RHEL 8 must not have unnecessary accounts. |
| SV-230380 | RHEL 8 must not allow accounts configured with blank or null passwords. |
| SV-230381 | RHEL 8 must display the date and time of the last successful account logon upon logon. |
| SV-230382 | RHEL 8 must display the date and time of the last successful account logon upon an SSH logon. |
| SV-230383 | RHEL 8 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files. |
| SV-230384 | RHEL 8 must set the umask value to 077 for all local interactive user accounts. |
| SV-230385 | RHEL 8 must define default permissions for logon and non-logon shells. |
| SV-230386 | The RHEL 8 audit system must be configured to audit the execution of privileged functions and prevent all software from executing at higher privilege levels than users executing the software. |
| SV-230387 | Cron logging must be implemented in RHEL 8. |
| SV-230388 | The RHEL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted of an audit processing failure event. |
| SV-230389 | The RHEL 8 Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) must have mail aliases to be notified of an audit processing failure. |
| SV-230390 | The RHEL 8 System must take appropriate action when an audit processing failure occurs. |
| SV-230391 | The RHEL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted when the audit storage volume is full. |
| SV-230392 | The RHEL 8 audit system must take appropriate action when the audit storage volume is full. |
| SV-230393 | The RHEL 8 audit system must audit local events. |
| SV-230394 | RHEL 8 must label all off-loaded audit logs before sending them to the central log server. |
| SV-230395 | RHEL 8 must resolve audit information before writing to disk. |
| SV-230396 | RHEL 8 audit logs must have a mode of 0600 or less permissive to prevent unauthorized read access. |
| SV-230397 | RHEL 8 audit logs must be owned by root to prevent unauthorized read access. |
| SV-230398 | RHEL 8 audit logs must be group-owned by root to prevent unauthorized read access. |
| SV-230399 | RHEL 8 audit log directory must be owned by root to prevent unauthorized read access. |
| SV-230400 | RHEL 8 audit log directory must be group-owned by root to prevent unauthorized read access. |
| SV-230401 | RHEL 8 audit log directory must have a mode of 0700 or less permissive to prevent unauthorized read access. |
| SV-230402 | RHEL 8 audit system must protect auditing rules from unauthorized change. |
| SV-230403 | RHEL 8 audit system must protect logon UIDs from unauthorized change. |
| SV-230404 | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow. |
| SV-230405 | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd. |
| SV-230406 | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd. |
| SV-230407 | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow. |
| SV-230408 | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group. |
| SV-230409 | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers. |
| SV-230410 | RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d/. |
| SV-230411 | The RHEL 8 audit package must be installed. |
| SV-230412 | Successful/unsuccessful uses of the su command in RHEL 8 must generate an audit record. |
| SV-230413 | The RHEL 8 audit system must be configured to audit any usage of the lremovexattr system call. |
| SV-230414 | The RHEL 8 audit system must be configured to audit any usage of the removexattr system call. |
| SV-230415 | The RHEL 8 audit system must be configured to audit any usage of the lsetxattr system call. |
| SV-230416 | The RHEL 8 audit system must be configured to audit any usage of the fsetxattr system call. |
| SV-230417 | The RHEL 8 audit system must be configured to audit any usage of the fremovexattr system call. |
| SV-230418 | Successful/unsuccessful uses of the chage command in RHEL 8 must generate an audit record. |
| SV-230419 | Successful/unsuccessful uses of the chcon command in RHEL 8 must generate an audit record. |
| SV-230420 | The RHEL 8 audit system must be configured to audit any usage of the setxattr system call. |
| SV-230421 | Successful/unsuccessful uses of the ssh-agent in RHEL 8 must generate an audit record. |
| SV-230422 | Successful/unsuccessful uses of the passwd command in RHEL 8 must generate an audit record. |
| SV-230423 | Successful/unsuccessful uses of the mount command in RHEL 8 must generate an audit record. |
| SV-230424 | Successful/unsuccessful uses of the umount command in RHEL 8 must generate an audit record. |
| SV-230425 | Successful/unsuccessful uses of the mount syscall in RHEL 8 must generate an audit record. |
| SV-230426 | Successful/unsuccessful uses of the unix_update in RHEL 8 must generate an audit record. |
| SV-230427 | Successful/unsuccessful uses of postdrop in RHEL 8 must generate an audit record. |
| SV-230428 | Successful/unsuccessful uses of postqueue in RHEL 8 must generate an audit record. |
| SV-230429 | Successful/unsuccessful uses of semanage in RHEL 8 must generate an audit record. |
| SV-230430 | Successful/unsuccessful uses of setfiles in RHEL 8 must generate an audit record. |
| SV-230431 | Successful/unsuccessful uses of userhelper in RHEL 8 must generate an audit record. |
| SV-230432 | Successful/unsuccessful uses of setsebool in RHEL 8 must generate an audit record. |
| SV-230433 | Successful/unsuccessful uses of unix_chkpwd in RHEL 8 must generate an audit record. |
| SV-230434 | Successful/unsuccessful uses of the ssh-keysign in RHEL 8 must generate an audit record. |
| SV-230435 | Successful/unsuccessful uses of the setfacl command in RHEL 8 must generate an audit record. |
| SV-230436 | Successful/unsuccessful uses of the pam_timestamp_check command in RHEL 8 must generate an audit record. |
| SV-230437 | Successful/unsuccessful uses of the newgrp command in RHEL 8 must generate an audit record. |
| SV-230438 | Successful/unsuccessful uses of the init_module command in RHEL 8 must generate an audit record. |
| SV-230439 | Successful/unsuccessful uses of the rename command in RHEL 8 must generate an audit record. |
| SV-230440 | Successful/unsuccessful uses of the renameat command in RHEL 8 must generate an audit record. |
| SV-230441 | Successful/unsuccessful uses of the rmdir command in RHEL 8 must generate an audit record. |
| SV-230442 | Successful/unsuccessful uses of the unlink command in RHEL 8 must generate an audit record. |
| SV-230443 | Successful/unsuccessful uses of the unlinkat command in RHEL 8 must generate an audit record. |
| SV-230444 | Successful/unsuccessful uses of the gpasswd command in RHEL 8 must generate an audit record. |
| SV-230445 | Successful/unsuccessful uses of the finit_module command in RHEL 8 must generate an audit record. |
| SV-230446 | Successful/unsuccessful uses of the delete_module command in RHEL 8 must generate an audit record. |
| SV-230447 | Successful/unsuccessful uses of the crontab command in RHEL 8 must generate an audit record. |
| SV-230448 | Successful/unsuccessful uses of the chsh command in RHEL 8 must generate an audit record. |
| SV-230449 | Successful/unsuccessful uses of the truncate command in RHEL 8 must generate an audit record. |
| SV-230450 | Successful/unsuccessful uses of the openat system call in RHEL 8 must generate an audit record. |
| SV-230451 | Successful/unsuccessful uses of the open system call in RHEL 8 must generate an audit record. |
| SV-230452 | Successful/unsuccessful uses of the open_by_handle_at system call in RHEL 8 must generate an audit record. |
| SV-230453 | Successful/unsuccessful uses of the ftruncate command in RHEL 8 must generate an audit record. |
| SV-230454 | Successful/unsuccessful uses of the creat system call in RHEL 8 must generate an audit record. |
| SV-230455 | Successful/unsuccessful uses of the chown command in RHEL 8 must generate an audit record. |
| SV-230456 | Successful/unsuccessful uses of the chmod command in RHEL 8 must generate an audit record. |
| SV-230457 | Successful/unsuccessful uses of the lchown system call in RHEL 8 must generate an audit record. |
| SV-230458 | Successful/unsuccessful uses of the fchownat system call in RHEL 8 must generate an audit record. |
| SV-230459 | Successful/unsuccessful uses of the fchown system call in RHEL 8 must generate an audit record. |
| SV-230460 | Successful/unsuccessful uses of the fchmodat system call in RHEL 8 must generate an audit record. |
| SV-230461 | Successful/unsuccessful uses of the fchmod system call in RHEL 8 must generate an audit record. |
| SV-230462 | Successful/unsuccessful uses of the sudo command in RHEL 8 must generate an audit record. |
| SV-230463 | Successful/unsuccessful uses of the usermod command in RHEL 8 must generate an audit record. |
| SV-230464 | Successful/unsuccessful uses of the chacl command in RHEL 8 must generate an audit record. |
| SV-230465 | Successful/unsuccessful uses of the kmod command in RHEL 8 must generate an audit record. |
| SV-230466 | Successful/unsuccessful modifications to the faillock log file in RHEL 8 must generate an audit record. |
| SV-230467 | Successful/unsuccessful modifications to the lastlog file in RHEL 8 must generate an audit record. |
| SV-230468 | RHEL 8 must enable auditing of processes that start prior to the audit daemon. |
| SV-230469 | RHEL 8 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon. |
| SV-230470 | RHEL 8 must enable Linux audit logging for the USBGuard daemon. |
| SV-230471 | RHEL 8 must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited. |
| SV-230472 | RHEL 8 audit tools must have a mode of 0755 or less permissive. |
| SV-230473 | RHEL 8 audit tools must be owned by root. |
| SV-230474 | RHEL 8 audit tools must be group-owned by root. |
| SV-230475 | RHEL 8 must use cryptographic mechanisms to protect the integrity of audit tools. |
| SV-230476 | RHEL 8 must allocate audit record storage capacity to store at least one week of audit records, when audit records are not immediately sent to a central audit record storage facility. |
| SV-230477 | RHEL 8 must have the packages required for offloading audit logs installed. |
| SV-230478 | RHEL 8 must have the packages required for encrypting offloaded audit logs installed. |
| SV-230479 | The RHEL 8 audit records must be off-loaded onto a different system or storage media from the system being audited. |
| SV-230480 | RHEL 8 must take appropriate action when the internal event queue is full. |
| SV-230481 | RHEL 8 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited. |
| SV-230482 | RHEL 8 must authenticate the remote logging server for off-loading audit logs. |
| SV-230483 | RHEL 8 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity. |
| SV-230484 | RHEL 8 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). |
| SV-230485 | RHEL 8 must disable the chrony daemon from acting as a server. |
| SV-230486 | RHEL 8 must disable network management of the chrony daemon. |
| SV-230487 | RHEL 8 must not have the telnet-server package installed. |
| SV-230488 | RHEL 8 must not have any automated bug reporting tools installed. |
| SV-230489 | RHEL 8 must not have the sendmail package installed. |
| SV-230491 | RHEL 8 must enable mitigations against processor-based vulnerabilities. |
| SV-230492 | RHEL 8 must not have the rsh-server package installed. |
| SV-230493 | RHEL 8 must cover or disable the built-in or attached camera when not in use. |
| SV-230494 | RHEL 8 must disable the asynchronous transfer mode (ATM) protocol. |
| SV-230495 | RHEL 8 must disable the controller area network (CAN) protocol. |
| SV-230496 | RHEL 8 must disable the stream control transmission protocol (SCTP). |
| SV-230497 | RHEL 8 must disable the transparent inter-process communication (TIPC) protocol. |
| SV-230498 | RHEL 8 must disable mounting of cramfs. |
| SV-230499 | RHEL 8 must disable IEEE 1394 (FireWire) Support. |
| SV-230500 | RHEL 8 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments. |
| SV-230502 | The RHEL 8 file system automounter must be disabled unless required. |
| SV-230503 | RHEL 8 must be configured to disable USB mass storage. |
| SV-230504 | A RHEL 8 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems. |
| SV-230505 | A firewall must be installed on RHEL 8. |
| SV-230506 | RHEL 8 wireless network adapters must be disabled. |
| SV-230507 | RHEL 8 Bluetooth must be disabled. |
| SV-230508 | RHEL 8 must mount /dev/shm with the nodev option. |
| SV-230509 | RHEL 8 must mount /dev/shm with the nosuid option. |
| SV-230510 | RHEL 8 must mount /dev/shm with the noexec option. |
| SV-230511 | RHEL 8 must mount /tmp with the nodev option. |
| SV-230512 | RHEL 8 must mount /tmp with the nosuid option. |
| SV-230513 | RHEL 8 must mount /tmp with the noexec option. |
| SV-230514 | RHEL 8 must mount /var/log with the nodev option. |
| SV-230515 | RHEL 8 must mount /var/log with the nosuid option. |
| SV-230516 | RHEL 8 must mount /var/log with the noexec option. |
| SV-230517 | RHEL 8 must mount /var/log/audit with the nodev option. |
| SV-230518 | RHEL 8 must mount /var/log/audit with the nosuid option. |
| SV-230519 | RHEL 8 must mount /var/log/audit with the noexec option. |
| SV-230520 | RHEL 8 must mount /var/tmp with the nodev option. |
| SV-230521 | RHEL 8 must mount /var/tmp with the nosuid option. |
| SV-230522 | RHEL 8 must mount /var/tmp with the noexec option. |
| SV-230523 | The RHEL 8 fapolicy module must be installed. |
| SV-230524 | RHEL 8 must block unauthorized peripherals before establishing a connection. |
| SV-230525 | A firewall must be able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces. |
| SV-230526 | All RHEL 8 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission. |
| SV-230527 | RHEL 8 must force a frequent session key renegotiation for SSH connections to the server. |
| SV-230529 | The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 8. |
| SV-230530 | The x86 Ctrl-Alt-Delete key sequence in RHEL 8 must be disabled if a graphical user interface is installed. |
| SV-230531 | The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be disabled. |
| SV-230532 | The debug-shell systemd service must be disabled on RHEL 8. |
| SV-230533 | The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for RHEL 8 operational support. |
| SV-230534 | The root account must be the only account having unrestricted access to the RHEL 8 system. |
| SV-230535 | RHEL 8 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted. |
| SV-230536 | RHEL 8 must not send Internet Control Message Protocol (ICMP) redirects. |
| SV-230537 | RHEL 8 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address. |
| SV-230538 | RHEL 8 must not forward IPv6 source-routed packets. |
| SV-230539 | RHEL 8 must not forward IPv6 source-routed packets by default. |
| SV-230540 | RHEL 8 must not be performing packet forwarding unless the system is a router. |
| SV-230541 | RHEL 8 must not accept router advertisements on all IPv6 interfaces. |
| SV-230542 | RHEL 8 must not accept router advertisements on all IPv6 interfaces by default. |
| SV-230543 | RHEL 8 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default. |
| SV-230544 | RHEL 8 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages. |
| SV-230545 | RHEL 8 must disable access to network bpf syscall from unprivileged processes. |
| SV-230546 | RHEL 8 must restrict usage of ptrace to descendant  processes. |
| SV-230547 | RHEL 8 must restrict exposed kernel pointer addresses access. |
| SV-230548 | RHEL 8 must disable the use of user namespaces. |
| SV-230549 | RHEL 8 must use reverse path filtering on all IPv4 interfaces. |
| SV-230550 | RHEL 8 must be configured to prevent unrestricted mail relaying. |
| SV-230551 | The RHEL 8 file integrity tool must be configured to verify extended attributes. |
| SV-230552 | The RHEL 8 file integrity tool must be configured to verify Access Control Lists (ACLs). |
| SV-230553 | The graphical display manager must not be installed on RHEL 8 unless approved. |
| SV-230554 | RHEL 8 network interfaces must not be in promiscuous mode. |
| SV-230555 | RHEL 8 remote X connections for interactive users must be disabled unless to fulfill documented and validated mission requirements. |
| SV-230556 | The RHEL 8 SSH daemon must prevent remote hosts from connecting to the proxy display. |
| SV-230557 | If the Trivial File Transfer Protocol (TFTP) server is required, the RHEL 8 TFTP daemon must be configured to operate in secure mode. |
| SV-230558 | A File Transfer Protocol (FTP) server package must not be installed unless mission essential on RHEL 8. |
| SV-230559 | The gssproxy package must not be installed unless mission essential on RHEL 8. |
| SV-230560 | The iprutils package must not be installed unless mission essential on RHEL 8. |
| SV-230561 | The tuned package must not be installed unless mission essential on RHEL 8. |
| SV-237640 | The krb5-server package must not be installed on RHEL 8. |
| SV-237641 | RHEL 8 must restrict privilege elevation to authorized personnel. |
| SV-237642 | RHEL 8 must use the invoking user's password for privilege escalation when using "sudo". |
| SV-237643 | RHEL 8 must require re-authentication when using the "sudo" command. |
| SV-244519 | RHEL 8 must display a banner before granting local or remote access to the system via a graphical user logon. |
| SV-244520 | The RHEL 8 system-auth file must be configured to use a sufficient number of hashing rounds. |
| SV-244521 | RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require a unique superusers name upon booting into single-user mode and maintenance. |
| SV-244522 | RHEL 8 operating systems booted with a BIOS must require  a unique superusers name upon booting into single-user and maintenance modes. |
| SV-244523 | RHEL 8 operating systems must require authentication upon booting into emergency mode. |
| SV-244524 | The RHEL 8 pam_unix.so module must be configured in the system-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication. |
| SV-244525 | The RHEL 8 SSH daemon must be configured with a timeout interval. |
| SV-244526 | The RHEL 8 SSH daemon must be configured to use system-wide crypto policies. |
| SV-244527 | RHEL 8 must have the packages required to use the hardware random number generator entropy gatherer service. |
| SV-244528 | The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements. |
| SV-244529 | RHEL 8 must use a separate file system for /var/tmp. |
| SV-244530 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory. |
| SV-244531 | All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive. |
| SV-244532 | RHEL 8 must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member. |
| SV-244533 | RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file. |
| SV-244534 | RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file. |
| SV-244535 | RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated. |
| SV-244536 | RHEL 8 must disable the user list at logon for graphical user interfaces. |
| SV-244537 | RHEL 8 must have the tmux package installed. |
| SV-244538 | RHEL 8 must prevent a user from overriding the session idle-delay setting for the graphical user interface. |
| SV-244539 | RHEL 8 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface. |
| SV-244540 | RHEL 8 must not allow blank or null passwords in the system-auth file. |
| SV-244541 | RHEL 8 must not allow blank or null passwords in the password-auth file. |
| SV-244542 | RHEL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events. |
| SV-244543 | RHEL 8 must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization. |
| SV-244544 | A firewall must be active on RHEL 8. |
| SV-244545 | The RHEL 8 fapolicy module must be enabled. |
| SV-244546 | The RHEL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs. |
| SV-244547 | RHEL 8 must have the USBGuard installed. |
| SV-244548 | RHEL 8 must enable the USBGuard. |
| SV-244549 | All RHEL 8 networked systems must have SSH installed. |
| SV-244550 | RHEL 8 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted. |
| SV-244551 | RHEL 8 must not forward IPv4 source-routed packets. |
| SV-244552 | RHEL 8 must not forward IPv4 source-routed packets by default. |
| SV-244553 | RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages. |
| SV-244554 | RHEL 8 must enable hardening for the Berkeley Packet Filter Just-in-time compiler. |
| SV-245540 | The RHEL 8 operating system must implement the Endpoint Security for Linux Threat Prevention tool. |


## **UBI8 Container Applicable Checks**

The following RHEL8 STIG rules are reviewed to applicable RHEL UBI8 container.

| Control ID | Rationale |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SV-230221 | RHEL 8 must be a vendor-supported release. |
| SV-230222 | RHEL 8 vendor packaged system security patches and updates must be installed and up to date. |
| SV-230223 | RHEL 8 must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. |
| SV-230225 | RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a ssh logon. |
| SV-230228 | All RHEL 8 remote access methods must be monitored. |
| SV-230229 | RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor. |
| SV-230230 | RHEL 8, for certificate-based authentication, must enforce authorized access to the corresponding private key. |
| SV-230231 | RHEL 8 must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm. |
| SV-230232 | RHEL 8 must employ FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords. |
| SV-230233 | The RHEL 8 password-auth file must be configured to use a sufficient number of hashing rounds. |
| SV-230237 | The RHEL 8 pam_unix.so module must be configured in the password-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication. |
| SV-230238 | RHEL 8 must prevent system daemons from using Kerberos for authentication. |
| SV-230239 | The krb5-workstation package must not be installed on RHEL 8. |
| SV-230242 | All RHEL 8 public directories must be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources. |
| SV-230243 | A sticky bit must be set on all RHEL 8 public directories to prevent unauthorized and unintended information transferred via shared system resources. |
| SV-230244 | RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements. |
| SV-230245 | The RHEL 8 /var/log/messages file must have mode 0640 or less permissive. |
| SV-230246 | The RHEL 8 /var/log/messages file must be owned by root. |
| SV-230247 | The RHEL 8 /var/log/messages file must be group-owned by root. |
| SV-230248 | The RHEL 8 /var/log directory must have mode 0755 or less permissive. |
| SV-230249 | The RHEL 8 /var/log directory must be owned by root. |
| SV-230250 | The RHEL 8 /var/log directory must be group-owned by root. |
| SV-230251 | The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms. |
| SV-230252 | The RHEL 8 operating system must implement DoD-approved encryption to protect the confidentiality of SSH server connections. |
| SV-230253 | RHEL 8 must ensure the SSH server uses strong entropy. |
| SV-230254 | The RHEL 8 operating system must implement DoD-approved encryption in the OpenSSL package. |
| SV-230255 | The RHEL 8 operating system must implement DoD-approved TLS encryption in the OpenSSL package. |
| SV-230256 | The RHEL 8 operating system must implement DoD-approved TLS encryption in the GnuTLS package. |
| SV-230257 | RHEL 8 system commands must have mode 0755 or less permissive. |
| SV-230258 | RHEL 8 system commands must be owned by root. |
| SV-230259 | RHEL 8 system commands must be group-owned by root or a system account. |
| SV-230260 | RHEL 8 library files must have mode 0755 or less permissive. |
| SV-230261 | RHEL 8 library files must be owned by root. |
| SV-230262 | RHEL 8 library files must be group-owned by root or a system account. |
| SV-230264 | RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. |
| SV-230265 | RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. |
| SV-230271 | RHEL 8 must require users to provide a password for privilege escalation. |
| SV-230272 | RHEL 8 must require users to reauthenticate for privilege escalation. |
| SV-230281 | YUM must remove all software components after updated versions have been installed on RHEL 8. |
| SV-230283 | There must be no shosts.equiv files on the RHEL 8 operating system. |
| SV-230284 | There must be no .shosts files on the RHEL 8 operating system. |
| SV-230286 | The RHEL 8 SSH public host key files must have mode 0644 or less permissive. |
| SV-230287 | The RHEL 8 SSH private host key files must have mode 0600 or less permissive. |
| SV-230288 | The RHEL 8 SSH daemon must perform strict mode checking of home directory configuration files. |
| SV-230289 | The RHEL 8 SSH daemon must not allow compression or must only allow compression after successful authentication. |
| SV-230290 | The RHEL 8 SSH daemon must not allow authentication using known host‚Äôs authentication. |
| SV-230291 | The RHEL 8 SSH daemon must not allow Kerberos authentication, except to fulfill documented and validated mission requirements. |
| SV-230296 | RHEL 8 must not permit direct logons to the root account using remote access via SSH. |
| SV-230301 | RHEL 8 must prevent special devices on non-root local partitions. |
| SV-230303 | RHEL 8 must prevent special devices on file systems that are used with removable media. |
| SV-230304 | RHEL 8 must prevent code from being executed on file systems that are used with removable media. |
| SV-230305 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media. |
| SV-230306 | RHEL 8 must prevent code from being executed on file systems that are imported via Network File System (NFS). |
| SV-230307 | RHEL 8 must prevent special devices on file systems that are imported via Network File System (NFS). |
| SV-230308 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS). |
| SV-230309 | Local RHEL 8 initialization files must not execute world-writable programs. |
| SV-230316 | For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured. |
| SV-230317 | Executable search paths within the initialization files of all local interactive RHEL 8 users must only contain paths that resolve to the system default or the users home directory. |
| SV-230318 | All RHEL 8 world-writable directories must be owned by root, sys, bin, or an application user. |
| SV-230319 | All RHEL 8 world-writable directories must be group-owned by root, sys, bin, or an application group. |
| SV-230320 | All RHEL 8 local interactive users must have a home directory assigned in the /etc/passwd file. |
| SV-230321 | All RHEL 8 local interactive user home directories must have mode 0750 or less permissive. |
| SV-230322 | All RHEL 8 local interactive user home directories must be group-owned by the home directory owner‚Äôs primary group. |
| SV-230323 | All RHEL 8 local interactive user home directories defined in the /etc/passwd file must exist. |
| SV-230324 | All RHEL 8 local interactive user accounts must be assigned a home directory upon creation. |
| SV-230325 | All RHEL 8 local initialization files must have mode 0740 or less permissive. |
| SV-230326 | All RHEL 8 local files and directories must have a valid owner. |
| SV-230327 | All RHEL 8 local files and directories must have a valid group owner. |
| SV-230330 | RHEL 8 must not allow users to override SSH environment variables. |
| SV-230331 | RHEL 8 temporary user accounts must be provisioned with an expiration time of 72 hours or less. |
| SV-230332 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur. |
| SV-230333 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur. |
| SV-230334 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230335 | RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230336 | RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230337 | RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230338 | RHEL 8 must ensure account lockouts persist. |
| SV-230339 | RHEL 8 must ensure account lockouts persist. |
| SV-230340 | RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur. |
| SV-230341 | RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur. |
| SV-230342 | RHEL 8 must log user name information when unsuccessful logon attempts occur. |
| SV-230343 | RHEL 8 must log user name information when unsuccessful logon attempts occur. |
| SV-230344 | RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230345 | RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period. |
| SV-230346 | RHEL 8 must limit the number of concurrent sessions to ten for all accounts and/or account types. |
| SV-230355 | RHEL 8 must map the authenticated identity to the user or group account for PKI-based authentication. |
| SV-230356 | RHEL 8 must ensure a password complexity module is enabled. |
| SV-230357 | RHEL 8 must enforce password complexity by requiring that at least one uppercase character be used. |
| SV-230358 | RHEL 8 must enforce password complexity by requiring that at least one lower-case character be used. |
| SV-230359 | RHEL 8 must enforce password complexity by requiring that at least one numeric character be used. |
| SV-230360 | RHEL 8 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed. |
| SV-230361 | RHEL 8 must require the maximum number of repeating characters be limited to three when passwords are changed. |
| SV-230362 | RHEL 8 must require the change of at least four character classes when passwords are changed. |
| SV-230363 | RHEL 8 must require the change of at least 8 characters when passwords are changed. |
| SV-230364 | RHEL 8 passwords must have a 24 hours/1 day minimum password lifetime restriction in /etc/shadow. |
| SV-230365 | RHEL 8 passwords for new users or password changes must have a 24 hours/1 day minimum password lifetime restriction in /etc/logins.def. |
| SV-230366 | RHEL 8 user account passwords must have a 60-day maximum password lifetime restriction. |
| SV-230367 | RHEL 8 user account passwords must be configured so that existing passwords are restricted to a 60-day maximum lifetime. |
| SV-230368 | RHEL 8 passwords must be prohibited from reuse for a minimum of five generations. |
| SV-230369 | RHEL 8 passwords must have a minimum of 15 characters. |
| SV-230370 | RHEL 8 passwords for new users must have a minimum of 15 characters. |
| SV-230371 | RHEL 8 duplicate User IDs (UIDs) must not exist for interactive users. |
| SV-230373 | RHEL 8 account identifiers (individuals, groups, roles, and devices) must be disabled after 35 days of inactivity. |
| SV-230374 | RHEL 8 emergency accounts must be automatically removed or disabled after the crisis is resolved or within 72 hours. |
| SV-230375 | All RHEL 8 passwords must contain at least one special character. |
| SV-230376 | RHEL 8 must prohibit the use of cached authentications after one day. |
| SV-230377 | RHEL 8 must prevent the use of dictionary words for passwords. |
| SV-230378 | RHEL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt. |
| SV-230379 | RHEL 8 must not have unnecessary accounts. |
| SV-230380 | RHEL 8 must not allow accounts configured with blank or null passwords. |
| SV-230381 | RHEL 8 must display the date and time of the last successful account logon upon logon. |
| SV-230382 | RHEL 8 must display the date and time of the last successful account logon upon an SSH logon. |
| SV-230383 | RHEL 8 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files. |
| SV-230384 | RHEL 8 must set the umask value to 077 for all local interactive user accounts. |
| SV-230385 | RHEL 8 must define default permissions for logon and non-logon shells. |
| SV-230485 | RHEL 8 must disable the chrony daemon from acting as a server. |
| SV-230486 | RHEL 8 must disable network management of the chrony daemon. |
| SV-230487 | RHEL 8 must not have the telnet-server package installed. |
| SV-230488 | RHEL 8 must not have any automated bug reporting tools installed. |
| SV-230489 | RHEL 8 must not have the sendmail package installed. |
| SV-230492 | RHEL 8 must not have the rsh-server package installed. |
| SV-230508 | RHEL 8 must mount /dev/shm with the nodev option. |
| SV-230509 | RHEL 8 must mount /dev/shm with the nosuid option. |
| SV-230510 | RHEL 8 must mount /dev/shm with the noexec option. |
| SV-230527 | RHEL 8 must force a frequent session key renegotiation for SSH connections to the server. |
| SV-230533 | The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for RHEL 8 operational support. |
| SV-230534 | The root account must be the only account having unrestricted access to the RHEL 8 system. |
| SV-230550 | RHEL 8 must be configured to prevent unrestricted mail relaying. |
| SV-230553 | The graphical display manager must not be installed on RHEL 8 unless approved. |
| SV-230556 | The RHEL 8 SSH daemon must prevent remote hosts from connecting to the proxy display. |
| SV-230557 | If the Trivial File Transfer Protocol (TFTP) server is required, the RHEL 8 TFTP daemon must be configured to operate in secure mode. |
| SV-230558 | A File Transfer Protocol (FTP) server package must not be installed unless mission essential on RHEL 8. |
| SV-230559 | The gssproxy package must not be installed unless mission essential on RHEL 8. |
| SV-230560 | The iprutils package must not be installed unless mission essential on RHEL 8. |
| SV-230561 | The tuned package must not be installed unless mission essential on RHEL 8. |
| SV-237640 | The krb5-server package must not be installed on RHEL 8. |
| SV-237641 | RHEL 8 must restrict privilege elevation to authorized personnel. |
| SV-237642 | RHEL 8 must use the invoking user's password for privilege escalation when using "sudo". |
| SV-237643 | RHEL 8 must require re-authentication when using the "sudo" command. |
| SV-244520 | The RHEL 8 system-auth file must be configured to use a sufficient number of hashing rounds. |
| SV-244524 | The RHEL 8 pam_unix.so module must be configured in the system-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication. |
| SV-244525 | The RHEL 8 SSH daemon must be configured with a timeout interval. |
| SV-244526 | The RHEL 8 SSH daemon must be configured to use system-wide crypto policies. |
| SV-244528 | The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements. |
| SV-244531 | All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive. |
| SV-244532 | RHEL 8 must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member. |
| SV-244533 | RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file. |
| SV-244534 | RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file. |
| SV-244540 | RHEL 8 must not allow blank or null passwords in the system-auth file. |
| SV-244541 | RHEL 8 must not allow blank or null passwords in the password-auth file. |

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Feedback and Support

For questions or comments regarding the validation profile, please contact the DISA SD DevSecOps Helpdesk: disa.meade.sd.mbx.devsecops-mailbox@mail.mil

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
