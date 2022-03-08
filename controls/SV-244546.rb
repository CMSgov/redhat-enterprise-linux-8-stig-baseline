control 'SV-244546' do
  title "The RHEL 8 fapolicy module must be configured to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs."
  desc  "The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    Utilizing a whitelist provides a configuration management method for
allowing the execution of only authorized software. Using only authorized
software decreases risk by limiting the number of potential vulnerabilities.
Verification of whitelisted software occurs prior to execution or at system
startup.

    User home directories/folders may contain information of a sensitive
nature. Non-privileged users should coordinate any sharing of information with
an SA through shared resources.

    RHEL 8 ships with many optional packages. One such package is a file access
policy daemon called \"fapolicyd\". \"fapolicyd\" is a userspace daemon that
determines access rights to files based on attributes of the process and file.
It can be used to either blacklist or whitelist processes or file access.

    Proceed with caution with enforcing the use of this daemon. Improper
configuration may render the system non-functional. The \"fapolicyd\" API is
not namespace aware and can cause issues when launching or running containers.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the RHEL 8 \"fapolicyd\" employs a deny-all, permit-by-exception
policy.

    Check that \"fapolicyd\" is in enforcement mode with the following command:

    $ sudo grep permissive /etc/fapolicyd/fapolicyd.conf

    permissive = 0

    Check that fapolicyd employs a deny-all policy on system mounts with the
following commands:

    $ sudo tail /etc/fapolicyd/fapolicyd.rules

    allow exe=/usr/bin/python3.7 : ftype=text/x-python
    deny_audit perm=any pattern=ld_so : all
    deny perm=any all : all

    $ sudo cat /etc/fapolicyd/fapolicyd.mounts

    /dev/shm
    /run
    /sys/fs/cgroup
    /
    /home
    /boot
    /run/user/42
    /run/user/1000

    If fapolicyd is not running in enforcement mode on all system mounts with a
deny-all, permit-by-exception policy, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to employ a deny-all, permit-by-exception application
whitelisting policy with \"fapolicyd\" using the following command:

    Note: Running this command requires a root shell

    # mount | egrep '^tmpfs| ext4| ext3| xfs' | awk '{ printf \"%s\
    \", $3 }' >> /etc/fapolicyd/fapolicyd.mounts

    With the \"fapolicyd\" installed and enabled, configure the daemon to
function in permissive mode until the whitelist is built correctly to avoid
system lockout. Do this by editing the \"/etc/fapolicyd/fapolicyd.conf\" file
with the following line:

    permissive = 1

    Build the whitelist in the \"/etc/fapolicyd/fapolicyd.rules\" file ensuring
the last rule is \"deny perm=any all : all\".

    Once it is determined the whitelist is built correctly, set the fapolicyd
to enforcing mode by editing the \"permissive\" line in the
/etc/fapolicyd/fapolicyd.conf file.

    permissive = 0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155',
'SRG-OS-000480-GPOS-00232']
  tag gid: 'V-244546'
  tag rid: 'SV-244546r743887_rule'
  tag stig_id: 'RHEL-08-040137'
  tag fix_id: 'F-47778r743886_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe parse_config_file('/etc/fapolicyd/fapolicyd.conf') do
      its('permissive') { should eq 0 }
    end
  
    describe file('/etc/fapolicyd/fapolicyd.rules') do
      it { should exist }
    end
  
    describe file('/etc/fapolicyd/fapolicyd.rules').content.strip.split("\n")[-1] do
      it { should cmp 'deny all all' }
    end if file('/etc/fapolicyd/fapolicyd.rules').exist?

    system_mounts = command("mount | egrep '^tmpfs| ext4| ext3| xfs' | awk '{ printf \"%s\\n\", $3 }'").stdout.split

    describe file('/etc/fapolicyd/fapolicyd.mounts') do
      it { should exist }
    end
  
    describe file('/etc/fapolicyd/fapolicyd.mounts') do
      its('content.split') { should match_array system_mounts }        
    end if file('/etc/fapolicyd/fapolicyd.mounts').exist?
  end
end

