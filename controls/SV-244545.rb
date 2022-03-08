control 'SV-244545' do
  title 'The RHEL 8 fapolicy module must be enabled.'
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
    Verify the RHEL 8 \"fapolicyd\" is enabled and running with the following
command:

    $ sudo systemctl status fapolicyd.service

    fapolicyd.service - File Access Policy Daemon
    Loaded: loaded (/usr/lib/systemd/system/fapolicyd.service; enabled; vendor
preset: disabled)
    Active: active (running)

    If fapolicyd is not enabled and running, this is a finding.
  "
  desc  'fix', "
    Enable \"fapolicyd\" using the following command:

    $ sudo systemctl enable --now fapolicyd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155',
'SRG-OS-000480-GPOS-00232']
  tag gid: 'V-244545'
  tag rid: 'SV-244545r743884_rule'
  tag stig_id: 'RHEL-08-040136'
  tag fix_id: 'F-47777r743883_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe service('fapolicyd') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end

