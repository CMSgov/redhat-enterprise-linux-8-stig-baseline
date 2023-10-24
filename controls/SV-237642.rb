control 'SV-237642' do
  title %q(RHEL 8 must use the invoking user's password for privilege escalation
when using "sudo".)
  desc %q(The sudoers security policy requires that users authenticate
themselves before they can use sudo. When sudoers requires authentication, it
validates the invoking user's credentials. If the rootpw, targetpw, or runaspw
flags are defined and not disabled, by default the operating system will prompt
the invoking user for the "root" user password.
    For more information on each of the listed configurations, reference the
sudoers(5) manual page.)
  desc 'check', %q(Verify that the sudoers security policy is configured to use the invoking user's password for privilege escalation.

     $ sudo grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'

     /etc/sudoers:Defaults !targetpw
     /etc/sudoers:Defaults !rootpw
     /etc/sudoers:Defaults !runaspw

If conflicting results are returned, this is a finding.
If "Defaults !targetpw" is not defined, this is a finding.
If "Defaults !rootpw" is not defined, this is a finding.
If "Defaults !runaspw" is not defined, this is a finding.)
  desc 'fix', 'Define the following in the Defaults section of the /etc/sudoers file or a configuration file in the /etc/sudoers.d/ directory:
     Defaults !targetpw
     Defaults !rootpw
     Defaults !runaspw

Remove any configurations that conflict with the above from the following locations: 
     /etc/sudoers
     /etc/sudoers.d/'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-237642'
  tag rid: 'SV-237642r880727_rule'
  tag stig_id: 'RHEL-08-010383'
  tag fix_id: 'F-40824r880726_fix'
  tag cci: ['CCI-002227']
  tag nist: ['AC-6 (5)']

  if virtualization.system.eql?('docker') && !command('sudo').exist?
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe bash("egrep -i '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/* | grep -v '#' |  awk -F ':' '{ print $2 }'") do
      its('stdout') { should match /^Defaults !targetpw/ }
      its('stdout') { should match /^Defaults !rootpw/ }
      its('stdout') { should match /^Defaults !runaspw/ }
    end
  end
end
