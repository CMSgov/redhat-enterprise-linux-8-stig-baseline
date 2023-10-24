control 'SV-230430' do
  title 'Successful/unsuccessful uses of setfiles in RHEL 8 must generate an
audit record.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "setfiles" command is primarily used to initialize the security context
fields (extended attributes) on one or more filesystems (or parts of them).
Usually it is initially run as part of the SELinux installation process (a step
commonly known as labeling).

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use
of "setfiles" by performing the following command to check the file system
rules in "/etc/audit/audit.rules":

    $ sudo grep -w "setfiles" /etc/audit/audit.rules

    -a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F
auid!=unset -k privileged-unix-update

    If the command does not return a line, or the line is commented out, this
is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any
successful/unsuccessful uses of the "setfiles" by adding or updating the
following rule in the "/etc/audit/rules.d/audit.rules" file:

    -a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F
auid!=unset -k privileged-unix-update

    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-230430'
  tag rid: 'SV-230430r627750_rule'
  tag stig_id: 'RHEL-08-030314'
  tag fix_id: 'F-33074r568037_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  audit_file = '/usr/sbin/setfiles'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe auditd.file(audit_file) do
      its('permissions.flatten') { should include 'x' }
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('fields.flatten') { should include 'auid>=1000' }
      its('fields.flatten') { should include 'auid!=-1' }
      its('key.uniq') { should cmp 'privileged-unix-update' }
    end
  end
end
