control 'SV-230416' do
  title "The RHEL 8 audit system must be configured to audit any usage of the
fsetxattr system call."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). \"Fsetxattr\" is a system
call used to set an extended attribute value. This is used to set extended
attributes on a file.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
\"-1\". The auid representation is an unsigned 32-bit integer, which equals
\"4294967295\". The audit system interprets \"-1\", \"4294967295\", and
\"unset\" in the same way.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify if RHEL 8 is configured to audit the execution of the \"fsetxattr\"
system call, by running the following command:

    $ sudo grep -w fsetxattr /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -k
perm_mod
    -a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -k
perm_mod

    -a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod
    -a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod

    If the command does not return all lines, or the lines are commented out,
this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to audit the execution of the \"fsetxattr\" system call,
by adding or updating the following lines to \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -k
perm_mod
    -a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -k
perm_mod

    -a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod
    -a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: %w(SRG-OS-000062-GPOS-00031 SRG-OS-000037-GPOS-00015
                    SRG-OS-000042-GPOS-00020 SRG-OS-000062-GPOS-00031
                    SRG-OS-000392-GPOS-00172 SRG-OS-000458-GPOS-00203
                    SRG-OS-000462-GPOS-00206 SRG-OS-000463-GPOS-00207
                    SRG-OS-000468-GPOS-00212 SRG-OS-000471-GPOS-00215
                    SRG-OS-000474-GPOS-00219)
  tag gid: 'V-230416'
  tag rid: 'SV-230416r627750_rule'
  tag stig_id: 'RHEL-08-030230'
  tag fix_id: 'F-33060r567995_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  audit_syscall = 'fsetxattr'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe auditd.syscall(audit_syscall) do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('arch.uniq') { should include 'b32' }
      its('arch.uniq') { should include 'b64' }
      its('fields.flatten') { should include 'auid>=1000' }
      its('fields.flatten') { should include 'auid!=-1' }
      its('key.uniq') { should cmp 'perm_mod' }
    end
  end
end
