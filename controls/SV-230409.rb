control 'SV-230409' do
  title 'RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect /etc/sudoers.'
  desc 'Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).'
  desc 'check', 'Verify RHEL 8 generates audit records for all account creations,
modifications, disabling, and termination events that affect "/etc/sudoers".

    Check the auditing rules in "/etc/audit/audit.rules" with the following
command:

    $ sudo grep /etc/sudoers /etc/audit/audit.rules

    -w /etc/sudoers -p wa -k identity

    If the command does not return a line, or the line is commented out, this
is a finding.'
  desc 'fix', 'Configure RHEL 8 to generate audit records for all account creations,
modifications, disabling, and termination events that affect "/etc/sudoers".

    Add or update the following file system rule to
"/etc/audit/rules.d/audit.rules":

    -w /etc/sudoers -p wa -k identity

    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015',
                  'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000304-GPOS-00121', 'CCI-002884', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000476-GPOS-00221']
  tag gid: 'V-230409'
  tag rid: 'SV-230409r627750_rule'
  tag stig_id: 'RHEL-08-030171'
  tag fix_id: 'F-33053r567974_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  audit_file = '/etc/sudoers'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe auditd.file(audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
      its('key') { should cmp 'identity' }
    end

    # Resource creates data structure including all usages of file
    perms = auditd.file(audit_file).permissions

    perms.each do |perm|
      describe perm do
        it { should include 'w' }
        it { should include 'a' }
      end
    end
  end
end
