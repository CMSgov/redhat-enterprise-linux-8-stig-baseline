control 'SV-230404' do
  title 'RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect /etc/shadow.'
  desc 'Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).'
  desc 'check', 'Verify RHEL 8 generates audit records for all account creations,
modifications, disabling, and termination events that affect "/etc/shadow".

    Check the auditing rules in "/etc/audit/audit.rules" with the following
command:

    $ sudo grep /etc/shadow /etc/audit/audit.rules

    -w /etc/shadow -p wa -k identity

    If the command does not return a line, or the line is commented out, this
is a finding.'
  desc 'fix', 'Configure RHEL 8 to generate audit records for all account creations,
modifications, disabling, and termination events that affect "/etc/shadow".

    Add or update the following file system rule to
"/etc/audit/rules.d/audit.rules":

    -w /etc/shadow -p wa -k identity

    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000476-GPOS-00221']
  tag gid: 'V-230404'
  tag rid: 'SV-230404r627750_rule'
  tag stig_id: 'RHEL-08-030130'
  tag fix_id: 'F-33048r567959_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_command = '/etc/shadow'
  audit_rule_keys = input('audit_rule_keys')

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.key).to be_in audit_rule_keys
      expect(audit_rule.permissions.flatten).to include('w', 'a')
    end
  end
end
