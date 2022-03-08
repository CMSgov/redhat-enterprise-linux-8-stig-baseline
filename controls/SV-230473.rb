control 'SV-230473' do
  title 'RHEL 8 audit tools must be owned by root.'
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    RHEL 8 systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools,
and the corresponding rights the user enjoys, to make access decisions
regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the audit tools are owned by \"root\" to prevent any unauthorized
access, deletion, or modification.

    Check the owner of each audit tool by running the following command:

    $ sudo stat -c \"%U %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch
/sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

    root /sbin/auditctl
    root /sbin/aureport
    root /sbin/ausearch
    root /sbin/autrace
    root /sbin/auditd
    root /sbin/rsyslogd
    root /sbin/augenrules

    If any of the audit tools are not owned by \"root\", this is a finding.
  "
  desc  'fix', "
    Configure the audit tools to be owned by \"root\", by running the following
command:

    $ sudo chown root [audit_tool]

    Replace \"[audit_tool]\" with each audit tool not owned by \"root\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098',
'SRG-OS-000258-GPOS-00099']
  tag gid: 'V-230473'
  tag rid: 'SV-230473r744008_rule'
  tag stig_id: 'RHEL-08-030630'
  tag fix_id: 'F-33117r568166_fix'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe file('/sbin/auditctl') do
      it { should be_owned_by 'root' }
    end
    describe file('/sbin/aureport') do
      it { should be_owned_by 'root' }
    end
    describe file('/sbin/ausearch') do
      it { should be_owned_by 'root' }
    end
    describe file('/sbin/autrace') do
      it { should be_owned_by 'root' }
    end
    describe file('/sbin/auditd') do
      it { should be_owned_by 'root' }
    end
    describe file('/sbin/rsyslogd') do
      it { should be_owned_by 'root' }
    end
    describe file('/sbin/augenrules') do
      it { should be_owned_by 'root' }
    end
  end
end
