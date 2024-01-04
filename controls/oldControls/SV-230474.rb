control 'SV-230474' do
  title 'RHEL 8 audit tools must be group-owned by root.'
  desc 'Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    RHEL 8 systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools,
and the corresponding rights the user enjoys, to make access decisions
regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.'
  desc 'check', 'Verify the audit tools are group-owned by "root" to prevent any
unauthorized access, deletion, or modification.

    Check the owner of each audit tool by running the following commands:

    $ sudo stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch
/sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

    root /sbin/auditctl
    root /sbin/aureport
    root /sbin/ausearch
    root /sbin/autrace
    root /sbin/auditd
    root /sbin/rsyslogd
    root /sbin/augenrules

    If any of the audit tools are not group-owned by "root", this is a
finding.'
  desc 'fix', 'Configure the audit tools to be group-owned by "root", by running the
following command:

    $ sudo chgrp root [audit_tool]

    Replace "[audit_tool]" with each audit tool not group-owned by "root".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag gid: 'V-230474'
  tag rid: 'SV-230474r627750_rule'
  tag stig_id: 'RHEL-08-030640'
  tag fix_id: 'F-33118r568169_fix'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9', 'AU-9 a']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe file('/sbin/auditctl') do
      it { should be_grouped_into 'root' }
    end
    describe file('/sbin/aureport') do
      it { should be_grouped_into 'root' }
    end
    describe file('/sbin/ausearch') do
      it { should be_grouped_into 'root' }
    end
    describe file('/sbin/autrace') do
      it { should be_grouped_into 'root' }
    end
    describe file('/sbin/auditd') do
      it { should be_grouped_into 'root' }
    end
    describe file('/sbin/rsyslogd') do
      it { should be_grouped_into 'root' }
    end
    describe file('/sbin/augenrules') do
      it { should be_grouped_into 'root' }
    end
  end
end
