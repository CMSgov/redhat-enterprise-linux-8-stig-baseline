control 'SV-230398' do
  title "RHEL 8 audit logs must be group-owned by root to prevent unauthorized
read access."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 activity.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the audit logs are group-owned by \"root\". First determine where
the audit logs are stored with the following command:

    $ sudo grep -iw log_file /etc/audit/auditd.conf

    log_file = /var/log/audit/audit.log

    Using the location of the audit log file, determine if the audit log is
group-owned by \"root\" using the following command:

    $ sudo ls -al /var/log/audit/audit.log

    rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log

    If the audit log is not group-owned by \"root\", this is a finding.
  "
  desc 'fix', "
    Configure the audit log to be owned by root by configuring the log group in
the /etc/audit/auditd.conf file:

    log_group = root
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: %w(SRG-OS-000057-GPOS-00027 SRG-OS-000058-GPOS-00028
                    SRG-OS-000059-GPOS-00029)
  tag gid: 'V-230398'
  tag rid: 'SV-230398r627750_rule'
  tag stig_id: 'RHEL-08-030090'
  tag fix_id: 'F-33042r567941_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9']

  log_file = auditd_conf('/etc/audit/auditd.conf').log_file

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe file(log_file) do
      its('group') { should eq 'root' }
    end
  end
end
