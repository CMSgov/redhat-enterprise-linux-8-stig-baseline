control 'SV-230397' do
  title "RHEL 8 audit logs must be owned by root to prevent unauthorized read
access."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the audit logs are owned by \"root\". First, determine where the
audit logs are stored with the following command:

    $ sudo grep -iw log_file /etc/audit/auditd.conf

    log_file = /var/log/audit/audit.log

    Using the location of the audit log file, determine if the audit log is
owned by \"root\" using the following command:

    $ sudo ls -al /var/log/audit/audit.log

    rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log

    If the audit log is not owned by \"root\", this is a finding.
  "
  desc 'fix', "
    Configure the audit log to be protected from unauthorized read access, by
setting the correct owner as \"root\" with the following command:

    $ sudo chown root [audit_log_file]

    Replace \"[audit_log_file]\" to the correct audit log path, by default this
location is \"/var/log/audit/audit.log\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: %w(SRG-OS-000057-GPOS-00027 SRG-OS-000058-GPOS-00028
                    SRG-OS-000059-GPOS-00029 SRG-OS-000206-GPOS-00084)
  tag gid: 'V-230397'
  tag rid: 'SV-230397r627750_rule'
  tag stig_id: 'RHEL-08-030080'
  tag fix_id: 'F-33041r567938_fix'
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
      its('owner') { should eq 'root' }
    end
  end
end
