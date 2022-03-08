control 'SV-230400' do
  title "RHEL 8 audit log directory must be group-owned by root to prevent
unauthorized read access."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 activity.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the audit log directory is group-owned by \"root\" to prevent
unauthorized read access.

    Determine where the audit logs are stored with the following command:

    $ sudo grep -iw log_file /etc/audit/auditd.conf

    log_file = /var/log/audit/audit.log

    Determine the group owner of the audit log directory by using the output of
the above command (ex: \"/var/log/audit/\"). Run the following command with the
correct audit log directory path:

    $ sudo ls -ld /var/log/audit

    drw------- 2 root root 23 Jun 11 11:56 /var/log/audit

    If the audit log directory is not group-owned by \"root\", this is a
finding.
  "
  desc 'fix', "
    Configure the audit log to be protected from unauthorized read access by
setting the correct group-owner as \"root\" with the following command:

    $ sudo chgrp root [audit_log_directory]

    Replace \"[audit_log_directory]\" with the correct audit log directory
path, by default this location is usually \"/var/log/audit\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: %w(SRG-OS-000057-GPOS-00027 SRG-OS-000058-GPOS-00028
                    SRG-OS-000059-GPOS-00029)
  tag gid: 'V-230400'
  tag rid: 'SV-230400r627750_rule'
  tag stig_id: 'RHEL-08-030110'
  tag fix_id: 'F-33044r567947_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9']


  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    log_dir = auditd_conf('/etc/audit/auditd.conf').log_file.split('/')[0..-2].join('/')
    describe directory(log_dir) do
      its('group') { should eq 'root' }
    end
  end
end
