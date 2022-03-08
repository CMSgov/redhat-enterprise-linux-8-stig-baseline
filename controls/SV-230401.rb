control 'SV-230401' do
  title "RHEL 8 audit log directory must have a mode of 0700 or less permissive
to prevent unauthorized read access."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 system activity.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the audit log directories have a mode of \"0700\" or less permissive
by first determining where the audit logs are stored with the following command:

    $ sudo grep -iw log_file /etc/audit/auditd.conf

    log_file = /var/log/audit/audit.log

    Using the location of the audit log, determine the directory where the
audit logs are stored (ex: \"/var/log/audit\"). Run the following command to
determine the permissions for the audit log folder:

    $ sudo stat -c \"%a %n\" /var/log/audit

    700 /var/log/audit

    If the audit log directory has a mode more permissive than \"0700\", this
is a finding.
  "
  desc 'fix', "
    Configure the audit log directory to be protected from unauthorized read
access by setting the correct permissive mode with the following command:

    $ sudo chmod 0700 [audit_log_directory]

    Replace \"[audit_log_directory]\" to the correct audit log directory path,
by default this location is \"/var/log/audit\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: %w(SRG-OS-000057-GPOS-00027 SRG-OS-000058-GPOS-00028
                    SRG-OS-000059-GPOS-00029)
  tag gid: 'V-230401'
  tag rid: 'SV-230401r627750_rule'
  tag stig_id: 'RHEL-08-030120'
  tag fix_id: 'F-33045r567950_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9']

  log_dir = command("dirname #{auditd_conf('/etc/audit/auditd.conf').log_file}").stdout.strip

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe directory(log_dir) do
      it { should_not be_more_permissive_than('0700') }
    end
  end
end
