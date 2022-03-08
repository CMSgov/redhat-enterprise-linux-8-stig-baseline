control 'SV-230466' do
  title "Successful/unsuccessful modifications to the faillock log file in RHEL
8 must generate an audit record."
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.

    From \"Pam_Faillock man\" pages: Note the default directory that
pam_faillock uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the \"dir\" option.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 generates an audit record when successful/unsuccessful
modifications to the \"faillock\" file occur. First, determine where the
faillock tallies are stored with the following commands:

    For RHEL versions 8.0 and 8.1:

    $ sudo grep -i pam_faillock.so /etc/pam.d/system-auth

    auth     required          pam_faillock.so preauth dir=/var/log/faillock
silent deny=3 fail_interval=900 even_deny_root

    For RHEL versions 8.2 and newer:

    $ sudo grep dir /etc/security/faillock.conf

    dir=/var/log/faillock

    Using the location of the faillock log file, check that the following calls
are being audited by performing the following command to check the file system
rules in \"/etc/audit/audit.rules\":

    $ sudo grep -w faillock /etc/audit/audit.rules

    -w /var/log/faillock -p wa -k logins

    If the command does not return a line, or the line is commented out, this
is a finding.
  "
  desc 'fix', "
    Configure the audit system to generate an audit event for any
successful/unsuccessful modifications to the \"faillock\" file by adding or
updating the following rules in the \"/etc/audit/rules.d/audit.rules\" file:

    -w /var/log/faillock -p wa -k logins

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: %w(SRG-OS-000062-GPOS-00031 SRG-OS-000037-GPOS-00015
                    SRG-OS-000042-GPOS-00020 SRG-OS-000062-GPOS-00031
                    SRG-OS-000392-GPOS-00172 SRG-OS-000462-GPOS-00206
                    SRG-OS-000471-GPOS-00215 SRG-OS-000473-GPOS-00218)
  tag gid: 'V-230466'
  tag rid: 'SV-230466r627750_rule'
  tag stig_id: 'RHEL-08-030590'
  tag fix_id: 'F-33110r568145_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  if os.release < '8.2'
    m = /dir=(?<dir>\S*)/
    s = command('grep -i pam_faillock.so /etc/pam.d/system-auth').stdout
    dir_match = m.match(s)
    audit_file = (dir_match[:dir] if dir_match)
  else
    audit_file = parse_config_file('/etc/security/faillock.conf').params('dir')
  end

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if audit_file
      describe auditd.file(audit_file) do
        its('permissions.flatten') { should include 'w' }
        its('permissions.flatten') { should include 'a' }
        its('key') { should cmp 'logins' }
      end
    else
      describe 'No faillock logfile found' do
        subject { audit_file }
        it { should_not be nil }
      end
    end
  end
end
