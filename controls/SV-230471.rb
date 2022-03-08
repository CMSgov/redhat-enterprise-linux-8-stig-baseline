control 'SV-230471' do
  title "RHEL 8 must allow only the Information System Security Manager (ISSM)
(or individuals or roles appointed by the ISSM) to select which auditable
events are to be audited."
  desc  "Without the capability to restrict the roles and individuals that can
select which events are audited, unauthorized personnel may be able to prevent
the auditing of critical events. Misconfigured audits may degrade the system's
performance by overwhelming the audit log. Misconfigured audits may also make
it more difficult to establish, correlate, and investigate the events relating
to an incident or identify those responsible for one."
  desc  'rationale', ''
  desc  'check', "
    Verify that the files in directory \"/etc/audit/rules.d/\" and
\"/etc/audit/auditd.conf\" file have a mode of \"0640\" or less permissive by
using the following commands:

    $ sudo ls -al /etc/audit/rules.d/*.rules

    -rw-r----- 1 root root 1280 Feb 16 17:09 audit.rules

    $ sudo ls -l /etc/audit/auditd.conf

    -rw-r----- 1 root root 621 Sep 22 17:19 auditd.conf

    If the files in the \"/etc/audit/rules.d/\" directory or the
\"/etc/audit/auditd.conf\" file have a mode more permissive than \"0640\", this
is a finding.
  "
  desc 'fix', "
    Configure the files in directory \"/etc/audit/rules.d/\" and the
\"/etc/audit/auditd.conf\" file to have a mode of \"0640\" with the following
commands:

    $ sudo chmod 0640 /etc/audit/rules.d/audit.rules
    $ sudo chmod 0640 /etc/audit/rules.d/[customrulesfile].rules
    $ sudo chmod 0640 /etc/audit/auditd.conf
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag gid: 'V-230471'
  tag rid: 'SV-230471r627750_rule'
  tag stig_id: 'RHEL-08-030610'
  tag fix_id: 'F-33115r568160_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  rules_files = bash('ls -d /etc/audit/rules.d/*.rules').stdout.strip.split.append('/etc/audit/auditd.conf')

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    rules_files.each do |rf|
      describe file(rf) do
        it { should_not be_more_permissive_than('0640') }
      end
    end
  end
end
