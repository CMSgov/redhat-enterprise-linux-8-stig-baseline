control 'SV-230391' do
  title "The RHEL 8 System Administrator (SA) and Information System Security
Officer (ISSO) (at a minimum) must be alerted when the audit storage volume is
full."
  desc  "It is critical that when RHEL 8 is at risk of failing to process audit
logs as required, it takes action to mitigate the failure. Audit processing
failures include software/hardware errors; failures in the audit capturing
mechanisms; and audit storage capacity being reached or exceeded. Responses to
audit failure depend upon the nature of the failure mode.

    When availability is an overriding concern, other approved actions in
response to an audit failure are as follows:

    1) If the failure was caused by the lack of audit record storage capacity,
RHEL 8 must continue generating audit records if possible (automatically
restarting the audit service if necessary) and overwriting the oldest audit
records in a first-in-first-out manner.

    2) If audit records are sent to a centralized collection server and
communication with this server is lost or the server fails, RHEL 8 must queue
audit records locally until communication is restored or until the audit
records are retrieved manually. Upon restoration of the connection to the
centralized collection server, action should be taken to synchronize the local
audit data with the collection server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the SA and ISSO (at a minimum) are notified when the audit
storage volume is full.

    Check which action RHEL 8 takes when the audit storage volume is full with
the following command:

    $ sudo grep max_log_file_action /etc/audit/auditd.conf

    max_log_file_action=syslog

    If the value of the \"max_log_file_action\" option is set to \"ignore\",
\"rotate\", or \"suspend\", or the line is commented out, ask the system
administrator to indicate how the system takes appropriate action when an audit
storage volume is full.  If there is no evidence of appropriate action, this is
a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to notify the System Administrator (SA) and Information
System Security Officer (ISSO) when the audit storage volume is full by
configuring the \"max_log_file_action\" parameter in the
\"/etc/audit/auditd.conf\" file with the a value of \"syslog\" or \"keep_logs\":

    max_log_file_action=syslog
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag gid: 'V-230391'
  tag rid: 'SV-230391r743998_rule'
  tag stig_id: 'RHEL-08-030050'
  tag fix_id: 'F-33035r743997_fix'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe auditd_conf do
      its('max_log_file_action') { should cmp 'syslog' }
    end
  end
end
