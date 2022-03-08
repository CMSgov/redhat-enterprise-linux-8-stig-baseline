control 'SV-244543' do
  title "RHEL 8 must notify the System Administrator (SA) and Information
System Security Officer (ISSO) (at a minimum) when allocated audit record
storage volume 75 percent utilization."
  desc  "If security personnel are not notified immediately when storage volume
reaches 75 percent utilization, they are unable to plan for audit record
storage capacity expansion."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 notifies the SA and ISSO (at a minimum) when allocated audit
record storage volume reaches 75 percent of the repository maximum audit record
storage capacity with the following command:

    $ sudo grep -w space_left_action /etc/audit/auditd.conf

    space_left_action = email

    If the value of the \"space_left_action\" is not set to \"email\", or if
the line is commented out, ask the System Administrator to indicate how the
system is providing real-time alerts to the SA and ISSO.

    If there is no evidence that real-time alerts are configured on the system,
this is a finding.
  "
  desc  'fix', "
    Configure the operating system to initiate an action to notify the SA and
ISSO (at a minimum) when allocated audit record storage volume reaches 75
percent of the repository maximum audit record storage capacity by
adding/modifying the following line in the /etc/audit/auditd.conf file.

    space_left_action = email

    Note: Option names and values in the auditd.conf file are case insensitive.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-244543'
  tag rid: 'SV-244543r743878_rule'
  tag stig_id: 'RHEL-08-030731'
  tag fix_id: 'F-47775r743877_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe auditd_conf do
      its('space_left_action.downcase') { should cmp 'email' }
    end
  end
end

