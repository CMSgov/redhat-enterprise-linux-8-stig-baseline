control 'SV-237643' do
  title 'RHEL 8 must require re-authentication when using the "sudo" command.'
  desc  "Without re-authentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the organization requires the user to
re-authenticate when using the \"sudo\" command.

    If the value is set to an integer less than 0, the user's time stamp will
not expire and the user will not have to re-authenticate for privileged actions
until the user's session is terminated.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system requires re-authentication when using the
\"sudo\" command to elevate privileges.

    $ sudo grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*
    /etc/sudoers:Defaults timestamp_timout=0

    If \"timestamp_timeout\" is set to a negative number, is commented out, or
no results are returned, this is a finding.
  "
  desc 'fix', "
    Configure the \"sudo\" command to require re-authentication.
    Edit the /etc/sudoers file:
    $ sudo visudo

    Add or modify the following line:
    Defaults timestamp_timeout=[value]
    Note: The \"[value]\" must be a number that is greater than or equal to
\"0\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag gid: 'V-237643'
  tag rid: 'SV-237643r646899_rule'
  tag stig_id: 'RHEL-08-010384'
  tag fix_id: 'F-40825r646898_fix'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']



  if virtualization.system.eql?('docker') && !command("sudo").exist?
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    config = bash("grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/* |  awk -F ':' '{ print $2 }'")
    describe config do
      its('stdout') { should match /^Defaults timestamp_timeout/ }
    end
  
    describe parse_config(config.stdout) do
      its('Defaults timestamp_timeout') { should cmp >= 0 }
    end
  end
end
