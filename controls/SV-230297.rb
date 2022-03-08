control 'SV-230297' do
  title 'The auditd service must be running in RHEL 8.'
  desc  "Configuring RHEL 8 to implement organization-wide security
implementation guides and security checklists ensures compliance with federal
standards and establishes a common security baseline across the DoD that
reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed in
hardware, software, or firmware components of the system that affect the
security posture and/or functionality of the system. Security-related
parameters are those parameters impacting the security state of the system,
including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example: registry
settings; account, file, directory permission settings; and settings for
functions, ports, protocols, services, and remote connections.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the audit service is enabled and active with the following commands:

    $ sudo systemctl is-enabled auditd

    enabled

    $ sudo systemctl is-active auditd

    active

    If the service is not \"enabled\" and \"active\" this is a finding.
  "
  desc 'fix', "
    Start the auditd service, and enable the auditd service with the following
commands:

    $ sudo systemctl start auditd.service

    $ sudo systemctl enable auditd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230297'
  tag rid: 'SV-230297r627750_rule'
  tag stig_id: 'RHEL-08-010560'
  tag fix_id: 'F-32941r567638_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe service('auditd') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end
