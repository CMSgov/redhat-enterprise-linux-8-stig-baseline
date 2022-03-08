control 'SV-244544' do
  title 'A firewall must be active on RHEL 8.'
  desc  "\"Firewalld\" provides an easy and effective way to block/limit remote
access to the system via ports, services, and protocols.

    Remote access services, such as those providing remote access to network
devices and information systems, which lack automated control capabilities,
increase risk and make remote user access management difficult at best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.
    RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement
action if the audit reveals unauthorized activity. Automated control of remote
access sessions allows organizations to ensure ongoing compliance with remote
access policies by enforcing connection rules of remote access applications on
a variety of information system components (e.g., servers, workstations,
notebook computers, smartphones, and tablets).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that \"firewalld\" is active with the following commands:

    $ sudo systemctl is-active firewalld

    active

    If the \"firewalld\" package is not \"active\", ask the System
Administrator if another firewall is installed. If no firewall is installed and
active this is a finding.
  "
  desc  'fix', "
    Configure \"firewalld\" to protect the operating system with the following
command:

    $ sudo systemctl enable firewalld
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag gid: 'V-244544'
  tag rid: 'SV-244544r743881_rule'
  tag stig_id: 'RHEL-08-040101'
  tag fix_id: 'F-47776r743880_fix'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe systemd_service('firewalld.service') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end

