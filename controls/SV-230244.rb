control 'SV-230244' do
  title 'RHEL 8 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.'
  desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

RHEL 8 uses /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" is used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.'
  desc 'check', 'Verify the SSH server automatically terminates a user session after the SSH client has become unresponsive.

Check that the "ClientAliveCountMax" is set to "1" by performing the following command:

     $ sudo grep -ir clientalivecountmax /etc/ssh/sshd_config*

     ClientAliveCountMax 1

If "ClientAliveCountMax" do not exist, is not set to a value of "1" in "/etc/ssh/sshd_config", or is commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Note: This setting must be applied in conjunction with RHEL-08-010201 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has become unresponsive.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

     ClientAliveCountMax 1

For the changes to take effect, the SSH daemon must be restarted:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000126-GPOS-00066', 'SRG-OS-000279-GPOS-00109']
  tag gid: 'V-230244'
  tag rid: 'SV-230244r917867_rule'
  tag stig_id: 'RHEL-08-010200'
  tag fix_id: 'F-32888r917866_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('ClientAliveCountMax') { should cmp input('sshd_client_alive_count_max') }
    end
  end
end