control 'SV-230481' do
  title "RHEL 8 must encrypt the transfer of audit records off-loaded onto a
different system or media from the system being audited."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides \"rsyslogd\".  \"rsyslogd\" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with \"gnutls\" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system encrypts audit records off-loaded onto a
different system or media from the system being audited with the following
commands:

    $ sudo grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf
/etc/rsyslog.d/*.conf

    /etc/rsyslog.conf:$DefaultNetstreamDriver gtls

    If the value of the \"$DefaultNetstreamDriver\" option is not set to
\"gtls\" or the line is commented out, this is a finding.

    $ sudo grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf
/etc/rsyslog.d/*.conf

    /etc/rsyslog.conf:$ActionSendStreamDriverMode 1

    If the value of the \"$ActionSendStreamDriverMode\" option is not set to
\"1\" or the line is commented out, this is a finding.

    If either of the definitions above are set, ask the System Administrator to
indicate how the audit logs are off-loaded to a different system or media.

    If there is no evidence that the transfer of the audit logs being
off-loaded to another system or media is encrypted, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to encrypt off-loaded audit records by
setting the following options in \"/etc/rsyslog.conf\" or
\"/etc/rsyslog.d/[customfile].conf\":

    $DefaultNetstreamDriver gtls
    $ActionSendStreamDriverMode 1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: %w(SRG-OS-000342-GPOS-00133 SRG-OS-000479-GPOS-00224)
  tag gid: 'V-230481'
  tag rid: 'SV-230481r627750_rule'
  tag stig_id: 'RHEL-08-030710'
  tag fix_id: 'F-33125r568190_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe 'rsyslog configuration' do
      subject { command("grep -i '^\$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/* | awk -F ':' '{ print $2 }'").stdout }
      it { should match /\$DefaultNetstreamDriver\s+gtls/ }
    end
  
    describe 'rsyslog configuration' do
      subject { command("grep -i '^\$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/* | awk -F ':' '{ print $2 }'").stdout }
      it { should match /\$ActionSendStreamDriverMode\s+1/ }
    end
  end
end
