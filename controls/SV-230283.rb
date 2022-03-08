control 'SV-230283' do
  title 'There must be no shosts.equiv files on the RHEL 8 operating system.'
  desc  "The \"shosts.equiv\" files are used to configure host-based
authentication for the system via SSH. Host-based authentication is not
sufficient for preventing unauthorized access to the system, as it does not
require interactive identification and authentication of a connection request,
or for the use of two-factor authentication."
  desc  'rationale', ''
  desc  'check', "
    Verify there are no \"shosts.equiv\" files on RHEL 8 with the following
command:

    $ sudo find / -name shosts.equiv

    If a \"shosts.equiv\" file is found, this is a finding.
  "
  desc 'fix', "
    Remove any found \"shosts.equiv\" files from the system.

    $ sudo rm /etc/ssh/shosts.equiv
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230283'
  tag rid: 'SV-230283r627750_rule'
  tag stig_id: 'RHEL-08-010460'
  tag fix_id: 'F-32927r567596_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('find / -xdev -xautofs -name shosts.equiv') do
    its('stdout') { should be_empty }
  end
end
