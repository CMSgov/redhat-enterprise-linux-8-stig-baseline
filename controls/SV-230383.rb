control 'SV-230383' do
  title 'RHEL 8 must define default permissions for all authenticated users in
such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new
accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify the operating system defines default permissions for all
authenticated users in such a way that the user can only read and modify their
own files.

    Check for the value of the "UMASK" parameter in "/etc/login.defs" file
with the following command:

    Note: If the value of the "UMASK" parameter is set to "000" in
"/etc/login.defs" file, the Severity is raised to a CAT I.

    # grep -i umask /etc/login.defs

    UMASK 077

    If the value for the "UMASK" parameter is not "077", or the "UMASK"
parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to define default permissions for all
authenticated users in such a way that the user can only read and modify their
own files.

    Add or edit the line for the "UMASK" parameter in "/etc/login.defs"
file to "077":

    UMASK 077'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag gid: 'V-230383'
  tag rid: 'SV-230383r627750_rule'
  tag stig_id: 'RHEL-08-020351'
  tag fix_id: 'F-33027r567896_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host', 'container'

  permissions_for_shells = input('permissions_for_shells')

  impact 0.7 if login_defs.read_params['UMASK'].eql?('000')
  describe login_defs do
    its('UMASK') { should cmp permissions_for_shells['default_umask'] }
  end
end
