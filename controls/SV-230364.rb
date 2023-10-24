control 'SV-230364' do
  title 'RHEL 8 passwords must have a 24 hours/1 day minimum password lifetime
restriction in /etc/shadow.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated
password changes to defeat the password reuse or history enforcement
requirement. If users are allowed to immediately and continually change their
password, the password could be repeatedly changed in a short period of time to
defeat the organization's policy regarding password reuse."
  desc 'check', %q(Check whether the minimum time period between password changes for each
user account is one day or greater.

    $ sudo awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow

    If any results are returned that are not associated with a system account,
this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 24 hours/1 day minimum
password lifetime:

    $ sudo chage -m 1 [user]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag gid: 'V-230364'
  tag rid: 'SV-230364r627750_rule'
  tag stig_id: 'RHEL-08-020180'
  tag fix_id: 'F-33008r567839_fix'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']

  shadow.users.each do |user|
    # filtering on non-system accounts (uid >= 1000)
    next unless user(user).uid >= 1000
    describe shadow.users(user) do
      its('min_days.first.to_i') { should cmp >= 1 }
    end
  end
end
