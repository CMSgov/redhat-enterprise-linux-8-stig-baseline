# frozen_string_literal: true

control 'SV-230355' do
  title "RHEL 8 must map the authenticated identity to the user or group
account for PKI-based authentication."
  desc "Without mapping the certificate used to authenticate to the user
account, the ability to determine the identity of the individual user or group
will not be available for forensic analysis.

    There are various methods of mapping certificates to user/group accounts
for RHEL 8. For the purposes of this requirement, the check and fix will
account for Active Directory mapping. Some of the other possible methods
include joining the system to a domain and utilizing a Red Hat idM server, or a
<<<<<<< HEAD
local system mapping, where the system is not part of a domain."
  desc 'check', 'Verify the certificate of the user or group is mapped to the corresponding
user or group in the "sssd.conf" file with the following command:
=======
local system mapping, where the system is not part of a domain.'
  desc 'check', 'Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:
>>>>>>> 87a05e3c31795238f35c7bb155a9770db9a9c15c

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

$ sudo cat /etc/sssd/sssd.conf

[sssd]
config_file_version = 2
services = pam, sudo, ssh
domains = testing.test

[pam]
pam_cert_auth = True

[domain/testing.test]
id_provider = ldap

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the certmap section does not exist, ask the System Administrator to indicate how certificates are mapped to accounts. If there is no evidence of certificate mapping, this is a finding.'
  desc 'fix', 'Configure the operating system to map the authenticated identity to the user or group account by adding or modifying the certmap section of the "/etc/sssd/sssd.conf file based on the following example:

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'V-230355'
  tag rid: 'SV-230355r858743_rule'
  tag stig_id: 'RHEL-08-020090'
  tag fix_id: 'F-32999r818835_fix'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (c)', 'IA-5 (2) (a) (2)']

  if virtualization.system.eql?('docker') && !file('/etc/sssd/sssd.conf').exist?
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe file('/etc/sssd/sssd.conf') do
      it { should exist }
      its('content') { should match(/^\s*\[certmap.*\]\s*$/) }
    end
  end
end
