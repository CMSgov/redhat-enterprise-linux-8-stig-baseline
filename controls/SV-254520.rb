control 'SV-254520' do
  title 'RHEL 8 must prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 
 
Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users.'
  desc 'check', 'Verify the operating system prevents nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures. 
 
Obtain a list of authorized users (other than system administrator and guest accounts) for the system. 
 
Check the list against the system by using the following command: 
 
     $ sudo semanage login -l | more
 
     Login Name    SELinux User    MLS/MCS Range    Service

     __default__   user_u                 s0-s0:c0.c1023        *
     root                   unconfined_u  s0-s0:c0.c1023        *
     system_u        system_u           s0-s0:c0.c1023        *
     joe                     staff_u                s0-s0:c0.c1023        *
 
All administrators must be mapped to the "sysadm_u", "staff_u", or an appropriately tailored confined role as defined by the organization. 
 
All authorized nonadministrative users must be mapped to the "user_u" role. 
 
If they are not mapped in this way, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures. 
 
Use the following command to map a new user to the "sysadm_u" role: 
 
     $ sudo semanage login -a -s sysadm_u <username> 
 
Use the following command to map an existing user to the "sysadm_u" role: 
 
     $ sudo semanage login -m -s sysadm_u <username> 
 
Use the following command to map a new user to the "staff_u" role: 
 
     $ sudo semanage login -a -s staff_u <username> 
 
Use the following command to map an existing user to the "staff_u" role: 
 
     $ sudo semanage login -m -s staff_u <username> 
 
Use the following command to map a new user to the "user_u" role: 
 
     $ sudo  semanage login -a -s user_u <username> 
 
Use the following command to map an existing user to the "user_u" role: 
 
     $ sudo semanage login -m -s user_u <username>

Note: SELinux confined users mapped to sysadm_u are not allowed to log in to the system over SSH, by default. If this is a required function, it can be configured by setting the ssh_sysadm_login SELinux boolean to "on" with the following command:

     $ sudo setsebool -P ssh_sysadm_login on

This must be documented with the information system security officer (ISSO) as an operational requirement.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-58004r928594_chk'
  tag severity: 'medium'
  tag gid: 'V-254520'
  tag rid: 'SV-254520r928805_rule'
  tag stig_id: 'RHEL-08-040400'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57953r928805_fix'
  tag 'documentable'
  tag cci: ['CCI-002265']
  tag nist: ['AC-16 b']
end
