control 'SV-230263' do
  title "The RHEL 8 file integrity tool must notify the system administrator
when changes to the baseline configuration or anomalies in the operation of any
security functions are discovered within an organizationally defined frequency."
  desc  "Unauthorized changes to the baseline configuration could make the
system vulnerable to various attacks or allow unauthorized access to the
operating system. Changes to operating system configurations can have
unintended side effects, some of which may be relevant to security.

    Detecting such changes and providing an automated response can help avoid
unintended, negative consequences that could ultimately affect the security
state of the operating system. The operating system's Information Management
Officer (IMO)/Information System Security Officer (ISSO) and System
Administrators (SAs) must be notified via email and/or monitoring system trap
when there is an unauthorized modification of a configuration item.

    Notifications provided by information systems include messages to local
computer consoles, and/or hardware indications, such as lights.

    This capability must take into account operational requirements for
availability for selecting an appropriate response. The organization may choose
to shut down or restart the information system upon security function anomaly
detection.

    RHEL 8 comes with many optional software packages. A file integrity tool
called Advanced Intrusion Detection Environment (AIDE) is one of those optional
packages. This requirement assumes the use of AIDE; however, a different tool
may be used if the requirements are met. Note that AIDE does not have a
configuration that will send a notification, so a cron job is recommended that
uses the mail application on the system to email the results of the file
integrity check.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system routinely checks the baseline configuration for
unauthorized changes and notifies the system administrator when anomalies in
the operation of any security functions are discovered.

    Check to see if AIDE is installed on the system with the following command:

    $ sudo yum list installed aide

    If AIDE is not installed, ask the System Administrator how file integrity
checks are performed on the system.

    Check that RHEL 8 routinely executes a file integrity scan for changes to
the system baseline. The command used in the example will use a daily
occurrence.

    Check the cron directories for scripts controlling the execution and
notification of results of the file integrity application. For example, if AIDE
is installed on the system, use the following commands:

    $ sudo ls -al /etc/cron.* | grep aide

    -rwxr-xr-x 1 root root 29 Nov 22 2015 aide

    $ sudo grep aide /etc/crontab /var/spool/cron/root

    /etc/crontab: 30 04 * * * root usr/sbin/aide
    /var/spool/cron/root: 30 04 * * * root usr/sbin/aide

    $ sudo more /etc/cron.daily/aide

    #!/bin/bash
    /usr/sbin/aide --check | /bin/mail -s \"$HOSTNAME - Daily aide integrity
check run\" root@sysname.mil

    If the file integrity application does not exist, or a script file
controlling the execution of the file integrity application does not exist, or
the file integrity application does not notify designated personnel of changes,
this is a finding.
  "
  desc 'fix', "
    Configure the file integrity tool to run automatically on the system at
least weekly and to notify designated personnel if baseline configurations are
changed in an unauthorized manner. The AIDE tool can be configured to email
designated personnel with the use of the cron system.

    The following example output is generic. It will set cron to run AIDE daily
and to send email at the completion of the analysis.

    $ sudo more /etc/cron.daily/aide

    #!/bin/bash

    /usr/sbin/aide --check | /bin/mail -s \"$HOSTNAME - Daily aide integrity
check run\" root@sysname.mil
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag satisfies: %w(SRG-OS-000363-GPOS-00150 SRG-OS-000446-GPOS-00200
                    SRG-OS-000447-GPOS-00201)
  tag gid: 'V-230263'
  tag rid: 'SV-230263r627750_rule'
  tag stig_id: 'RHEL-08-010360'
  tag fix_id: 'F-32907r567536_fix'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']

  file_integrity_tool = input('file_integrity_tool')

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe package(file_integrity_tool) do
      it { should be_installed }
    end
    describe.one do
      describe file("/etc/cron.daily/#{file_integrity_tool}") do
        its('content') { should match %r{/bin/mail} }
      end
      describe file("/etc/cron.weekly/#{file_integrity_tool}") do
        its('content') { should match %r{/bin/mail} }
      end
      describe crontab('root').where { command =~ /#{file_integrity_tool}/ } do
        its('commands.flatten') { should include(match %r{/bin/mail}) }
      end
      if file("/etc/cron.d/#{file_integrity_tool}").exist?
        describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
          its('commands') { should include(match %r{/bin/mail}) }
        end
      end
    end
  end
end
