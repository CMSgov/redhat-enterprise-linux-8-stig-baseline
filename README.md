# RedHat Enterprise Linux 8.x Security Technical Implementation Guide InSpec Profile

The Redhat Enterprise Linux 8.X Security Technical Implementation Guide (RHEL8.x STIG) InSpec Profile can help programs automate their compliance checks of RedHat Enterprise Linux 8.x System to Department of Defense (DoD) requirements.

- Profile Version: `1.12.0`
- RedHat Enterprise Linux 8 Security Technical Implementation Guide v1r12

This profile was developed to reduce the time it takes to perform a security checks based upon the STIG Guidance from the Defense Information Systems Agency (DISA) in partnership between the DISA Services Directorate (SD) and the DISA Risk Management Executive (RME) office.

The results of a profile run will provide information needed to support an Authority to Operate (ATO) decision for the applicable technology.

The RHEL8 STIG Profile uses the [InSpec](https://github.com/inspec/inspec) open-source compliance validation language to support automation of the required compliance, security and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions and Continuous Authority to Operate (cATO) processes.

Table of Contents
=================

- [RedHat Enterprise Linux 8.x Security Technical Implementation Guide InSpec Profile](#redhat-enterprise-linux-8x-security-technical-implementation-guide-inspec-profile)
- [Table of Contents](#table-of-contents)
  - [RedHat 8.x Enterprise Linux Security Technical Implementation Guide (RHEL8 STIG)](#redhat-8x-enterprise-linux-security-technical-implementation-guide-rhel8-stig)
    - [Source Guidance](#source-guidance)
    - [Current Profile Statistics](#current-profile-statistics)
- [Getting Started and Intended Usage](#getting-started-and-intended-usage)
  - [Intended Usage - `main` vs `releases`](#intended-usage-main-vs-releases)
  - [Environment Aware Testing](#environment-aware-testing)
  - [Tailoring to Your Environment](#tailoring-to-your-environment)
    - [Profile Inputs (see `inspec.yml` file)](#profile-inputs-see-inspecyml-file)
      - [**_Do not change the inputs in the `inspec.yml` file_**](#do-not-change-the-inputs-in-the-inspecyml-file)
      - [Update Profile Inputs from the CLI or Local File](#update-profile-inputs-from-the-cli-or-local-file)
      - [Expected versus max/min input values](#expected-versus-maxmin-input-values)
      - [The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment.](#the-following-inputs-may-be-configured-in-an-inputs-yml-file-for-the-profile-to-run-correctly-for-your-specific-environment)
- [Running the Profile](#running-the-profile)
  - [Running the Profile in an Internet-Connected Environment](#running-the-profile-in-an-internet-connected-environment)
  - [Running the Profile in an Airgapped (disconnected) Environment](#running-the-profile-in-an-airgapped-disconnected-environment)
  - [Different Run Options](#different-run-options)
  - [Attestations](#attestations)
- [Using Heimdall for Viewing Test Results and Exporting for Checklist and eMASS](#using-heimdall-for-viewing-test-results-and-exporting-for-checklist-and-emass)
  - [Organization of the Repository](#organization-of-the-repository)
    - [`main` and `development` branch](#main-and-development-branch)
    - [`#v{x}r{y}.{z}` branches](#vxryz-branches)
    - [Releases](#releases)
    - [Tags](#tags)
      - [Major and Minor Version Tags](#major-and-minor-version-tags)
    - [Patch Releases](#patch-releases)
  - [Updates, Releases \& Submitting PRs to the Profile](#updates-releases-submitting-prs-to-the-profile)
    - [Submitting Bugs](#submitting-bugs)
- [Authors](#authors)
    - [NOTICE](#notice)
    - [NOTICE](#notice-1)
    - [NOTICE](#notice-2)
    - [NOTICE](#notice-3)

## RedHat 8.x Enterprise Linux Security Technical Implementation Guide (RHEL8 STIG)

The DISA RME and DISA SD Office, along with their vendor partners, create and maintain a set of Security Technical Implementation Guides for applications, computer systems and networks connected to the Department of Defense (DoD). These guidelines are the primary security standards used by the DoD agencies. In addition to defining security guidelines, the STIGs also stipulate how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

The RHEL8 STIG (see public.cyber.mil/stigs/) offers a comprehensive compliance guide for the configuration and operation your RedHat Enterprise Linux 8.x system.

The requirements associated with the RHEL8 STIG are derived from the [Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide) and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST) [Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53) Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The RHEL8.x STIG profile checks were developed to provide technical implementation validation to the defined DoD requirements, the guidance can provide insight for any organizations wishing to enhance their security posture and can be tailored easily for use in your organization.

### Source Guidance

- RedHat Enterprise Linux 8 Security Technical Implementation Guide v1r12

### Current Profile Statistics

The profile is tested on every commit and every release against both `vanilla` and `hardened` ubi8 and ec2 images using [CI/CD pipelines](https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline/actions). The `vanilla` images are unmodified base images sourced from Red Hat itself. The `hardened` images have had their settings configured for security according to STIG guidance, and are sourced from [Platform One's](https://p1.dso.mil/) [Iron Bank](https://login.dso.mil). Testing both vanilla and hardened configurations of both containerized and virtual machine implementations of RHEL8 is necessary to ensure the profile works in multiple environments.

# Getting Started and Intended Usage

1. It is intended and recommended that InSpec and the profile be run from a **"runner"** host, either from source or a local archieve - [Running the Profile](#running-the-profile) - (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target [ remotely over **ssh**].

2. **For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.**

3. The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

4. Always use the latest version of the `released profile` (see below) on your system.

## Intended Usage - `main` vs `releases`

1. The latest 'released' version of the profile is intended for use in A&A testing, formal results to Authorizing Officials, Information Assurance Managers and other security stakeholders. Please use the tagged, released versions of the profile in these types of workflows.

2. The `main` branch is a development branch that will become the next release of the profile. The `main` branch is intended for use in _developement and testing_ merge requests for the next release of the profile, and _is not intended_ be used for formal and ongoing testing on systems.

## Environment Aware Testing

The RHEL8.x STIG profile is `container aware` and is able to determine when the profile is being executed inside or outside a container (ex. the Universal Base Image container images from Red Hat) and will only run the tests that are approporate for the enviroment it is testing in. The tests are tagged depending on their applicability to containers as opposed to full hosts.

Controls will be tagged as some combination of `host`, `container`, and `container-conditional`. Controls that apply to full host deployments (i.e. bare-metal servers or virtual machines) are marked `host`. Controls that apply to containers are marked `container`. Controls that only apply to containers depending on the packages and services included in the container are marked `container-conditional`.

All the profile's tests apply to the `host` but many of the controls are `Not Applicable` when running inside a container. (such as, for example, controls that test the system's kernel configuration). When running inside a container, the tests that only applicable to the host will be marked as `Not Applicable` automatically.

InSpec also has a command-line flag to only run tests in a profile that match a given tag, if desired. See [Running Controls By Tag](#running-controls-by-tag).

### Testing Containers

Note that, because so many STIG requirements are not applicable to containers, it is often necessary to *also* asses the container host's STIG compliance. A container can only ever be as secure as the platform it runs on.

For example, many STIG controls concern the Linux kernel's settings. A container's configuration cannot affect the hosts's kernel, so these controls are marked as not applicable to containers. However, we still need to know if our container is running a secure kernel. As such, we need to asses *the container host's* kernel settings in addition to the container.

In practice, this usually means running an InSpec STIG compliance profile against *both* the container and the host, which are ultimately part of the same interconnected system.

## Tailoring to Your Environment

### Profile Inputs (see `inspec.yml` file)

This profile uses InSpec's [inputs](https://docs.chef.io/inspec/profiles/inputs/) feature to make the tests more flexible. By default, the profile sets the inputs to baseline STIG-aligned values, but you are able to provide inputs at runtime either via the cli or via YAML files to help the profile work best in your deployment if necessary.

#### **_Do not change the inputs in the `inspec.yml` file_**

Inputs are defined, and given a default value, in the `inspec.yml` file at the root of the profile directory. The inputs configured in the `inspec.yml` file are **profile definitions and defaults**, and it is not intended for the user to modify them in that file directly. To tailor the profile inputs to match your deployment or organizationally defined values, **_you should instead override the inputs_** as described below.

It is recommended to review `inspec.yml`'s `inputs` section to get the list of all inputs that can be configured and see if any of them need to be overridden to more accurately scan your system.

#### Update Profile Inputs from the CLI or Local File

InSpec provides two ways to adjust the profiles inputs at run-time that do not require modifiying `inspec.yml` itself:

1. Via the cli with the `--input` flag
2. Pass them in a YAML file with the `--input-file` flag.

More information about InSpec inputs can be found in the [InSpec Inputs Documentation](https://docs.chef.io/inspec/inputs/).

#### Sample Input File

The following YAML file is formatted as an InSpec input file. 

Note that any of the inputs that are not explicitly overridden by this file will be set to their default values (as given in `inspec.yml`) when the profile is run.

```yaml
disable_slow_controls: true
kernel_config_files:
  - "/etc/sysctl.d/*.conf"
  - "/run/sysctl.d/*.conf"
  - "/lib/sysctl.d/*.conf"
  - "/etc/sysctl.conf"
user_accounts:
  - "jdoe"
ipv4_enabled: false
bluetooth_installed: false
known_system_accounts:
  - adm
  - bin
  - chrony
  - daemon
  - dbus
  - halt
  - lp
  - mail
  - nobody
  - ntp
  - operator
  - polkitd
  - postfix
  - root
  - shutdown
  - sshd
  - sssd
  - sync
  - systemd-bus-proxy
  - systemd-network
private_key_files:
  - "/home/jdoe/.ssh/id_rsa.pem"
system_inactivity_timeout:
  - 1500
gui_required: true
```

# Running the Profile

InSpec profiles can be executed against a local system, or a remote system using a transport. Airgapped environments can use an archived profile for local execution.

## Running the Profile in an Internet-Connected Environment

InSpec can execute a test profile directly from a source code repository -- for example, GitHub. It is recommended to run the profile using the source GitHub repository as the profile source where possible. This ensures that you are always running the profile version with the latest patch updates.

It is also recommended to "pin" the version of the profile you are running from GitHub by specifying a tagged minor release (ex. "v1.12" -- see the "Organization of the Repository" section). This way, you will always know exactly which version and release of the STIG you are using to validate your system.

Against a remote target using ssh with escalated privileges (i.e., InSpec installed on a separate runner host)
```bash
inspec exec https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline/archive/v1.12.tar.gz -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --sudo --sudo-password=<SUDO_PASSWORD_IF_REQUIRED> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_desired_output_file.json>
```
Against a remote target using a pem key with escalated privileges (i.e., InSpec installed on a separate runner host)
```bash
inspec exec https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline/archive/v1.12.tar.gz -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <path_to_your_pem_key> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_desired_output_file.json> 
```
Against a local running Red Hat Docker container (i.e., InSpec installed on the container host):
```bash
inspec exec https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline/archive/v1.12.tar.gz -t docker://<name_of_the_container> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_desired_output_file.json> 
```
Against a local Red Hat host with escalated privileges (i.e., InSpec installed directly on the target)
```bash
sudo inspec exec https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline/archive/v1.12.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_desired_output_file.json> 
```
## Running the Profile in an Airgapped (disconnected) Environment

If your runner will not have direct access to the profile's hosted location, you can use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(A local Git installation is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site. Airgapped systems will need to use alternate sources for downloading Git.)

When the **"runner"** host uses this profile overlay for the first time, follow these steps:

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline.git
inspec archive redhat-enterprise-linux-8-stig-baseline
<sneakerNet your archive>
inspec exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter json:<your_results_file.json>
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

1. Delete and recreate your archive as shown above, or:
2. Update your archive with the following steps

```
cd redhat-enterprise-linux-8-stig-baseline
git pull
cd ..
inspec archive redhat-enterprise-linux-8-stig-baseline
```

## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Attestations

Not all controls in the STIG can be checked automatically by InSpec. Some controls are 'manual' -- for example, require the tester to confirm the existence of a written policy, or a control may state that a package is allowable only if the system ISSO confirms in an interview that it is necessary for that particular system. In these cases, InSpec will mark the test as `skipped` (as opposed to `passed` or `failed`) in the output. Note that this is a separate concept to a test that is `Not Applicable` -- unlike an N/A test, a `skipped` test still needs the tester to go back and determine manually if it passes or fails.

A tester can use the [SAF CLI's Attestation function](https://saf-cli.mitre.org/#attest) to record a manual assesment of a control as a file that can then be inserted back into an automated workflow as data. Attestations are valid for a specified timespan (1 day, 1 month, 1 year etc.), and can therefore be automatically "appended" to automated test results generated by pipelines or conducting a scan to produce a single report on the state of a system. The Heimdall application (see next section) can display automated test results that have been enhanced by attestation files, and note which controls were manual attestations and how long those attestations are valid.

# Using Heimdall for Viewing Test Results and Exporting for Checklist and eMASS

The JSON results output file can be loaded into **[Heimdall](https://heimdall-lite.mitre.org/)** for a user-interactive, graphical view of the profile scan results. Heimdall-Lite is a browser only viewer that allows you to easily view your results directly and locally rendered in your browser.

It can also **_export your results into a DISA Checklist (CKL) file_** using the `Heimdall Export` function, for easily upload into eMASS.

Depending on your enviroment, you can also use the [SAF CLI](https://saf-cli.mitre.org) pipeline utility tool to run a local Docker instance of heimdall-lite via the `saf view:heimdall` command.

The JSON results file may also be loaded into a **[full Heimdall Server](https://github.com/mitre/heimdall2)**, allowing for additional functionality such as storing, aggregating and comparing multiple profile runs.

You can deploy your own instances of Heimdall Lite or Heimdall Server easily via Docker, onto Kurbernetes, or using the installation packages.

## Organization of the Repository

### `main` and `development` branch

The `main` branch contains the most recent code for the profile. It may include bugs and is typically aligned with the latest patch release for the profile. ***The main branch is not meant for real scanning or production systems***. 

This branch is primarily used for development and testing workflows for the various testing targets.

For production validation, use the latest tagged patch release, such as `v1.12.1`.

### `#v{x}r{y}.{z}` branches

The `v{x}r{y}.{z}` branches represent the changes between releases of the benchmark. They align with the STIG releases for the Benchmark found at the DISA STIG Document Library. `{x}` aligns to the Version of the STIG Benchmark, `{y}` aligns to the Release of the Benchmark, and `{z}` aligns to the 'Release' of the tagged release of the profile as we fix or improve the tests.

### Releases

Releases use Semantic Versioning (SemVer), aligning with the STIG Benchmark versioning system of Major Version and Release. The SemVer patch number is used for updates, bug fixes, and code changes between STIG Benchmark Releases for the given product. STIG Benchmarks use a Version and Release tagging pattern `v{x}r{y}.{z}` - like V1R12 - and we mirror that pattern in our SemVer releases - and a patch release for any updates or fixes.

### Tags

This profile does not use a specific 'current' or 'latest' tag. The current/latest tag for the profile and repository will always be the latest major tag of the benchmark. For example, if `version 1, release 12` is the latest Benchmark release from the STIG author, then the tag `v1.12` will point to the `v1.12.3` release of the code.

#### Major and Minor Version Tags

Major tags point to the latest version of the STIG that they test, and minor tags point to the latest version and release of a STIG. The patch tag indicates the patch number of the InSpec profile itself and is the only tag in the semver that does not directly correspond to the STIG's schema.

 For example, `v1.3` and `v1.3.0` represent the first release of the Red Hat Enterprise Linux 8 STIG V1R3 Benchmark. The `v1.12.{z}` tag(s) represents the V1R12 Benchmark releases as the profile authors find bugs, fixes, or general improvements to the testing profile. This tag will point to its `v{x}r{y}.{z}` counterpart.

### Patch Releases

The latest patch release always points to the release for the profile.

For example, after releasing `v1.12.0`, we point `v1.12` to that patch release: `v1.12.0`. When an issue is found, we will fix, tag, and release `v1.12.1`. We will then 'move' the `v1.12` tag so that it points to tag `v1.12.1`. This way, your pipelines can choose if they want to pin on a specific release of the InSpec profile or always run 'current' for a particular release of the STIG.

## Updates, Releases & Submitting PRs to the Profile

This profile is updated and managed using our standard MITRE SAF InSpec Profile Development and Update process. You can learn more about this and how to help us keep the profile up to date from release to release of the Red Hat Enterprise Linux 8 STIG Benchmark at [SAF Profile Maintenance](https://mitre.github.io/saf-training-current/courses/profile-dev "Profile Maintenance Process") Process.

For example, `v1.12.2` would be the Red Hat Enterprise Linux 8 STIG Version 1 Release 12 with two 'patch' releases from the first `v1.12.0` release.

### Submitting Bugs

If you find an issue or a test that isn't operating as you expect, please submit an issue on the repository.

If possible, after you remove any identifying information about who and where your target is deployed, please provide a way we can 'reproduce' the error, any specific configuration examples on the target that cause the issue, or examples of settings, strings or other configuration settings we might need to reproduce the issue.

# Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

MITRE Security Automation Framework Team https://saf.mitre.org

### NOTICE

© 2018-2024 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx