<?php $cve_cache = array (
  'CVE-2023-22293' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-22293',
      'Description' => 'Improper access control in the Intel(R) Thunderbolt(TM) DCH drivers for Windows may allow an authenticated user to potentially enable escalation of privilege via local access.',
      'Date_Publication' => '2024-02-14',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '355.0',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2023-23444' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-23444',
      'Description' => 'Missing Authentication for Critical Function in SICK Flexi Classic and Flexi Soft Gateways with Partnumbers 1042193, 1042964, 1044078, 1044072, 1044073, 1044074, 1099830, 1099832, 1127717, 1069070, 1112296, 1051432, 1102420, 1127487, 1121596, 1121597 allows an unauthenticated remote attacker to influence the availability of the device by changing the IP settings of the device via broadcasted UDP packets.',
      'Date_Publication' => '2023-05-12',
      'Date_Modification' => '2025-01-24',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '120.0',
      'cwe_id' => '306.0',
      'cwe_name' => 'Missing Authentication for Critical Function',
    ),
  ),
  'CVE-2023-42648' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-42648',
      'Description' => 'In engineermode, there is a possible missing permission check. This could lead to local information disclosure with no additional execution privileges needed',
      'Date_Publication' => '2023-11-01',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '50.0',
      'cwe_id' => '862.0',
      'cwe_name' => 'Missing Authorization',
    ),
  ),
  'CVE-2023-29056' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-29056',
      'Description' => 'A valid LDAP user, under specific conditions, will default to read-only permissions when authenticating into XCC. To be vulnerable, XCC must be configured to use an LDAP server for Authentication/Authorization and have the login permission attribute not defined.',
      'Date_Publication' => '2023-04-28',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '29.0',
      'cwe_id' => '269.0',
      'cwe_name' => 'Improper Privilege Management',
    ),
  ),
  'CVE-2023-29057' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-29057',
      'Description' => 'A valid XCC user\'s local account permissions overrides their active directory permissions under specific configurations. This could lead to a privilege escalation. To be vulnerable, LDAP must be configured for authentication/authorization and logins configured as “Local First, then LDAP”.',
      'Date_Publication' => '2023-04-28',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.3',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '29.0',
      'cwe_id' => '276.0',
      'cwe_name' => 'Incorrect Default Permissions',
    ),
  ),
  'CVE-2024-0540' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0540',
      'Description' => 'A vulnerability was found in Tenda W9 1.0.0.7(4456). It has been classified as critical. Affected is the function formOfflineSet of the component httpd. The manipulation of the argument ssidIndex leads to stack-based buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-250710 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2024-01-15',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2022-47476' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-47476',
      'Description' => 'In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.',
      'Date_Publication' => '2023-03-10',
      'Date_Modification' => '2025-03-06',
      'CVSSv3_Score' => '5.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '81.0',
      'cwe_id' => '862.0',
      'cwe_name' => 'Missing Authorization',
    ),
  ),
  'CVE-2022-21198' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-21198',
      'Description' => 'Time-of-check time-of-use race condition in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.',
      'Date_Publication' => '2022-11-11',
      'Date_Modification' => '2025-02-04',
      'CVSSv3_Score' => '7.9',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '265.0',
      'cwe_id' => '367.0',
      'cwe_name' => 'Time-of-check Time-of-use (TOCTOU) Race Condition',
    ),
  ),
  'CVE-2022-26346' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-26346',
      'Description' => 'A denial of service vulnerability exists in the ucloud_del_node functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted network packet can lead to denial of service. An attacker can send packets to trigger this vulnerability.',
      'Date_Publication' => '2022-08-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.6',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '135.0',
      'cwe_id' => '284.0',
      'cwe_name' => 'Improper Access Control',
    ),
  ),
  'CVE-2021-34719' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-34719',
      'Description' => 'Multiple vulnerabilities in the CLI of Cisco IOS XR Software could allow an authenticated, local attacker with a low-privileged account to elevate privileges on an affected device. For more information about these vulnerabilities, see the Details section of this advisory.',
      'Date_Publication' => '2021-09-09',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '86.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2021-1217' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-1217',
      'Description' => 'Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an authenticated, remote attacker to execute arbitrary code or cause an affected device to restart unexpectedly. The vulnerabilities are due to improper validation of user-supplied input in the web-based management interface. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system or cause the device to reload, resulting in a denial of service (DoS) condition. To exploit these vulnerabilities, an attacker would need to have valid administrator credentials on the affected device. Cisco has not released software updates that address these vulnerabilities.',
      'Date_Publication' => '2021-01-13',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '61.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2021-34730' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-34730',
      'Description' => 'A vulnerability in the Universal Plug-and-Play (UPnP) service of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause an affected device to restart unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to improper validation of incoming UPnP traffic. An attacker could exploit this vulnerability by sending a crafted UPnP request to an affected device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system or cause the device to reload, resulting in a DoS condition. Cisco has not released software updates that address this vulnerability.',
      'Date_Publication' => '2021-08-18',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '64.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2020-10262' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2020-10262',
      'Description' => 'An issue was discovered on XIAOMI XIAOAI speaker Pro LX06 1.58.10. Attackers can activate the failsafe mode during the boot process, and use the mi_console command cascaded by the SN code shown on the product to get the root shell password, and then the attacker can (i) read Wi-Fi SSID or password, (ii) read the dialogue text files between users and XIAOMI XIAOAI speaker Pro LX06, (iii) use Text-To-Speech tools pretend XIAOMI speakers\' voice achieve social engineering attacks, (iv) eavesdrop on users and record what XIAOMI XIAOAI speaker Pro LX06 hears, (v) modify system files, (vi) use commands to send any IR code through IR emitter on XIAOMI XIAOAI Speaker Pro (LX06), (vii) stop voice assistant service, (viii) enable the XIAOMI XIAOAI Speaker Pro’s SSH or TELNET service as a backdoor, (IX) tamper with the router configuration of the router in the local area networks.',
      'Date_Publication' => '2020-04-08',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.8',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '29.0',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2025-1878' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-1878',
      'Description' => 'A vulnerability has been found in i-Drive i11 and i12 up to 20250227 and classified as problematic. This vulnerability affects unknown code of the component WiFi. The manipulation leads to use of default password. Access to the local network is required for this attack to succeed. The complexity of an attack is rather high. The exploitation appears to be difficult. It was not possible to identify the current maintainer of the product. It must be assumed that the product is end-of-life.',
      'Date_Publication' => '2025-03-03',
      'Date_Modification' => '2025-03-06',
      'CVSSv3_Score' => '3.1',
      'Severity' => 'LOW',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '1393.0',
      'cwe_name' => 'Use of Default Password',
    ),
  ),
  'CVE-2025-21424' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-21424',
      'Description' => 'Memory corruption while calling the NPU driver APIs concurrently.',
      'Date_Publication' => '2025-03-03',
      'Date_Modification' => '2025-03-07',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '75.0',
      'cwe_id' => '416.0',
      'cwe_name' => 'Use After Free',
    ),
  ),
  'CVE-2025-25664' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-25664',
      'Description' => 'Tenda AC8V4 V16.03.34.06 was discovered to contain a stack overflow via the shareSpeed parameter in the sub_49E098 function.',
      'Date_Publication' => '2025-02-20',
      'Date_Modification' => '2025-03-17',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '13.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2025-2618' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-2618',
      'Description' => 'A vulnerability, which was classified as critical, has been found in D-Link DAP-1620 1.03. Affected by this issue is the function set_ws_action of the file /dws/api/ of the component Path Handler. The manipulation leads to heap-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.',
      'Date_Publication' => '2025-03-22',
      'Date_Modification' => '2025-03-26',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2025-29135' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-29135',
      'Description' => 'A stack-based buffer overflow vulnerability in Tenda AC7 V15.03.06.44 allows a remote attacker to execute arbitrary code through a stack overflow attack using the security parameter of the formWifiBasicSet function.',
      'Date_Publication' => '2025-03-24',
      'Date_Modification' => '2025-04-01',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2025-21102' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-21102',
      'Description' => 'Dell VxRail, versions 7.0.000 through 7.0.532, contain(s) a Plaintext Storage of a Password vulnerability. A high privileged attacker with local access could potentially exploit this vulnerability, leading to Information exposure.',
      'Date_Publication' => '2025-01-08',
      'Date_Modification' => '2025-01-24',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '47.0',
      'cwe_id' => '522.0',
      'cwe_name' => 'Insufficiently Protected Credentials',
    ),
  ),
  'CVE-2020-25153' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2020-25153',
      'Description' => 'The built-in web service for MOXA NPort IAW5000A-I/O firmware version 2.1 or lower does not require users to have strong passwords.',
      'Date_Publication' => '2020-12-23',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '110.0',
      'cwe_id' => '521.0',
      'cwe_name' => 'Weak Password Requirements',
    ),
  ),
  'CVE-2021-26344' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-26344',
      'Description' => 'An out of bounds memory write when processing the AMD
PSP1 Configuration Block (APCB) could allow an attacker with access the ability
to modify the BIOS image, and the ability to sign the resulting image, to
potentially modify the APCB block resulting in arbitrary code execution.',
      'Date_Publication' => '2024-08-13',
      'Date_Modification' => '2024-12-12',
      'CVSSv3_Score' => '7.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '1291.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2022-0847' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-0847',
      'Description' => 'A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.',
      'Date_Publication' => '2022-03-10',
      'Date_Modification' => '2025-02-04',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '4.0',
      'cwe_id' => '665.0',
      'cwe_name' => 'Improper Initialization',
    ),
    1 => 
    array (
      'CVE_ID' => 'CVE-2022-0847',
      'Description' => 'A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.',
      'Date_Publication' => '2022-03-10',
      'Date_Modification' => '2025-02-04',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '4.0',
      'cwe_id' => '665.0',
      'cwe_name' => 'Improper Initialization',
    ),
  ),
  'CVE-2022-24041' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-24041',
      'Description' => 'A vulnerability has been identified in Desigo DXR2 (All versions < V01.21.142.5-22), Desigo PXC3 (All versions < V01.21.142.4-18), Desigo PXC4 (All versions < V02.20.142.10-10884), Desigo PXC5 (All versions < V02.20.142.10-10884). The web application stores the PBKDF2 derived key of users passwords with a low iteration count. An attacker with user profile access privilege can retrieve the stored password hashes of other accounts and then successfully perform an offline cracking attack and recover the plaintext passwords of other users.',
      'Date_Publication' => '2022-05-10',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '103.0',
      'cwe_id' => '916.0',
      'cwe_name' => 'Use of Password Hash With Insufficient Computational Effort',
    ),
  ),
  'CVE-2022-2985' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-2985',
      'Description' => 'In music service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed.',
      'Date_Publication' => '2022-10-14',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '50.0',
      'cwe_id' => '862.0',
      'cwe_name' => 'Missing Authorization',
    ),
  ),
  'CVE-2022-43326' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-43326',
      'Description' => 'An Insecure Direct Object Reference (IDOR) vulnerability in the password reset function of Telos Alliance Omnia MPX Node 1.0.0-1.4.[*] allows attackers to arbitrarily change user and Administrator account passwords.',
      'Date_Publication' => '2022-11-29',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '43.0',
      'cwe_id' => '639.0',
      'cwe_name' => 'Authorization Bypass Through User-Controlled Key',
    ),
  ),
  'CVE-2022-43325' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-43325',
      'Description' => 'An unauthenticated command injection vulnerability in the product license validation function of Telos Alliance Omnia MPX Node 1.3.* - 1.4.* allows attackers to execute arbitrary commands via a crafted payload injected into the license input.',
      'Date_Publication' => '2022-12-02',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '46.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2022-31234' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-31234',
      'Description' => 'Dell EMC PowerStore, contain(s) an Improper Restriction of Excessive Authentication Attempts Vulnerability in PowerStore Manager GUI. A remote unauthenticated attacker could potentially exploit this vulnerability, leading to password brute-forcing. Account takeover is possible if weak passwords are used by users.',
      'Date_Publication' => '2022-07-21',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.1',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '62.0',
      'cwe_id' => '307.0',
      'cwe_name' => 'Improper Restriction of Excessive Authentication Attempts',
    ),
  ),
  'CVE-2022-32482' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-32482',
      'Description' => '
Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user with admin privileges may potentially exploit this vulnerability in order to modify a UEFI variable.





',
      'Date_Publication' => '2023-02-01',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.6',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '239.0',
      'cwe_id' => '20.0',
      'cwe_name' => 'Improper Input Validation',
    ),
  ),
  'CVE-2022-26861' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-26861',
      'Description' => 'Dell BIOS versions contain an Insecure Automated Optimization vulnerability. A local authenticated malicious user could exploit this vulnerability by sending malicious input via SMI to obtain arbitrary code execution during SMM.',
      'Date_Publication' => '2022-09-06',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.9',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '180.0',
      'cwe_id' => '1038.0',
      'cwe_name' => 'Insecure Automated Optimizations',
    ),
  ),
  'CVE-2022-22566' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-22566',
      'Description' => 'Select Dell Client Commercial and Consumer platforms contain a pre-boot direct memory access (DMA) vulnerability. An authenticated attacker with physical access to the system may potentially exploit this vulnerability in order to execute arbitrary code on the device.',
      'Date_Publication' => '2022-02-09',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '36.0',
      'cwe_id' => '1190.0',
      'cwe_name' => 'DMA Device Enabled Too Early in Boot Phase',
    ),
  ),
  'CVE-2020-7562' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2020-7562',
      'Description' => 'A CWE-125: Out-of-Bounds Read vulnerability exists in the Web Server on Modicon M340, Modicon Quantum and Modicon Premium Legacy offers and their Communication Modules (see notification for details) which could cause a segmentation fault or a buffer overflow when uploading a specially crafted file on the controller over FTP.',
      'Date_Publication' => '2020-11-18',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.1',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '302.0',
      'cwe_id' => '125.0',
      'cwe_name' => 'Out-of-bounds Read',
    ),
  ),
  'CVE-2020-7563' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2020-7563',
      'Description' => 'A CWE-787: Out-of-bounds Write vulnerability exists in the Web Server on Modicon M340, Modicon Quantum and Modicon Premium Legacy offers and their Communication Modules (see notification for details) which could cause corruption of data, a crash, or code execution when uploading a specially crafted file on the controller over FTP.',
      'Date_Publication' => '2020-11-18',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '302.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2023-2266' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-2266',
      'Description' => 'An Improper neutralization of input during web page generation in the Schweitzer Engineering Laboratories SEL-411L could allow an attacker to generate cross-site scripting based attacks against an authorized and authenticated user.



See product Instruction Manual Appendix A dated 20230830 for more details.


',
      'Date_Publication' => '2023-11-30',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '4.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '219.0',
      'cwe_id' => '79.0',
      'cwe_name' => 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    ),
  ),
  'CVE-2023-31161' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-31161',
      'Description' => 'An Improper Input Validation vulnerability in the Schweitzer Engineering Laboratories Real-Time Automation Controller (SEL RTAC) Web Interface could allow an authenticated remote attacker to use internal resources, allowing a variety of potential effects.

See SEL Service Bulletin dated 2022-11-15 for more details.',
      'Date_Publication' => '2023-05-10',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '15.0',
      'cwe_id' => '20.0',
      'cwe_name' => 'Improper Input Validation',
    ),
  ),
  'CVE-2023-23588' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-23588',
      'Description' => 'A vulnerability has been identified in SIMATIC IPC1047 (All versions), SIMATIC IPC1047E (All versions with maxView Storage Manager < 4.09.00.25611 on Windows), SIMATIC IPC647D (All versions), SIMATIC IPC647E (All versions with maxView Storage Manager < 4.09.00.25611 on Windows), SIMATIC IPC847D (All versions), SIMATIC IPC847E (All versions with maxView Storage Manager < 4.09.00.25611 on Windows). The Adaptec Maxview application on affected devices is using a non-unique TLS certificate across installations to protect the communication from the local browser to the local application.
A local attacker may use this key to decrypt intercepted local traffic between the browser and the application and could perform a man-in-the-middle attack in order to modify data in transit.',
      'Date_Publication' => '2023-04-11',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.2',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '87.0',
      'cwe_id' => '295.0',
      'cwe_name' => 'Improper Certificate Validation',
    ),
  ),
  'CVE-2023-29058' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-29058',
      'Description' => 'A valid, authenticated XCC user with read-only permissions can modify custom user roles on other user accounts and the user trespass message through the XCC CLI. There is no exposure if SSH is disabled or if there are no users assigned optional read-only permissions.',
      'Date_Publication' => '2023-04-28',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.4',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '29.0',
      'cwe_id' => '276.0',
      'cwe_name' => 'Incorrect Default Permissions',
    ),
  ),
  'CVE-2024-20002' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-20002',
      'Description' => 'In TVAPI, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: DTV03961715; Issue ID: DTV03961715.',
      'Date_Publication' => '2024-02-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '94.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-20010' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-20010',
      'Description' => 'In keyInstall, there is a possible escalation of privilege due to type confusion. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS08358560; Issue ID: ALPS08358560.',
      'Date_Publication' => '2024-02-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '94.0',
      'cwe_id' => '843.0',
      'cwe_name' => 'Access of Resource Using Incompatible Type (\'Type Confusion\')',
    ),
  ),
  'CVE-2024-20064' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-20064',
      'Description' => 'In wlan service, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS08572601; Issue ID: MSV-1229.',
      'Date_Publication' => '2024-05-06',
      'Date_Modification' => '2025-02-03',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '185.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-20011' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-20011',
      'Description' => 'In alac decoder, there is a possible information disclosure due to an incorrect bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS08441146; Issue ID: ALPS08441146.',
      'Date_Publication' => '2024-02-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '94.0',
      'cwe_id' => '119.0',
      'cwe_name' => 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
    ),
  ),
  'CVE-2024-20087' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-20087',
      'Description' => 'In vdec, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS08932916; Issue ID: MSV-1550.',
      'Date_Publication' => '2024-09-02',
      'Date_Modification' => '2024-09-05',
      'CVSSv3_Score' => '6.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '304.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2019-12647' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-12647',
      'Description' => 'A vulnerability in the Ident protocol handler of Cisco IOS and IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload. The vulnerability exists because the affected software incorrectly handles memory structures, leading to a NULL pointer dereference. An attacker could exploit this vulnerability by opening a TCP connection to specific ports and sending traffic over that connection. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a denial of service (DoS) condition.',
      'Date_Publication' => '2019-09-25',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.6',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '113.0',
      'cwe_id' => '476.0',
      'cwe_name' => 'NULL Pointer Dereference',
    ),
  ),
  'CVE-2019-0005' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-0005',
      'Description' => 'On EX2300, EX3400, EX4600, QFX3K and QFX5K series, firewall filter configuration cannot perform packet matching on any IPv6 extension headers. This issue may allow IPv6 packets that should have been blocked to be forwarded. IPv4 packet filtering is unaffected by this vulnerability. Affected releases are Juniper Networks Junos OS on EX and QFX series;: 14.1X53 versions prior to 14.1X53-D47; 15.1 versions prior to 15.1R7; 15.1X53 versions prior to 15.1X53-D234 on QFX5200/QFX5110 series; 15.1X53 versions prior to 15.1X53-D591 on EX2300/EX3400 series; 16.1 versions prior to 16.1R7; 17.1 versions prior to 17.1R2-S10, 17.1R3; 17.2 versions prior to 17.2R3; 17.3 versions prior to 17.3R3; 17.4 versions prior to 17.4R2; 18.1 versions prior to 18.1R2.',
      'Date_Publication' => '2019-01-15',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '96.0',
      'cwe_id' => '770.0',
      'cwe_name' => 'Allocation of Resources Without Limits or Throttling',
    ),
  ),
  'CVE-2019-0003' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-0003',
      'Description' => 'When a specific BGP flowspec configuration is enabled and upon receipt of a specific matching BGP packet meeting a specific term in the flowspec configuration, a reachable assertion failure occurs, causing the routing protocol daemon (rpd) process to crash with a core file being generated. Affected releases are Juniper Networks Junos OS: 12.1X46 versions prior to 12.1X46-D77 on SRX Series; 12.3 versions prior to 12.3R12-S10; 12.3X48 versions prior to 12.3X48-D70 on SRX Series; 14.1X53 versions prior to 14.1X53-D47 on EX2200/VC, EX3200, EX3300/VC, EX4200, EX4300, EX4550/VC, EX4600, EX6200, EX8200/VC (XRE), QFX3500, QFX3600, QFX5100; 15.1 versions prior to 15.1R3; 15.1F versions prior to 15.1F3; 15.1X49 versions prior to 15.1X49-D140 on SRX Series; 15.1X53 versions prior to 15.1X53-D59 on EX2300/EX3400.',
      'Date_Publication' => '2019-01-15',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '96.0',
      'cwe_id' => '617.0',
      'cwe_name' => 'Reachable Assertion',
    ),
  ),
  'CVE-2019-15468' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-15468',
      'Description' => 'The Xiaomi Mi A2 Lite Android device with a build fingerprint of xiaomi/daisy/daisy_sprout:9/PKQ1.180917.001/V10.0.3.0.PDLMIXM:user/release-keys contains a pre-installed app with a package name of com.huaqin.factory app (versionCode=1, versionName=QL1715_201812071953) that allows unauthorized wireless settings modification via a confused deputy attack. This capability can be accessed by any app co-located on the device.',
      'Date_Publication' => '2019-11-14',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '84.0',
      'cwe_id' => '610.0',
      'cwe_name' => 'Externally Controlled Reference to a Resource in Another Sphere',
    ),
  ),
  'CVE-2019-15913' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-15913',
      'Description' => 'An issue was discovered on Xiaomi DGNWG03LM, ZNCZ03LM, MCCGQ01LM, WSDCGQ01LM, RTCGQ01LM devices. Because of insecure key transport in ZigBee communication, causing attackers to gain sensitive information and denial of service attack, take over smart home devices, and tamper with messages.',
      'Date_Publication' => '2019-12-20',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '107.0',
      'cwe_id' => '639.0',
      'cwe_name' => 'Authorization Bypass Through User-Controlled Key',
    ),
  ),
  'CVE-2019-2248' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-2248',
      'Description' => 'Buffer overflow can occur if invalid header tries to overwrite the existing buffer which fix size allocation in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables in MDM9150, MDM9206, MDM9607, MDM9650, MSM8909W, MSM8996AU, Qualcomm 215, SD 210/SD 212/SD 205, SD 425, SD 427, SD 430, SD 435, SD 439 / SD 429, SD 450, SD 615/16/SD 415, SD 625, SD 632, SD 636, SD 650/52, SD 820, SD 820A, SD 845 / SD 850, SDM439, SDM660, SDX20',
      'Date_Publication' => '2019-05-24',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '165.0',
      'cwe_id' => '119.0',
      'cwe_name' => 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
    ),
  ),
  'CVE-2019-0135' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-0135',
      'Description' => 'Improper permissions in the installer for Intel(R) Accelerated Storage Manager in Intel(R) RSTe before version 5.5.0.2015 may allow an authenticated user to potentially enable escalation of privilege via local access. L-SA-00206',
      'Date_Publication' => '2019-03-14',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '121.0',
      'cwe_id' => '264.0',
      'cwe_name' => 'Inconnu',
    ),
  ),
  'CVE-2019-0164' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-0164',
      'Description' => 'Improper permissions in the installer for Intel(R) Turbo Boost Max Technology 3.0 driver version 1.0.0.1035 and before may allow an authenticated user to potentially enable escalation of privilege via local access.',
      'Date_Publication' => '2019-06-13',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.3',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '212.0',
      'cwe_id' => '264.0',
      'cwe_name' => 'Inconnu',
    ),
  ),
  'CVE-2019-6190' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-6190',
      'Description' => 'Lenovo was notified of a potential denial of service vulnerability, affecting various versions of BIOS for Lenovo Desktop, Desktop - All in One, and ThinkStation, that could cause PCRs to be cleared intermittently after resuming from sleep (S3) on systems with Intel TXT enabled.',
      'Date_Publication' => '2020-02-14',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.0',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '399.0',
      'cwe_id' => '665.0',
      'cwe_name' => 'Improper Initialization',
    ),
  ),
  'CVE-2019-6156' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-6156',
      'Description' => 'In Lenovo systems, SMM BIOS Write Protection is used to prevent writes to SPI Flash. While this provides sufficient protection, an additional layer of protection is provided by SPI Protected Range Registers (PRx). Lenovo was notified that after resuming from S3 sleep mode in various versions of BIOS for Lenovo systems, the PRx is not set. This does not impact the SMM BIOS Write Protection, which keeps systems protected.',
      'Date_Publication' => '2019-04-10',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '3.3',
      'Severity' => 'LOW',
      'Temps_de_correction' => '89.0',
      'cwe_id' => '667.0',
      'cwe_name' => 'Improper Locking',
    ),
  ),
  'CVE-2019-18618' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2019-18618',
      'Description' => 'Incorrect access control in the firmware of Synaptics VFS75xx family fingerprint sensors that include external flash (all versions prior to 2019-11-15) allows a local administrator or physical attacker to compromise the confidentiality of sensor data via injection of an unverified partition table.',
      'Date_Publication' => '2020-07-22',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.0',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '267.0',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2024-37037' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-37037',
      'Description' => 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory (‘Path
Traversal’) vulnerability exists that could allow an authenticated user with access to the device’s
web interface to corrupt files and impact device functionality when sending a crafted HTTP
request.',
      'Date_Publication' => '2024-06-12',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.1',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '12.0',
      'cwe_id' => '22.0',
      'cwe_name' => 'Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')',
    ),
  ),
  'CVE-2024-0542' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0542',
      'Description' => 'A vulnerability was found in Tenda W9 1.0.0.7(4456). It has been rated as critical. Affected by this issue is the function formWifiMacFilterGet of the component httpd. The manipulation of the argument index leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-250712. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2024-01-15',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-8453' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-8453',
      'Description' => 'Certain switch models from PLANET Technology use an insecure hashing function to hash user passwords without being salted. Remote attackers with administrator privileges can read configuration files to obtain the hash values, and potentially crack them to retrieve the plaintext passwords.',
      'Date_Publication' => '2024-09-30',
      'Date_Modification' => '2024-10-04',
      'CVSSv3_Score' => '4.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '25.0',
      'cwe_id' => '328.0',
      'cwe_name' => 'Use of Weak Hash',
    ),
    1 => 
    array (
      'CVE_ID' => 'CVE-2024-8453',
      'Description' => 'Certain switch models from PLANET Technology use an insecure hashing function to hash user passwords without being salted. Remote attackers with administrator privileges can read configuration files to obtain the hash values, and potentially crack them to retrieve the plaintext passwords.',
      'Date_Publication' => '2024-09-30',
      'Date_Modification' => '2024-10-04',
      'CVSSv3_Score' => '4.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '25.0',
      'cwe_id' => '759.0',
      'cwe_name' => 'Use of a One-Way Hash without a Salt',
    ),
    2 => 
    array (
      'CVE_ID' => 'CVE-2024-8453',
      'Description' => 'Certain switch models from PLANET Technology use an insecure hashing function to hash user passwords without being salted. Remote attackers with administrator privileges can read configuration files to obtain the hash values, and potentially crack them to retrieve the plaintext passwords.',
      'Date_Publication' => '2024-09-30',
      'Date_Modification' => '2024-10-04',
      'CVSSv3_Score' => '4.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '25.0',
      'cwe_id' => '328.0',
      'cwe_name' => 'Use of Weak Hash',
    ),
    3 => 
    array (
      'CVE_ID' => 'CVE-2024-8453',
      'Description' => 'Certain switch models from PLANET Technology use an insecure hashing function to hash user passwords without being salted. Remote attackers with administrator privileges can read configuration files to obtain the hash values, and potentially crack them to retrieve the plaintext passwords.',
      'Date_Publication' => '2024-09-30',
      'Date_Modification' => '2024-10-04',
      'CVSSv3_Score' => '4.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '25.0',
      'cwe_id' => '759.0',
      'cwe_name' => 'Use of a One-Way Hash without a Salt',
    ),
  ),
  'CVE-2024-8457' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-8457',
      'Description' => 'Certain switch models from PLANET Technology have a web application that does not properly validate specific parameters, allowing remote authenticated users with administrator privileges to inject arbitrary JavaScript, leading to Stored XSS attack.',
      'Date_Publication' => '2024-09-30',
      'Date_Modification' => '2024-10-04',
      'CVSSv3_Score' => '4.8',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '25.0',
      'cwe_id' => '79.0',
      'cwe_name' => 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    ),
  ),
  'CVE-2024-34057' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-34057',
      'Description' => 'Triangle Microworks TMW IEC 61850 Client source code libraries before 12.2.0 lack a buffer size check when processing received messages. The resulting buffer overflow can cause a crash, resulting in a denial of service.',
      'Date_Publication' => '2024-09-18',
      'Date_Modification' => '2024-09-25',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '141.0',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2023-30383' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-30383',
      'Description' => 'TP-LINK Archer C50v2 Archer C50(US)_V2_160801, TP-LINK Archer C20v1 Archer_C20_V1_150707, and TP-LINK Archer C2v1 Archer_C2_US__V1_170228 were discovered to contain a buffer overflow which may lead to a Denial of Service (DoS) when parsing crafted data.',
      'Date_Publication' => '2023-07-18',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '102.0',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2024-0541' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0541',
      'Description' => 'A vulnerability was found in Tenda W9 1.0.0.7(4456). It has been declared as critical. Affected by this vulnerability is the function formAddSysLogRule of the component httpd. The manipulation of the argument sysRulenEn leads to stack-based buffer overflow. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-250711. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2024-01-15',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2023-23451' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-23451',
      'Description' => 'The Flexi Classic and Flexi Soft Gateways SICK UE410-EN3 FLEXI ETHERNET GATEW. with serial number <=2311xxxx all Firmware versions, SICK UE410-EN1 FLEXI ETHERNET GATEW. with serial number <=2311xxxx all Firmware versions, SICK UE410-EN3S04 FLEXI ETHERNET GATEW. with serial number <=2311xxxx all Firmware versions, SICK UE410-EN4 FLEXI ETHERNET GATEW. with serial number <=2311xxxx all Firmware versions, SICK FX0-GENT00000 FLEXISOFT EIP GATEW. with serial number <=2311xxxx with Firmware <=V2.11.0, SICK FX0-GMOD00000 FLEXISOFT MOD GATEW. with serial number <=2311xxxx with Firmware <=V2.11.0, SICK FX0-GPNT00000 FLEXISOFT PNET GATEW. with serial number <=2311xxxx with Firmware <=V2.12.0, SICK FX0-GENT00030 FLEXISOFT EIP GATEW.V2 with serial number <=2311xxxx all Firmware versions, SICK FX0-GPNT00030 FLEXISOFT PNET GATEW.V2 with serial number <=2311xxxx all Firmware versions and SICK FX0-GMOD00010 FLEXISOFT MOD GW with serial number <=2311xxxx with Firmware <=V2.11.0 all have Telnet enabled by factory default. No password is set in the default configuration.',
      'Date_Publication' => '2023-04-19',
      'Date_Modification' => '2025-02-05',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '97.0',
      'cwe_id' => '306.0',
      'cwe_name' => 'Missing Authentication for Critical Function',
    ),
  ),
  'CVE-2023-48347' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-48347',
      'Description' => 'In video decoder, there is a possible out of bounds read due to improper input validation. This could lead to local denial of service with no additional execution privileges needed',
      'Date_Publication' => '2024-01-18',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '125.0',
      'cwe_name' => 'Out-of-bounds Read',
    ),
  ),
  'CVE-2023-20824' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-20824',
      'Description' => 'In duraspeed, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with no additional execution privilege needed. User interaction is not needed for exploitation. Patch ID: ALPS07951402; Issue ID: ALPS07951402.',
      'Date_Publication' => '2023-09-04',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '862.0',
      'cwe_name' => 'Missing Authorization',
    ),
  ),
  'CVE-2023-20750' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-20750',
      'Description' => 'In swpm, there is a possible out of bounds write due to a race condition. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07780926; Issue ID: ALPS07780928.',
      'Date_Publication' => '2023-06-06',
      'Date_Modification' => '2025-01-07',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '362.0',
      'cwe_name' => 'Concurrent Execution using Shared Resource with Improper Synchronization (\'Race Condition\')',
    ),
    1 => 
    array (
      'CVE_ID' => 'CVE-2023-20750',
      'Description' => 'In swpm, there is a possible out of bounds write due to a race condition. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07780926; Issue ID: ALPS07780928.',
      'Date_Publication' => '2023-06-06',
      'Date_Modification' => '2025-01-07',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2023-20825' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-20825',
      'Description' => 'In duraspeed, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with no additional execution privilege needed. User interaction is not needed for exploitation. Patch ID: ALPS07951402; Issue ID: ALPS07951413.',
      'Date_Publication' => '2023-09-04',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '862.0',
      'cwe_name' => 'Missing Authorization',
    ),
  ),
  'CVE-2022-24162' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-24162',
      'Description' => 'Tenda AX3 v16.03.12.10_CN was discovered to contain a stack overflow in the function saveParentControlInfo. This vulnerability allows attackers to cause a Denial of Service (DoS) via the time parameter.',
      'Date_Publication' => '2022-02-04',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '4.0',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2022-26320' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-26320',
      'Description' => 'The Rambus SafeZone Basic Crypto Module before 10.4.0, as used in certain Fujifilm (formerly Fuji Xerox) devices before 2022-03-01, Canon imagePROGRAF and imageRUNNER devices through 2022-03-14, and potentially many other devices, generates RSA keys that can be broken with Fermat\'s factorization method. This allows efficient calculation of private RSA keys from the public key of a TLS certificate.',
      'Date_Publication' => '2022-03-14',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.1',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '14.0',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2022-48440' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-48440',
      'Description' => 'In dialer service, there is a possible missing permission check. This could lead to local denial of service with no additional execution privileges.',
      'Date_Publication' => '2023-06-06',
      'Date_Modification' => '2025-01-07',
      'CVSSv3_Score' => '5.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '54.0',
      'cwe_id' => '862.0',
      'cwe_name' => 'Missing Authorization',
    ),
  ),
  'CVE-2021-1370' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-1370',
      'Description' => 'A vulnerability in a CLI command of Cisco IOS XR Software for the Cisco 8000 Series Routers and Network Convergence System 540 Series Routers running NCS540L software images could allow an authenticated, local attacker to elevate their privilege to root. To exploit this vulnerability, an attacker would need to have a valid account on an affected device. The vulnerability is due to insufficient validation of command line arguments. An attacker could exploit this vulnerability by authenticating to the device and entering a crafted command at the prompt. A successful exploit could allow an attacker with low-level privileges to escalate their privilege level to root.',
      'Date_Publication' => '2021-02-04',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '83.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2021-34725' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-34725',
      'Description' => 'A vulnerability in the CLI of Cisco IOS XE SD-WAN Software could allow an authenticated, local attacker to inject arbitrary commands to be executed with root-level privileges on the underlying operating system. This vulnerability is due to insufficient input validation on certain CLI commands. An attacker could exploit this vulnerability by authenticating to an affected device and submitting crafted input to the CLI. The attacker must be authenticated as an administrative user to execute the affected commands. A successful exploit could allow the attacker to execute commands with root-level privileges.',
      'Date_Publication' => '2021-09-23',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '100.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2021-1621' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-1621',
      'Description' => 'A vulnerability in the Layer 2 punt code of Cisco IOS XE Software could allow an unauthenticated, adjacent attacker to cause a queue wedge on an interface that receives specific Layer 2 frames, resulting in a denial of service (DoS) condition. This vulnerability is due to improper handling of certain Layer 2 frames. An attacker could exploit this vulnerability by sending specific Layer 2 frames on the segment the router is connected to. A successful exploit could allow the attacker to cause a queue wedge on the interface, resulting in a DoS condition.',
      'Date_Publication' => '2021-09-23',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.4',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '314.0',
      'cwe_id' => '399.0',
      'cwe_name' => 'Inconnu',
    ),
  ),
  'CVE-2020-1793' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2020-1793',
      'Description' => 'There is an improper authentication vulnerability in several smartphones. The applock does not perform a sufficient authentication in certain scenarios, successful exploit could allow the attacker to gain certain data of the application which is locked. Affected product versions include:HUAWEI Mate 20 versions Versions earlier than 10.0.0.188(C00E74R3P8);HUAWEI Mate 30 Pro versions Versions earlier than 10.0.0.203(C00E202R7P2).',
      'Date_Publication' => '2020-03-20',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '4.6',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '112.0',
      'cwe_id' => '287.0',
      'cwe_name' => 'Improper Authentication',
    ),
  ),
  'CVE-2021-20171' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-20171',
      'Description' => 'Netgear RAX43 version 1.0.3.96 stores sensitive information in plaintext. All usernames and passwords for the device\'s associated services are stored in plaintext on the device. For example, the admin password is stored in plaintext in the primary configuration file on the device.',
      'Date_Publication' => '2021-12-30',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '378.0',
      'cwe_id' => '312.0',
      'cwe_name' => 'Cleartext Storage of Sensitive Information',
    ),
  ),
  'CVE-2021-38514' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2021-38514',
      'Description' => 'Certain NETGEAR devices are affected by authentication bypass. This affects D3600 before 1.0.0.72, D6000 before 1.0.0.72, D6100 before 1.0.0.63, D6200 before 1.1.00.34, D6220 before 1.0.0.48, D6400 before 1.0.0.86, D7000 before 1.0.1.70, D7000v2 before 1.0.0.52, D7800 before 1.0.1.56, D8500 before 1.0.3.44, DC112A before 1.0.0.42, DGN2200v4 before 1.0.0.108, DGND2200Bv4 before 1.0.0.108, EX2700 before 1.0.1.48, EX3700 before 1.0.0.76, EX3800 before 1.0.0.76, EX6000 before 1.0.0.38, EX6100 before 1.0.2.24, EX6100v2 before 1.0.1.76, EX6120 before 1.0.0.42, EX6130 before 1.0.0.28, EX6150v1 before 1.0.0.42, EX6150v2 before 1.0.1.76, EX6200 before 1.0.3.88, EX6200v2 before 1.0.1.72, EX6400 before 1.0.2.136, EX7000 before 1.0.0.66, EX7300 before 1.0.2.136, EX8000 before 1.0.1.180, RBK50 before 2.1.4.10, RBR50 before 2.1.4.10, RBS50 before 2.1.4.10, RBK40 before 2.1.4.10, RBR40 before 2.1.4.10, RBS40 before 2.1.4.10, RBW30 before 2.2.1.204, PR2000 before 1.0.0.28, R6020 before 1.0.0.38, R6080 before 1.0.0.38, R6050 before 1.0.1.18, JR6150 before 1.0.1.18, R6120 before 1.0.0.46, R6220 before 1.1.0.86, R6250 before 1.0.4.34, R6300v2 before 1.0.4.32, R6400 before 1.0.1.44, R6400v2 before 1.0.2.62, R6700 before 1.0.1.48, R6700v2 before 1.2.0.36, R6800 before 1.2.0.36, R6900v2 before 1.2.0.36, R6900 before 1.0.1.48, R7000 before 1.0.9.34, R6900P before 1.3.1.64, R7000P before 1.3.1.64, R7100LG before 1.0.0.48, R7300DST before 1.0.0.70, R7500v2 before 1.0.3.38, R7800 before 1.0.2.52, R7900 before 1.0.3.8, R8000 before 1.0.4.28, R7900P before 1.4.1.30, R8000P before 1.4.1.30, R8300 before 1.0.2.128, R8500 before 1.0.2.128, R9000 before 1.0.3.10, RBS40V before 2.2.0.58, RBK50V before 2.2.0.58, WN2000RPTv3 before 1.0.1.32, WN2500RPv2 before 1.0.1.54, WN3000RPv3 before 1.0.2.78, WN3100RPv2 before 1.0.0.66, WNDR3400v3 before 1.0.1.22, WNDR3700v4 before 1.0.2.102, WNDR4300v1 before 1.0.2.104, WNDR4300v2 before 1.0.0.56, WNDR4500v3 before 1.0.0.56, WNR2000v5 (R2000) before 1.0.0.66, WNR2020 before 1.1.0.62, WNR2050 before 1.1.0.62, WNR3500Lv2 before 1.2.0.62, and XR500 before 2.3.2.22.',
      'Date_Publication' => '2021-08-11',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '2.4',
      'Severity' => 'LOW',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2022-41005' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-41005',
      'Description' => 'Several stack-based buffer overflow vulnerabilities exist in the DetranCLI command parsing functionality of Siretta QUARTZ-GOLD G5.0.1.5-210720-141020. A specially-crafted network packet can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.This buffer overflow is in the function that manages the \'ip static route destination A.B.C.D gateway A.B.C.D mask A.B.C.D metric <0-10> interface (lan|wan|vpn) description WORD\' command template.',
      'Date_Publication' => '2023-01-26',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2022-24023' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-24023',
      'Description' => 'A buffer overflow vulnerability exists in the GetValue functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted configuration value can lead to a buffer overflow. An attacker can modify a configuration value to trigger this vulnerability.This vulnerability represents all occurances of the buffer overflow vulnerability within the pppd binary.',
      'Date_Publication' => '2022-08-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2022-24019' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-24019',
      'Description' => 'A buffer overflow vulnerability exists in the GetValue functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted configuration value can lead to a buffer overflow. An attacker can modify a configuration value to trigger this vulnerability.This vulnerability represents all occurances of the buffer overflow vulnerability within the netctrl binary.',
      'Date_Publication' => '2022-08-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2022-45562' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-45562',
      'Description' => 'Insecure permissions in Telos Alliance Omnia MPX Node v1.0.0 to v1.4.9 allow attackers to manipulate and access system settings with backdoor account low privilege, this can lead to change hardware settings and execute arbitrary commands in vulnerable system functions that is requires high privilege to access.',
      'Date_Publication' => '2022-12-02',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '276.0',
      'cwe_name' => 'Incorrect Default Permissions',
    ),
  ),
  'CVE-2025-25625' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-25625',
      'Description' => 'A stored cross-site scripting vulnerability exists in FS model S3150-8T2F switches running firmware s3150-8t2f-switch-fsos-220d_118101 and web firmware v2.2.2, which allows an authenticated web interface user to bypass input filtering on user names, and stores un-sanitized HTML and Javascript on the device. Pages which then present the user name without encoding special characters will then cause the injected code to be parsed by the browsers of other users accessing the web interface.',
      'Date_Publication' => '2025-03-13',
      'Date_Modification' => '2025-04-03',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2025-1283' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-1283',
      'Description' => 'The Dingtian DT-R0 Series is vulnerable to an exploit that allows 
attackers to bypass login requirements by directly navigating to the 
main page.',
      'Date_Publication' => '2025-02-13',
      'Date_Modification' => '2025-04-10',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '288.0',
      'cwe_name' => 'Authentication Bypass Using an Alternate Path or Channel',
    ),
  ),
  'CVE-2025-20633' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-20633',
      'Description' => 'In wlan AP driver, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote (proximal/adjacent) code execution with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: WCNCR00400889; Issue ID: MSV-2491.',
      'Date_Publication' => '2025-02-03',
      'Date_Modification' => '2025-03-18',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2025-25742' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-25742',
      'Description' => 'D-Link DIR-853 A1 FW1.20B07 was discovered to contain a stack-based buffer overflow vulnerability via the AccountPassword parameter in the SetSysEmailSettings module.',
      'Date_Publication' => '2025-02-12',
      'Date_Modification' => '2025-03-05',
      'CVSSv3_Score' => '',
      'Severity' => '',
      'Temps_de_correction' => '',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-38426' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-38426',
      'Description' => 'While processing the authentication message in UE, improper authentication may lead to information disclosure.',
      'Date_Publication' => '2025-03-03',
      'Date_Modification' => '2025-03-06',
      'CVSSv3_Score' => '5.4',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '260.0',
      'cwe_id' => '287.0',
      'cwe_name' => 'Improper Authentication',
    ),
  ),
  'CVE-2023-22767' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-22767',
      'Description' => 'Authenticated command injection vulnerabilities exist in the ArubaOS command line interface. Successful exploitation of these vulnerabilities result in the ability to execute arbitrary commands as a privileged user on the underlying operating system.

',
      'Date_Publication' => '2023-03-01',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '53.0',
      'cwe_id' => '77.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in a Command (\'Command Injection\')',
    ),
  ),
  'CVE-2023-25495' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-25495',
      'Description' => 'A valid, authenticated administrative user can query a web interface API to reveal the configured LDAP client password used by XCC to authenticate to an external LDAP server in certain configurations.  There is no exposure where no LDAP client password is configured',
      'Date_Publication' => '2023-04-28',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '4.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '81.0',
      'cwe_id' => '522.0',
      'cwe_name' => 'Insufficiently Protected Credentials',
    ),
  ),
  'CVE-2023-4608' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-4608',
      'Description' => 'An authenticated XCC user with elevated privileges can perform blind SQL injection in limited cases through a crafted API command. 

This affects ThinkSystem v2 and v3 servers with XCC; ThinkSystem v1 servers are not affected.',
      'Date_Publication' => '2023-10-25',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '4.1',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '56.0',
      'cwe_id' => '89.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an SQL Command (\'SQL Injection\')',
    ),
  ),
  'CVE-2023-25492' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-25492',
      'Description' => 'A valid, authenticated user may be able to trigger a denial of service of the XCC web user interface or other undefined behavior through a format string injection vulnerability in a web interface API.',
      'Date_Publication' => '2023-05-01',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '83.0',
      'cwe_id' => '134.0',
      'cwe_name' => 'Use of Externally-Controlled Format String',
    ),
  ),
  'CVE-2023-4607' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-4607',
      'Description' => 'An authenticated XCC user can change permissions for any user through a crafted API command.',
      'Date_Publication' => '2023-10-25',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '56.0',
      'cwe_id' => '269.0',
      'cwe_name' => 'Improper Privilege Management',
    ),
  ),
  'CVE-2023-2290' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-2290',
      'Description' => 'A potential vulnerability in the LenovoFlashDeviceInterface SMI handler may allow an attacker with local access and elevated privileges to execute arbitrary code.',
      'Date_Publication' => '2023-06-26',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.4',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '62.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2023-2993' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-2993',
      'Description' => 'A valid, authenticated user with limited privileges may be able to use specifically crafted web management server API calls to execute a limited number of commands on SMM v1, SMM v2, and FPC that the user does not normally have sufficient privileges to execute.',
      'Date_Publication' => '2023-06-26',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.4',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '27.0',
      'cwe_id' => '281.0',
      'cwe_name' => 'Improper Preservation of Permissions',
    ),
  ),
  'CVE-2024-44845' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-44845',
      'Description' => 'DrayTek Vigor3900 v1.5.1.6 was discovered to contain an authenticated command injection vulnerability via the value parameter in the filter_string function.',
      'Date_Publication' => '2024-09-06',
      'Date_Modification' => '2024-09-11',
      'CVSSv3_Score' => '8.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '16.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2024-46591' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-46591',
      'Description' => 'Draytek Vigor 3910 v4.3.2.6 was discovered to contain a buffer overflow in the sDnsPro parameter at v2x00.cgi. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input.',
      'Date_Publication' => '2024-09-18',
      'Date_Modification' => '2024-09-24',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '7.0',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2024-37039' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-37039',
      'Description' => 'CWE-252: Unchecked Return Value vulnerability exists that could cause denial of service of the
device when an attacker sends a specially crafted HTTP request.',
      'Date_Publication' => '2024-06-12',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '12.0',
      'cwe_id' => '252.0',
      'cwe_name' => 'Unchecked Return Value',
    ),
  ),
  'CVE-2024-20263' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-20263',
      'Description' => 'A vulnerability with the access control list (ACL) management within a stacked switch configuration of Cisco Business 250 Series Smart Switches and Business 350 Series Managed Switches could allow an unauthenticated, remote attacker to bypass protection offered by a configured ACL on an affected device. This vulnerability is due to incorrect processing of ACLs on a stacked configuration when either the primary or backup switches experience a full stack reload or power cycle. An attacker could exploit this vulnerability by sending crafted traffic through an affected device. A successful exploit could allow the attacker to bypass configured ACLs, causing traffic to be dropped or forwarded in an unexpected manner. The attacker does not have control over the conditions that result in the device being in the vulnerable state. Note: In the vulnerable state, the ACL would be correctly applied on the primary devices but could be incorrectly applied to the backup devices.',
      'Date_Publication' => '2024-01-26',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.8',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '79.0',
      'cwe_id' => '',
      'cwe_name' => '',
    ),
  ),
  'CVE-2024-45829' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-45829',
      'Description' => 'Sharp and Toshiba Tec MFPs provide the web page to download data, where query parameters in HTTP requests are improperly processed and resulting in an Out-of-bounds Read vulnerability.
Crafted HTTP requests may cause affected products crashed.',
      'Date_Publication' => '2024-10-25',
      'Date_Modification' => '2024-11-05',
      'CVSSv3_Score' => '4.9',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '9.0',
      'cwe_id' => '125.0',
      'cwe_name' => 'Out-of-bounds Read',
    ),
  ),
  'CVE-2024-49408' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-49408',
      'Description' => 'Out-of-bounds write in usb driver prior to Firmware update Sep-2024 Release on Galaxy S24 allows local attackers to write out-of-bounds memory. System privilege is required for triggering this vulnerability.',
      'Date_Publication' => '2024-11-06',
      'Date_Modification' => '2024-11-13',
      'CVSSv3_Score' => '6.4',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '21.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-0717' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0717',
      'Description' => 'A vulnerability classified as critical was found in D-Link DAP-1360, DIR-300, DIR-615, DIR-615GF, DIR-615S, DIR-615T, DIR-620, DIR-620S, DIR-806A, DIR-815, DIR-815AC, DIR-815S, DIR-816, DIR-820, DIR-822, DIR-825, DIR-825AC, DIR-825ACF, DIR-825ACG1, DIR-841, DIR-842, DIR-842S, DIR-843, DIR-853, DIR-878, DIR-882, DIR-1210, DIR-1260, DIR-2150, DIR-X1530, DIR-X1860, DSL-224, DSL-245GR, DSL-2640U, DSL-2750U, DSL-G2452GR, DVG-5402G, DVG-5402G, DVG-5402GFRU, DVG-N5402G, DVG-N5402G-IL, DWM-312W, DWM-321, DWR-921, DWR-953 and Good Line Router v2 up to 20240112. This vulnerability affects unknown code of the file /devinfo of the component HTTP GET Request Handler. The manipulation of the argument area with the input notice|net|version leads to information disclosure. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-251542 is the identifier assigned to this vulnerability.',
      'Date_Publication' => '2024-01-19',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '200.0',
      'cwe_name' => 'Exposure of Sensitive Information to an Unauthorized Actor',
    ),
  ),
  'CVE-2024-33182' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-33182',
      'Description' => 'Tenda AC18 V15.03.3.10_EN was discovered to contain a stack-based buffer overflow vulnerability via the deviceId parameter at ip/goform/addWifiMacFilter.',
      'Date_Publication' => '2024-07-16',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '84.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-0928' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0928',
      'Description' => 'A vulnerability was found in Tenda AC10U 15.03.06.49_multi_TDE01. It has been declared as critical. Affected by this vulnerability is the function fromDhcpListClient. The manipulation of the argument page/listN leads to stack-based buffer overflow. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-252133 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2024-01-26',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '4.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '121.0',
      'cwe_name' => 'Stack-based Buffer Overflow',
    ),
  ),
  'CVE-2024-33180' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-33180',
      'Description' => 'Tenda AC18 V15.03.3.10_EN was discovered to contain a stack-based buffer overflow vulnerability via the deviceId parameter at ip/goform/saveParentControlInfo.',
      'Date_Publication' => '2024-07-16',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '84.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-41468' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-41468',
      'Description' => 'Tenda FH1201 v1.2.0.14 was discovered to contain a command injection vulnerability via the cmdinput parameter at /goform/exeCommand',
      'Date_Publication' => '2024-07-25',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '7.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2024-41462' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-41462',
      'Description' => 'Tenda FH1201 v1.2.0.14 was discovered to contain a stack-based buffer overflow vulnerability via the page parameter at ip/goform/DhcpListClient.',
      'Date_Publication' => '2024-07-24',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '6.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-23786' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-23786',
      'Description' => 'Cross-site scripting vulnerability in Energy Management Controller with Cloud Services JH-RVB1 /JH-RV11 Ver.B0.1.9.1 and earlier allows a network-adjacent unauthenticated attacker to execute an arbitrary script on the web browser of the user who is accessing the management page of the affected product.',
      'Date_Publication' => '2024-02-14',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.3',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '23.0',
      'cwe_id' => '79.0',
      'cwe_name' => 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    ),
  ),
  'CVE-2024-47801' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-47801',
      'Description' => 'Sharp and Toshiba Tec MFPs improperly process query parameters in HTTP requests, resulting in a reflected cross-site scripting vulnerability.
Accessing a crafted URL which points to an affected product may cause malicious script executed on the web browser.',
      'Date_Publication' => '2024-10-25',
      'Date_Modification' => '2024-11-05',
      'CVSSv3_Score' => '7.4',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '9.0',
      'cwe_id' => '79.0',
      'cwe_name' => 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    ),
  ),
  'CVE-2024-53027' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-53027',
      'Description' => 'Transient DOS may occur while processing the country IE.',
      'Date_Publication' => '2025-03-03',
      'Date_Modification' => '2025-03-06',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '104.0',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2023-21517' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-21517',
      'Description' => 'Heap out-of-bound write vulnerability in Exynos baseband prior to SMR Jun-2023 Release 1 allows remote attacker to execute arbitrary code.',
      'Date_Publication' => '2023-06-28',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '226.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2023-27965' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2023-27965',
      'Description' => 'A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.3, Studio Display Firmware Update 16.4. An app may be able to execute arbitrary code with kernel privileges.',
      'Date_Publication' => '2023-05-08',
      'Date_Modification' => '2025-01-29',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '61.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-27374' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-27374',
      'Description' => 'An issue was discovered in Samsung Mobile Processor Exynos 980, Exynos 850, Exynos 1280, Exynos 1380, and Exynos 1330. In the function slsi_nan_publish_get_nl_params(), there is no input validation check on hal_req->service_specific_info_len coming from userspace, which can lead to a heap overwrite.',
      'Date_Publication' => '2024-06-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '101.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2025-1613' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-1613',
      'Description' => 'A vulnerability was found in FiberHome AN5506-01A ONU GPON RP2511. It has been rated as problematic. This issue affects some unknown processing of the file /goform/URL_filterCfg of the component URL Filtering Submenu. The manipulation of the argument url_IP leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2025-02-24',
      'Date_Modification' => '2025-02-28',
      'CVSSv3_Score' => '2.4',
      'Severity' => 'LOW',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '79.0',
      'cwe_name' => 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    ),
    1 => 
    array (
      'CVE_ID' => 'CVE-2025-1613',
      'Description' => 'A vulnerability was found in FiberHome AN5506-01A ONU GPON RP2511. It has been rated as problematic. This issue affects some unknown processing of the file /goform/URL_filterCfg of the component URL Filtering Submenu. The manipulation of the argument url_IP leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2025-02-24',
      'Date_Modification' => '2025-02-28',
      'CVSSv3_Score' => '2.4',
      'Severity' => 'LOW',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '94.0',
      'cwe_name' => 'Improper Control of Generation of Code (\'Code Injection\')',
    ),
    2 => 
    array (
      'CVE_ID' => 'CVE-2025-1613',
      'Description' => 'A vulnerability was found in FiberHome AN5506-01A ONU GPON RP2511. It has been rated as problematic. This issue affects some unknown processing of the file /goform/URL_filterCfg of the component URL Filtering Submenu. The manipulation of the argument url_IP leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2025-02-24',
      'Date_Modification' => '2025-02-28',
      'CVSSv3_Score' => '2.4',
      'Severity' => 'LOW',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '79.0',
      'cwe_name' => 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    ),
    3 => 
    array (
      'CVE_ID' => 'CVE-2025-1613',
      'Description' => 'A vulnerability was found in FiberHome AN5506-01A ONU GPON RP2511. It has been rated as problematic. This issue affects some unknown processing of the file /goform/URL_filterCfg of the component URL Filtering Submenu. The manipulation of the argument url_IP leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2025-02-24',
      'Date_Modification' => '2025-02-28',
      'CVSSv3_Score' => '2.4',
      'Severity' => 'LOW',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '94.0',
      'cwe_name' => 'Improper Control of Generation of Code (\'Code Injection\')',
    ),
  ),
  'CVE-2024-0555' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0555',
      'Description' => 'A Cross-Site Request Forgery (CSRF) vulnerability has been found on WIC1200, affecting version 1.1. An authenticated user could lead another user into executing unwanted actions inside the application they are logged in. This vulnerability is possible due to the lack of propper CSRF token implementation.',
      'Date_Publication' => '2024-01-16',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '4.6',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '352.0',
      'cwe_name' => 'Cross-Site Request Forgery (CSRF)',
    ),
  ),
  'CVE-2025-23006' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2025-23006',
      'Description' => 'Pre-authentication deserialization of untrusted data vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) and Central Management Console (CMC), which in specific conditions could potentially enable a remote unauthenticated attacker to execute arbitrary OS commands.',
      'Date_Publication' => '2025-01-23',
      'Date_Modification' => '2025-04-02',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '14.0',
      'cwe_id' => '502.0',
      'cwe_name' => 'Deserialization of Untrusted Data',
    ),
  ),
  'CVE-2024-24946' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-24946',
      'Description' => 'A heap-based buffer overflow vulnerability exists in the Programming Software Connection CurrDir functionality of AutomationDirect P3-550E 1.2.10.9. A specially crafted network packet can lead to denial of service. An attacker can send an unauthenticated packet to trigger these vulnerability.This CVE tracks the heap corruption that occurs at offset `0xb686c` of version 1.2.10.9 of the P3-550E firmware, which occurs when a call to `memset` relies on an attacker-controlled length value and corrupts any trailing heap allocations.',
      'Date_Publication' => '2024-05-28',
      'Date_Modification' => '2025-02-12',
      'CVSSv3_Score' => '8.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '116.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-23315' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-23315',
      'Description' => 'A read-what-where vulnerability exists in the Programming Software Connection IMM 01A1 Memory Read functionality of AutomationDirect P3-550E 1.2.10.9. A specially crafted network packet can lead to a disclosure of sensitive information. An attacker can send an unauthenticated packet to trigger this vulnerability.',
      'Date_Publication' => '2024-05-28',
      'Date_Modification' => '2025-02-12',
      'CVSSv3_Score' => '7.5',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '116.0',
      'cwe_id' => '284.0',
      'cwe_name' => 'Improper Access Control',
    ),
  ),
  'CVE-2024-24959' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-24959',
      'Description' => 'Several out-of-bounds write vulnerabilities exist in the Programming Software Connection FileSystem API functionality of AutomationDirect P3-550E 1.2.10.9. Specially crafted network packets can lead to heap-based memory corruption. An attacker can send malicious packets to trigger these vulnerabilities.This CVE tracks the arbitrary null-byte write vulnerability located in firmware 1.2.10.9 of the P3-550E at offset `0xb6c18`.',
      'Date_Publication' => '2024-05-28',
      'Date_Modification' => '2025-02-12',
      'CVSSv3_Score' => '8.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '116.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-24947' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-24947',
      'Description' => 'A heap-based buffer overflow vulnerability exists in the Programming Software Connection CurrDir functionality of AutomationDirect P3-550E 1.2.10.9. A specially crafted network packet can lead to denial of service. An attacker can send an unauthenticated packet to trigger these vulnerability.This CVE tracks the heap corruption that occurs at offset `0xb68c4` of version 1.2.10.9 of the P3-550E firmware, which occurs when a call to `memset` relies on an attacker-controlled length value and corrupts any trailing heap allocations.',
      'Date_Publication' => '2024-05-28',
      'Date_Modification' => '2025-02-12',
      'CVSSv3_Score' => '8.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '116.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-24962' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-24962',
      'Description' => 'A stack-based buffer overflow vulnerability exists in the Programming Software Connection FileSelect functionality of AutomationDirect P3-550E 1.2.10.9. A specially crafted network packet can lead to stack-based buffer overflow. An attacker can send an unauthenticated packet to trigger this vulnerability.This CVE tracks the stack-based buffer overflow that occurs at offset `0xb6e98` of v1.2.10.9 of the P3-550E firmware.',
      'Date_Publication' => '2024-05-28',
      'Date_Modification' => '2025-02-12',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '116.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-39427' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-39427',
      'Description' => 'In trusty service, there is a possible out of bounds write due to a missing bounds check. This could lead to local denial of service with System execution privileges needed',
      'Date_Publication' => '2024-07-01',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.1',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '6.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-39433' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-39433',
      'Description' => 'In drm service, there is a possible out of bounds write due to a missing bounds check. This could lead to local denial of service with System execution privileges needed.',
      'Date_Publication' => '2024-09-27',
      'Date_Modification' => '2024-09-30',
      'CVSSv3_Score' => '6.2',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '94.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-39539' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-39539',
      'Description' => 'A Missing Release of Memory after Effective Lifetime vulnerability in Juniper Networks Junos OS on MX Series allows an unauthenticated adjacent attacker to cause a Denial-of-Service (DoS).

In a subscriber management scenario continuous subscriber logins will trigger a memory leak and eventually lead to an FPC crash and restart.

This issue affects Junos OS on MX Series:



  *  All version before 21.2R3-S6,
  *  21.4 versions before 21.4R3-S6,
  *  22.1 versions before 22.1R3-S5,
  *  22.2 versions before 22.2R3-S3, 
  *  22.3 versions before 22.3R3-S2,
  *  22.4 versions before 22.4R3,
  *  23.2 versions before 23.2R2.',
      'Date_Publication' => '2024-07-11',
      'Date_Modification' => '2025-03-05',
      'CVSSv3_Score' => '5.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '16.0',
      'cwe_id' => '401.0',
      'cwe_name' => 'Missing Release of Memory after Effective Lifetime',
    ),
  ),
  'CVE-2024-21461' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-21461',
      'Description' => 'Memory corruption while performing finish HMAC operation when context is freed by keymaster.',
      'Date_Publication' => '2024-07-01',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.4',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '202.0',
      'cwe_id' => '415.0',
      'cwe_name' => 'Double Free',
    ),
  ),
  'CVE-2022-21743' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-21743',
      'Description' => 'In ion, there is a possible use after free due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06371108; Issue ID: ALPS06371108.',
      'Date_Publication' => '2022-05-03',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '158.0',
      'cwe_id' => '190.0',
      'cwe_name' => 'Integer Overflow or Wraparound',
    ),
  ),
  'CVE-2022-42433' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-42433',
      'Description' => 'This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link TL-WR841N TL-WR841N(US)_V14_220121 routers. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed. The specific flaw exists within the ated_tp service. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-17356.',
      'Date_Publication' => '2023-03-29',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.4',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '177.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2018-14318' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2018-14318',
      'Description' => 'This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Samsung Galaxy S8 G950FXXU1AQL5. User interaction is required to exploit this vulnerability in that the target must have their cellular radios enabled. The specific flaw exists within the handling of IPCP headers. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length, stack-based buffer. An attacker can leverage this vulnerability to execute code under the context of the baseband processor. Was ZDI-CAN-5368.',
      'Date_Publication' => '2018-09-24',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '71.0',
      'cwe_id' => '20.0',
      'cwe_name' => 'Improper Input Validation',
    ),
  ),
  'CVE-2022-38675' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-38675',
      'Description' => 'In  gpu driver, there is a possible out of bounds write due to a missing bounds check. This could lead to local denial of service in kernel.',
      'Date_Publication' => '2023-02-12',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '5.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '167.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2022-24017' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-24017',
      'Description' => 'A buffer overflow vulnerability exists in the GetValue functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted configuration value can lead to a buffer overflow. An attacker can modify a configuration value to trigger this vulnerability.This vulnerability represents all occurances of the buffer overflow vulnerability within the miniupnpd binary.',
      'Date_Publication' => '2022-08-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.6',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '191.0',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2022-24029' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-24029',
      'Description' => 'A buffer overflow vulnerability exists in the GetValue functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted configuration value can lead to a buffer overflow. An attacker can modify a configuration value to trigger this vulnerability.This vulnerability represents all occurances of the buffer overflow vulnerability within the rp-pppoe.so binary.',
      'Date_Publication' => '2022-08-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.6',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '191.0',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2022-24005' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-24005',
      'Description' => 'A buffer overflow vulnerability exists in the GetValue functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted configuration value can lead to a buffer overflow. An attacker can modify a configuration value to trigger this vulnerability.This vulnerability represents all occurances of the buffer overflow vulnerability within the ap_steer binary.',
      'Date_Publication' => '2022-08-05',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.6',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '191.0',
      'cwe_id' => '120.0',
      'cwe_name' => 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')',
    ),
  ),
  'CVE-2024-37990' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-37990',
      'Description' => 'A vulnerability has been identified in SIMATIC Reader RF610R CMIIT (6GT2811-6BC10-2AA0) (All versions < V4.2), SIMATIC Reader RF610R ETSI (6GT2811-6BC10-0AA0) (All versions < V4.2), SIMATIC Reader RF610R FCC (6GT2811-6BC10-1AA0) (All versions < V4.2), SIMATIC Reader RF615R CMIIT (6GT2811-6CC10-2AA0) (All versions < V4.2), SIMATIC Reader RF615R ETSI (6GT2811-6CC10-0AA0) (All versions < V4.2), SIMATIC Reader RF615R FCC (6GT2811-6CC10-1AA0) (All versions < V4.2), SIMATIC Reader RF650R ARIB (6GT2811-6AB20-4AA0) (All versions < V4.2), SIMATIC Reader RF650R CMIIT (6GT2811-6AB20-2AA0) (All versions < V4.2), SIMATIC Reader RF650R ETSI (6GT2811-6AB20-0AA0) (All versions < V4.2), SIMATIC Reader RF650R FCC (6GT2811-6AB20-1AA0) (All versions < V4.2), SIMATIC Reader RF680R ARIB (6GT2811-6AA10-4AA0) (All versions < V4.2), SIMATIC Reader RF680R CMIIT (6GT2811-6AA10-2AA0) (All versions < V4.2), SIMATIC Reader RF680R ETSI (6GT2811-6AA10-0AA0) (All versions < V4.2), SIMATIC Reader RF680R FCC (6GT2811-6AA10-1AA0) (All versions < V4.2), SIMATIC Reader RF685R ARIB (6GT2811-6CA10-4AA0) (All versions < V4.2), SIMATIC Reader RF685R CMIIT (6GT2811-6CA10-2AA0) (All versions < V4.2), SIMATIC Reader RF685R ETSI (6GT2811-6CA10-0AA0) (All versions < V4.2), SIMATIC Reader RF685R FCC (6GT2811-6CA10-1AA0) (All versions < V4.2), SIMATIC RF1140R (6GT2831-6CB00) (All versions < V1.1), SIMATIC RF1170R (6GT2831-6BB00) (All versions < V1.1), SIMATIC RF166C (6GT2002-0EE20) (All versions < V2.2), SIMATIC RF185C (6GT2002-0JE10) (All versions < V2.2), SIMATIC RF186C (6GT2002-0JE20) (All versions < V2.2), SIMATIC RF186CI (6GT2002-0JE50) (All versions < V2.2), SIMATIC RF188C (6GT2002-0JE40) (All versions < V2.2), SIMATIC RF188CI (6GT2002-0JE60) (All versions < V2.2), SIMATIC RF360R (6GT2801-5BA30) (All versions < V2.2). The affected applications contain configuration files which can be modified. An attacker with privilege access can modify these files and enable features that are not released for this device.',
      'Date_Publication' => '2024-09-10',
      'Date_Modification' => '2024-09-18',
      'CVSSv3_Score' => '6.5',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '91.0',
      'cwe_id' => '912.0',
      'cwe_name' => 'Hidden Functionality',
    ),
  ),
  'CVE-2022-21752' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-21752',
      'Description' => 'In WLAN driver, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06493873; Issue ID: ALPS06493873.',
      'Date_Publication' => '2022-06-06',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '192.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2022-26472' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-26472',
      'Description' => 'In ims, there is a possible escalation of privilege due to a parcel format mismatch. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07319095; Issue ID: ALPS07319095.',
      'Date_Publication' => '2022-10-07',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '217.0',
      'cwe_id' => '502.0',
      'cwe_name' => 'Deserialization of Untrusted Data',
    ),
  ),
  'CVE-2022-20014' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-20014',
      'Description' => 'In vow driver, there is a possible memory corruption due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05857308; Issue ID: ALPS05857308.',
      'Date_Publication' => '2022-01-04',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.7',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '84.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2022-20031' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-20031',
      'Description' => 'In fb driver, there is a possible memory corruption due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05850708; Issue ID: ALPS05850708.',
      'Date_Publication' => '2022-02-09',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '120.0',
      'cwe_id' => '416.0',
      'cwe_name' => 'Use After Free',
    ),
  ),
  'CVE-2022-25075' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-25075',
      'Description' => 'TOTOLink A3000RU V5.9c.2280_B20180512 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.',
      'Date_Publication' => '2022-02-24',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '9.8',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '8.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2022-40503' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-40503',
      'Description' => 'Information disclosure due to buffer over-read in Bluetooth Host while A2DP streaming.',
      'Date_Publication' => '2023-04-13',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.2',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '203.0',
      'cwe_id' => '125.0',
      'cwe_name' => 'Out-of-bounds Read',
    ),
  ),
  'CVE-2022-33289' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2022-33289',
      'Description' => 'Memory corruption occurs in Modem due to improper validation of array index when malformed APDU is sent from card.',
      'Date_Publication' => '2023-04-13',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '6.8',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '293.0',
      'cwe_id' => '129.0',
      'cwe_name' => 'Improper Validation of Array Index',
    ),
  ),
  'CVE-2024-33042' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-33042',
      'Description' => 'Memory corruption when Alternative Frequency offset value is set to 255.',
      'Date_Publication' => '2024-09-02',
      'Date_Modification' => '2024-09-04',
      'CVSSv3_Score' => '7.8',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '132.0',
      'cwe_id' => '787.0',
      'cwe_name' => 'Out-of-bounds Write',
    ),
  ),
  'CVE-2024-23373' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-23373',
      'Description' => 'Memory corruption when IOMMU unmap operation fails, the DMA and anon buffers are getting released.',
      'Date_Publication' => '2024-07-01',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '8.4',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '167.0',
      'cwe_id' => '416.0',
      'cwe_name' => 'Use After Free',
    ),
  ),
  'CVE-2024-47406' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-47406',
      'Description' => 'Sharp and Toshiba Tec MFPs improperly process HTTP authentication requests, resulting in an authentication bypass vulnerability.',
      'Date_Publication' => '2024-10-25',
      'Date_Modification' => '2024-11-05',
      'CVSSv3_Score' => '9.1',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '9.0',
      'cwe_id' => '306.0',
      'cwe_name' => 'Missing Authentication for Critical Function',
    ),
  ),
  'CVE-2024-37994' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-37994',
      'Description' => 'A vulnerability has been identified in SIMATIC Reader RF610R CMIIT (6GT2811-6BC10-2AA0) (All versions < V4.2), SIMATIC Reader RF610R ETSI (6GT2811-6BC10-0AA0) (All versions < V4.2), SIMATIC Reader RF610R FCC (6GT2811-6BC10-1AA0) (All versions < V4.2), SIMATIC Reader RF615R CMIIT (6GT2811-6CC10-2AA0) (All versions < V4.2), SIMATIC Reader RF615R ETSI (6GT2811-6CC10-0AA0) (All versions < V4.2), SIMATIC Reader RF615R FCC (6GT2811-6CC10-1AA0) (All versions < V4.2), SIMATIC Reader RF650R ARIB (6GT2811-6AB20-4AA0) (All versions < V4.2), SIMATIC Reader RF650R CMIIT (6GT2811-6AB20-2AA0) (All versions < V4.2), SIMATIC Reader RF650R ETSI (6GT2811-6AB20-0AA0) (All versions < V4.2), SIMATIC Reader RF650R FCC (6GT2811-6AB20-1AA0) (All versions < V4.2), SIMATIC Reader RF680R ARIB (6GT2811-6AA10-4AA0) (All versions < V4.2), SIMATIC Reader RF680R CMIIT (6GT2811-6AA10-2AA0) (All versions < V4.2), SIMATIC Reader RF680R ETSI (6GT2811-6AA10-0AA0) (All versions < V4.2), SIMATIC Reader RF680R FCC (6GT2811-6AA10-1AA0) (All versions < V4.2), SIMATIC Reader RF685R ARIB (6GT2811-6CA10-4AA0) (All versions < V4.2), SIMATIC Reader RF685R CMIIT (6GT2811-6CA10-2AA0) (All versions < V4.2), SIMATIC Reader RF685R ETSI (6GT2811-6CA10-0AA0) (All versions < V4.2), SIMATIC Reader RF685R FCC (6GT2811-6CA10-1AA0) (All versions < V4.2), SIMATIC RF1140R (6GT2831-6CB00) (All versions < V1.1), SIMATIC RF1170R (6GT2831-6BB00) (All versions < V1.1), SIMATIC RF166C (6GT2002-0EE20) (All versions < V2.2), SIMATIC RF185C (6GT2002-0JE10) (All versions < V2.2), SIMATIC RF186C (6GT2002-0JE20) (All versions < V2.2), SIMATIC RF186CI (6GT2002-0JE50) (All versions < V2.2), SIMATIC RF188C (6GT2002-0JE40) (All versions < V2.2), SIMATIC RF188CI (6GT2002-0JE60) (All versions < V2.2), SIMATIC RF360R (6GT2801-5BA30) (All versions < V2.2). The affected application contains a hidden configuration item to enable debug functionality. This could allow an attacker to gain insight into the internal configuration of the deployment.',
      'Date_Publication' => '2024-09-10',
      'Date_Modification' => '2024-09-18',
      'CVSSv3_Score' => '4.3',
      'Severity' => 'MEDIUM',
      'Temps_de_correction' => '91.0',
      'cwe_id' => '912.0',
      'cwe_name' => 'Hidden Functionality',
    ),
  ),
  'CVE-2024-0295' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0295',
      'Description' => 'A vulnerability, which was classified as critical, was found in Totolink LR1200GB 9.1.0u.6619_B20230130. This affects the function setWanCfg of the file /cgi-bin/cstecgi.cgi. The manipulation of the argument hostName leads to os command injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-249861 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2024-01-08',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.3',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2024-0299' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-0299',
      'Description' => 'A vulnerability was found in Totolink N200RE 9.3.5u.6139_B20201216. It has been declared as critical. Affected by this vulnerability is the function setTracerouteCfg of the file /cgi-bin/cstecgi.cgi. The manipulation of the argument command leads to os command injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-249865 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.',
      'Date_Publication' => '2024-01-08',
      'Date_Modification' => '2024-11-21',
      'CVSSv3_Score' => '7.3',
      'Severity' => 'HIGH',
      'Temps_de_correction' => '1.0',
      'cwe_id' => '78.0',
      'cwe_name' => 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')',
    ),
  ),
  'CVE-2024-48839' => 
  array (
    0 => 
    array (
      'CVE_ID' => 'CVE-2024-48839',
      'Description' => 'Improper Input Validation vulnerability allows Remote Code Execution. 
Affected products:


ABB ASPECT - Enterprise v3.08.02; 
NEXUS Series v3.08.02; 
MATRIX Series v3.08.02',
      'Date_Publication' => '2024-12-05',
      'Date_Modification' => '2025-02-18',
      'CVSSv3_Score' => '10.0',
      'Severity' => 'CRITICAL',
      'Temps_de_correction' => '57.0',
      'cwe_id' => '94.0',
      'cwe_name' => 'Improper Control of Generation of Code (\'Code Injection\')',
    ),
  ),
); ?>