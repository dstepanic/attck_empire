import sys
import os
import argparse
import csv
import time
import gen_layer
import fnmatch

# Find agent.log files
def files_within(directory_path, pattern="agent.log"):
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for file_name in fnmatch.filter(filenames, pattern):
            yield os.path.join(dirpath, file_name)

def main():
    techniques = {
    "powershell/code_ ecution/invoke_dllinjection":  ["T1055"],
    "powershell/code_execution/invoke_metasploitpayload":  ["T1064"],
    "powershell/code_execution/invoke_reflectivepeinjection":  ["T1055"],
    "powershell/code_execution/invoke_shellcode":  ["T1055"],
    "powershell/code_execution/invoke_shellcodemsil":  ["T1055"],
    "powershell/collection/ChromeDump":  ["T1003"],
    "powershell/collection/FoxDump":  ["T1003"],
    "powershell/collection/USBKeylogger":  ["T1056"],
    "powershell/collection/WebcamRecorder":  ["T1125"],
    "powershell/collection/browser_data":  ["T1217"],
    "powershell/collection/clipboard_monitor":  ["T1115"],
    "powershell/collection/file_finder":  ["T1083"],
    "powershell/collection/find_interesting_file":  ["T1083"],
    "powershell/collection/get_indexed_item":  ["T1083"],
    "powershell/collection/get_sql_column_sample_data":  ["T1005"],
    "powershell/collection/get_sql_query":  ["T1005"],
    "powershell/collection/inveigh":  ["T1171"],
    "powershell/collection/keylogger":  ["T1056"],
    "powershell/collection/minidump":  ["T1005"],
    "powershell/collection/netripper":  ["T1179"],
    "powershell/collection/ninjacopy":  ["T1003"],
    "powershell/collection/packet_capture":  ["T1040"],
    "powershell/collection/prompt":  ["T1141"],
    "powershell/collection/screenshot":  ["T1113"],
    "powershell/collection/vaults/add_keepass_config_trigger":  ["T1003"],
    "powershell/collection/vaults/find_keepass_config":  ["T1003"],
    "powershell/collection/vaults/get_keepass_config_trigger":  ["T1003"],
    "powershell/collection/vaults/keethief":  ["T1003"],
    "powershell/collection/vaults/remove_keepass_config_trigger":  ["T1003"],
    "powershell/credentials/credential_injection":  ["T1055"],
    "powershell/credentials/enum_cred_store":  ["T1003"],
    "powershell/credentials/invoke_kerberoast":  ["T1208"],
    "powershell/credentials/mimikatz/cache":  ["T1003"],
    "powershell/credentials/mimikatz/certs":  ["T1145"],
    "powershell/credentials/mimikatz/command":  ["T1003"],
    "powershell/credentials/mimikatz/dcsync":  ["T1003"],
    "powershell/credentials/mimikatz/dcsync_hashdump":  ["T1003"],
    "powershell/credentials/mimikatz/extract_tickets":  ["T1003"],
    "powershell/credentials/mimikatz/golden_ticket":  ["T1003","T1097"],
    "powershell/credentials/mimikatz/logonpasswords":  ["T1003"],
    "powershell/credentials/mimikatz/lsadump":  ["T1003"],
    "powershell/credentials/mimikatz/mimitokens":  ["T1003"],
    "powershell/credentials/mimikatz/pth":  ["T1075"],
    "powershell/credentials/mimikatz/purge":  ["T1070"],
    "powershell/credentials/mimikatz/sam":  ["T1003"],
    "powershell/credentials/mimikatz/silver_ticket":  ["T1003","T1097"],
    "powershell/credentials/mimikatz/trust_keys":  ["T1003"],
    "powershell/credentials/powerdump":  ["T1003"],
    "powershell/credentials/sessiongopher":  ["T1005","T1145"],
    "powershell/credentials/tokens":  ["T1134"],
    "powershell/credentials/vault_credential":  ["T1003"],
    "powershell/exfiltration/egresscheck":  ["T1020"],
    "powershell/exploitation/exploit_jboss":  ["T1210","T1190"],
    "powershell/exploitation/exploit_jenkins":  ["T1210","T1190"],
    "powershell/lateral_movement/inveigh_relay":  ["T1171"],
    "powershell/lateral_movement/invoke_dcom":  ["T1175"],
    "powershell/lateral_movement/invoke_executemsbuild":  ["T1127"],
    "powershell/lateral_movement/invoke_psexec":  ["T1035","T1077"],
    "powershell/lateral_movement/invoke_psremoting":  ["T1086"],
    "powershell/lateral_movement/invoke_sqloscmd":  ["T1059"],
    "powershell/lateral_movement/invoke_sshcommand":  ["T1043"],
    "powershell/lateral_movement/invoke_wmi":  ["T1047"],
    "powershell/lateral_movement/invoke_wmi_debugger":  ["T1015"],
    "powershell/lateral_movement/jenkins_script_console":  ["T1190"],
    "powershell/lateral_movement/new_gpo_immediate_task":  ["T1053"],
    "powershell/management/disable_rdp":  ["T1089"],
    "powershell/management/downgrade_account":  ["T1003"],
    "powershell/management/enable_multi_rdp":  ["T1076","T1043"],
    "powershell/management/enable_rdp":  ["T1076"],
    "powershell/management/get_domain_sid":  ["T1087"],
    "powershell/management/honeyhash":  ["T1098"],
    "powershell/management/invoke_script":  ["T1064"],
    "powershell/management/lock":  ["T1070"],
    "powershell/management/logoff":  ["T1070"],
    "powershell/management/mailraider/disable_security":  ["T1114"],
    "powershell/management/mailraider/get_emailitems":  ["T1114"],
    "powershell/management/mailraider/get_subfolders":  ["T1114"],
    "powershell/management/mailraider/mail_search":  ["T1114"],
    "powershell/management/mailraider/search_gal":  ["T1114"],
    "powershell/management/mailraider/send_mail":  ["T1114"],
    "powershell/management/mailraider/view_email":  ["T1114"],
    "powershell/management/psinject":  ["T1055"],
    "powershell/management/restart":  ["T1070"],
    "powershell/management/runas":  ["T1134"],
    "powershell/management/sid_to_user":  ["T1087"],
    "powershell/management/spawn":  ["T1086"],
    "powershell/management/spawnas":  ["T1059"],
    "powershell/management/switch_listener":  ["T1008"],
    "powershell/management/timestomp":  ["T1099"],
    "powershell/management/user_to_sid":  ["T1087"],
    "powershell/management/vnc":  ["T1219"],
    "powershell/management/wdigest_downgrade":  ["T1003"],
    "powershell/management/zipfolder":  ["T1002"],
    "powershell/persistence/elevated/registry":  ["T1060"],
    "powershell/persistence/elevated/schtasks":  ["T1053"],
    "powershell/persistence/elevated/wmi":  ["T1047"],
    "powershell/persistence/misc/add_netuser":  ["T1136"],
    "powershell/persistence/misc/add_sid_history":  ["T1178"],
    "powershell/persistence/misc/debugger":  ["T1015"],
    "powershell/persistence/misc/disable_machine_acct_change":  ["T1112"],
    "powershell/persistence/misc/get_ssps":  ["T1101"],
    "powershell/persistence/misc/install_ssp":  ["T1101"],
    "powershell/persistence/misc/memssp":  ["T1101"],
    "powershell/persistence/misc/skeleton_key":  ["T1108"],
    "powershell/persistence/powerbreach/deaduser":  ["T1108"],
    "powershell/persistence/powerbreach/eventlog":  ["T1108"],
    "powershell/persistence/powerbreach/resolver":  ["T1108"],
    "powershell/persistence/userland/backdoor_lnk":  ["T1023"],
    "powershell/persistence/userland/registry":  ["T1060"],
    "powershell/persistence/userland/schtasks":  ["T1053"],
    "powershell/privesc/ask":  ["T1088"],
    "powershell/privesc/bypassuac":  ["T1088"],
    "powershell/privesc/bypassuac_eventvwr":  ["T1088"],
    "powershell/privesc/bypassuac_wscript":  ["T1088"],
    "powershell/privesc/getsystem":  ["T1134"],
    "powershell/privesc/gpp":  ["T1003"],
    "powershell/privesc/mcafee_sitelist":  ["T1003"],
    "powershell/privesc/ms16-032":  ["T1068"],
    "powershell/privesc/powerup/allchecks":  ["T1034","T1044"],
    "powershell/privesc/powerup/find_dllhijack":  ["T1038"],
    "powershell/privesc/powerup/service_exe_restore":  ["T1050"],
    "powershell/privesc/powerup/service_exe_stager":  ["T1050"],
    "powershell/privesc/powerup/service_exe_useradd":  ["T1050"],
    "powershell/privesc/powerup/service_stager":  ["T1050"],
    "powershell/privesc/powerup/service_useradd":  ["T1136"],
    "powershell/privesc/powerup/write_dllhijacker":  ["T1038"],
    "powershell/privesc/tater":  ["T1068"],
    "powershell/recon/find_fruit":  ["T1046"],
    "powershell/recon/get_sql_server_login_default_pw":  ["T1110"],
    "powershell/recon/http_login":  ["T1110"],
    "powershell/situational_awareness/host/antivirusproduct":  ["T1063"],
    "powershell/situational_awareness/host/computerdetails":  ["T1082","T1005"],
    "powershell/situational_awareness/host/dnsserver":  ["T1016"],
    "powershell/situational_awareness/host/findtrusteddocuments":  ["T1213"],
    "powershell/situational_awareness/host/get_pathacl":  ["T1069"],
    "powershell/situational_awareness/host/get_proxy":  ["T1016"],
    "powershell/situational_awareness/host/monitortcpconnections":  ["T1049"],
    "powershell/situational_awareness/host/paranoia":  ["T1057"],
    "powershell/situational_awareness/host/winenum":  ["T1082"],
    "powershell/situational_awareness/network/arpscan":  ["T1016"],
    "powershell/situational_awareness/network/bloodhound":  ["T1033"],
    "powershell/situational_awareness/network/get_exploitable_system":  ["T1210"],
    "powershell/situational_awareness/network/get_spn":  ["T1087"],
    "powershell/situational_awareness/network/get_sql_instance_domain":  ["T1046"],
    "powershell/situational_awareness/network/get_sql_server_info":  ["T1046"],
    "powershell/situational_awareness/network/portscan":  ["T1046"],
    "powershell/situational_awareness/network/powerview/find_foreign_group":  ["T1087"],
    "powershell/situational_awareness/network/powerview/find_foreign_user":  ["T1087"],
    "powershell/situational_awareness/network/powerview/find_gpo_computer_admin":  ["T1087"],
    "powershell/situational_awareness/network/powerview/find_gpo_location":  ["T1087"],
    "powershell/situational_awareness/network/powerview/find_localadmin_access":  ["T1087"],
    "powershell/situational_awareness/network/powerview/find_managed_security_group":  ["T1087"],
    "powershell/situational_awareness/network/powerview/get_cached_rdpconnection":  ["T1012"],
    "powershell/situational_awareness/network/powerview/get_computer":  ["T1082"],
    "powershell/situational_awareness/network/powerview/get_dfs_share":  ["T1135"],
    "powershell/situational_awareness/network/powerview/get_domain_controller":  ["T1018"],
    "powershell/situational_awareness/network/powerview/get_domain_policy":  ["T1018"],
    "powershell/situational_awareness/network/powerview/get_domain_trust":  ["T1018"],
    "powershell/situational_awareness/network/powerview/get_fileserver":  ["T1083","T1135"],
    "powershell/situational_awareness/network/powerview/get_forest":  ["T1018"],
    "powershell/situational_awareness/network/powerview/get_forest_domain":  ["T1018"],
    "powershell/situational_awareness/network/powerview/get_gpo":  ["T1201"],
    "powershell/situational_awareness/network/powerview/get_gpo_computer":  ["T1087"],
    "powershell/situational_awareness/network/powerview/get_group":  ["T1087"],
    "powershell/situational_awareness/network/powerview/get_group_member":  ["T1087"],
    "powershell/situational_awareness/network/powerview/get_localgroup":  ["T1087"],
    "powershell/situational_awareness/network/powerview/get_loggedon":  ["T1087","T1033"],
    "powershell/situational_awareness/network/powerview/get_object_acl":  ["T1069"],
    "powershell/situational_awareness/network/powerview/get_ou":  ["T1087"],
    "powershell/situational_awareness/network/powerview/get_rdp_session":  ["T1049"],
    "powershell/situational_awareness/network/powerview/get_session":  ["T1033"],
    "powershell/situational_awareness/network/powerview/get_site":  ["T1018"],
    "powershell/situational_awareness/network/powerview/get_subnet":  ["T1016"],
    "powershell/situational_awareness/network/powerview/get_user":  ["T1087"],
    "powershell/situational_awareness/network/powerview/map_domain_trust":  ["T1069"],
    "powershell/situational_awareness/network/powerview/process_hunter":  ["T1057"],
    "powershell/situational_awareness/network/powerview/set_ad_object":  ["T1098"],
    "powershell/situational_awareness/network/powerview/share_finder":  ["T1135"],
    "powershell/situational_awareness/network/powerview/user_hunter":  ["T1087"],
    "powershell/situational_awareness/network/reverse_dns":  ["T1018"],
    "powershell/situational_awareness/network/smbautobrute":  ["T1110"],
    "powershell/situational_awareness/network/smbscanner":  ["T1110"],
    "powershell/code_execution/invoke_ntsd":  ["T1127"],
    "powershell/credentials/mimikatz/keys":  ["T1145"],
    "powershell/exfiltration/exfil_dropbox":  ["T1048","T1071"],
    "powershell/exploitation/exploit_eternalblue":  ["T1210","T1212"],
    "powershell/lateral_movement/invoke_smbexec":  ["T1187"],
    "powershell/management/reflective_inject":  ["T1055"],
    "powershell/management/shinject":  ["T1055"],
    "powershell/persistence/elevated/wmi_updater":  ["T1084"],
    "powershell/privesc/bypassuac_env":  ["T1088"],
    "powershell/privesc/bypassuac_fodhelper":  ["T1088"],
    "powershell/privesc/bypassuac_sdctlbypass":  ["T1088"],
    "powershell/privesc/bypassuac_tokenmanipulation":  ["T1088"],
    "powershell/privesc/ms16-135":  ["T1068"],
    "powershell/situational_awareness/host/get_uaclevel":  ["T1069"],
    "exfiltration/Invoke_ExfilDataToGitHub":  ["T1048"],
    "external/generate_agent":  ["T1008"],
    "python/collection/linux/hashdump":  ["T1003"],
    "python/collection/linux/keylogger":  ["T1056"],
    "python/collection/linux/mimipenguin":  ["T1003"],
    "python/collection/linux/pillage_user":  ["T1139","T1212"],
    "python/collection/linux/sniffer":  ["T1040"],
    "python/collection/linux/xkeylogger":  ["T1056"],
    "python/collection/osx/browser_dump":  ["T1005"],
    "python/collection/osx/clipboard":  ["T1115"],
    "python/collection/osx/hashdump":  ["T1003"],
    "python/collection/osx/imessage_dump":  ["T1005"],
    "python/collection/osx/kerberosdump":  ["T1003"],
    "python/collection/osx/keychaindump":  ["T1142"],
    "python/collection/osx/keychaindump_chainbreaker":  ["T1142"],
    "python/collection/osx/keychaindump_decrypt":  ["T1142"],
    "python/collection/osx/keylogger":  ["T1056"],
    "python/collection/osx/native_screenshot":  ["T1113"],
    "python/collection/osx/native_screenshot_mss":  ["T1113"],
    "python/collection/osx/osx_mic_record":  ["T1123"],
    "python/collection/osx/pillage_user":  ["T1139","T1033"],
    "python/collection/osx/prompt":  ["T1141"],
    "python/collection/osx/screensaver_alleyoop":  ["T1141"],
    "python/collection/osx/screenshot":  ["T1113"],
    "python/collection/osx/search_email":  ["T1114"],
    "python/collection/osx/sniffer":  ["T1040"],
    "python/collection/osx/webcam":  ["T1125"],
    "python/exploit/web/jboss_jmx":  ["T1190"],
    "python/lateral_movement/multi/ssh_command":  ["T1021"],
    "python/lateral_movement/multi/ssh_launcher":  ["T1021"],
    "python/management/multi/kerberos_inject":  ["T1003"],
    "python/management/multi/socks":  ["T1090"],
    "python/management/multi/spawn":  ["T1086"],
    "python/management/osx/screen_sharing":  ["T1219","T1021"],
    "python/management/osx/shellcodeinject64":  ["T1055"],
    "python/persistence/multi/crontab":  ["T1168"],
    "python/persistence/multi/desktopfile":  ["T1037"],
    "python/persistence/osx/CreateHijacker":  ["T1157"],
    "python/persistence/osx/RemoveDaemon":  ["T1070"],
    "python/persistence/osx/launchdaemonexecutable":  ["T1160"],
    "python/persistence/osx/loginhook":  ["T1037"],
    "python/persistence/osx/mail":  ["T1155","T1108"],
    "python/situational_awareness/host/multi/SuidGuidSearch":  ["T1044"],
    "python/situational_awareness/host/multi/WorldWriteableFileSearch":  ["T1044"],
    "python/situational_awareness/host/osx/HijackScanner":  ["T1157"],
    "python/situational_awareness/host/osx/situational_awareness":  ["T1005","T1082"],
    "python/situational_awareness/network/active_directory/dscl_get_groupmembers":  ["T1087"],
    "python/situational_awareness/network/active_directory/dscl_get_groups":  ["T1087"],
    "python/situational_awareness/network/active_directory/dscl_get_users":  ["T1087"],
    "python/situational_awareness/network/active_directory/get_computers":  ["T1018"],
    "python/situational_awareness/network/active_directory/get_domaincontrollers":  ["T1018"],
    "python/situational_awareness/network/active_directory/get_fileservers":  ["T1135"],
    "python/situational_awareness/network/active_directory/get_groupmembers":  ["T1087"],
    "python/situational_awareness/network/active_directory/get_groupmemberships":  ["T1087"],
    "python/situational_awareness/network/active_directory/get_groups":  ["T1087"],
    "python/situational_awareness/network/active_directory/get_ous":  ["T1087"],
    "python/situational_awareness/network/active_directory/get_userinformation":  ["T1087"],
    "python/situational_awareness/network/active_directory/get_users":  ["T1087"],
    "python/situational_awareness/network/dcos/chronos_api_add_job":  ["T1106","T1168"],
    "python/situational_awareness/network/dcos/chronos_api_delete_job":  ["T1106","T1168"],
    "python/situational_awareness/network/dcos/chronos_api_start_job":  ["T1106","T1168"],
    "python/situational_awareness/network/dcos/etcd_crawler":  ["T1003"],
    "python/situational_awareness/network/dcos/marathon_api_create_start_app":  ["T1106"],
    "python/situational_awareness/network/dcos/marathon_api_delete_app":  ["T1106"],
    "python/situational_awareness/network/find_fruit":  ["T1046"],
    "python/situational_awareness/network/gethostbyname":  ["T1018"],
    "python/situational_awareness/network/http_rest_api":  ["T1106"],
    "python/situational_awareness/network/port_scan":  ["T1046"],
    "python/situational_awareness/network/smb_mount":  ["T1135"],
    }

    csvData = [['TechID', 'Software', 'Groups', 'References']]

    with open('attack.csv', 'wb') as csvFile:
        writer = csv.writer(csvFile)
        writer.writerows(csvData)

        parser = argparse.ArgumentParser()
        requiredNamed = parser.add_argument_group('required named arguments')
        requiredNamed.add_argument("-a", "--Agent", action="store", dest="input_agent_file",
                        required=False, help="Use argument (-a) to point to PowerShell Empire Agent.log file "
                                             "or leave off argument and script will search current directory "
                                             "and sub-directories")


        args = parser.parse_args()

        # Set flag to prevent error if no agent.log files found
        isGeneratorEmpty = True

        #Search for agent.log files based on current file path
        file_path = ""
        for file_path in files_within("."):
            isGeneratorEmpty = False
            if args.input_agent_file is not None and file_path is not None:
                print "Processing Empire Agent log file: " + args.input_agent_file

                #Go through agent.log file then map ATT&CK techniques used by any PowerShell Empire modules
                with open(args.input_agent_file, 'rb') as file:
                    for line in file:
                        for module, technique in techniques.items():
                            for id in technique:
                                if module in line:
                                    writer = csv.writer(csvFile)
                                    writer.writerow([id, '0', '0', '0'])
                time.sleep(10)

            else:
                print "Processing Empire Agent log file: " + file_path

                #Go through each agent.log file then map ATT&CK techniques used by any PowerShell Empire modules
                with open(file_path, 'rb') as file:
                    for line in file:
                        for module, technique in techniques.items():
                            for id in technique:
                                if module in line:
                                    writer = csv.writer(csvFile)
                                    writer.writerow([id, '0', '0', '0'])
                # csvFile.close()
                time.sleep(10)

        if args.input_agent_file is None and file_path is "":
                print "\nNo Empire agent.log file was referenced or found in current directory/sub-directories"
                exit()

if __name__ == '__main__':
    main()
    gen_layer.generate()
