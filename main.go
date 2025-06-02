package main

import (
	"fmt"

	"github.com/TheManticoreProject/Delegations/core/mode_add"
	"github.com/TheManticoreProject/Delegations/core/mode_audit"
	"github.com/TheManticoreProject/Delegations/core/mode_clear"
	"github.com/TheManticoreProject/Delegations/core/mode_find"
	"github.com/TheManticoreProject/Delegations/core/mode_monitor"
	"github.com/TheManticoreProject/Delegations/core/mode_remove"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
)

var (
	mode           string
	delegationType string

	// Configuration
	debug bool

	// Delegations
	withProtocolTransition                bool
	removeProtocolTransition              bool
	distinguishedName                     string
	allowedToDelegateTo                   []string
	allowedToActOnBehalfOfAnotherIdentity []string

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// LDAP Connection Settings
	domainController string
	ldapPort         int
	useLdaps         bool
	useKerberos      bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Delegations - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0",
	}
	ap.SetupSubParsing("mode", &mode, true)
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	// add mode ============================================================================================================
	subparser_add := ap.AddSubParser("add", "Add a constrained, unconstrained, or resource-based constrained delegation to a computer, user or group.")
	subparser_add.SetupSubParsing("delegationType", &delegationType, true)

	// subparser for add constrained delegation ========================================================================================
	subparser_add_constrained := subparser_add.AddSubParser("constrained", "Add a constrained delegation to a computer, user or group.")
	subparser_add_constrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_add_constrained_group_config, err := subparser_add_constrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_constrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_add_constrained_group_config.NewBoolArgument(&withProtocolTransition, "-w", "--with-protocol-transition", false, "Enable protocol transition on this object on this object.")
		subparser_add_constrained_group_config.NewBoolArgument(&removeProtocolTransition, "-r", "--remove-protocol-transition", false, "Disable protocol transition on this object.")
		subparser_add_constrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to add the delegation to.")
		subparser_add_constrained_group_config.NewListOfStringsArgument(&allowedToDelegateTo, "-a", "--allowed-to-delegate-to", []string{}, true, "User or group to delegate to.")
	}
	// LDAP Connection Settings
	subparser_add_constrained_group_ldapSettings, err := subparser_add_constrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_constrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_add_constrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_add_constrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_add_constrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_add_constrained_group_auth, err := subparser_add_constrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_constrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_add_constrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_add_constrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_add_constrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// subparser for add ressource_based delegation ========================================================================================
	subparser_add_ressource_based := subparser_add.AddSubParser("rbcd", "Add a ressource-based delegation to a computer, user or group.")
	subparser_add_ressource_based.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_add_ressource_based_group_config, err := subparser_add_ressource_based.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_ressource_based_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_add_ressource_based_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to add the delegation to.")
		subparser_add_ressource_based_group_config.NewListOfStringsArgument(&allowedToActOnBehalfOfAnotherIdentity, "-a", "--allowed-to-act-on-behalf-of-another-identity", []string{}, true, "User or group to act on behalf of.")
	}
	// LDAP Connection Settings
	subparser_add_ressource_based_group_ldapSettings, err := subparser_add_ressource_based.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_ressource_based_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_add_ressource_based_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_add_ressource_based_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_add_ressource_based_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_add_ressource_based_group_auth, err := subparser_add_ressource_based.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_ressource_based_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_add_ressource_based_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_add_ressource_based_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_add_ressource_based_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// subparser for add unconstrained delegation ========================================================================================
	subparser_add_unconstrained := subparser_add.AddSubParser("unconstrained", "Add a unconstrained delegation to a computer, user or group.")
	subparser_add_unconstrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_add_unconstrained_group_config, err := subparser_add_unconstrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_unconstrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_add_unconstrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to add the delegation to.")
	}
	// LDAP Connection Settings
	subparser_add_unconstrained_group_ldapSettings, err := subparser_add_unconstrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_unconstrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_add_unconstrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_add_unconstrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_add_unconstrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_add_unconstrained_group_auth, err := subparser_add_unconstrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_unconstrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_add_unconstrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_add_unconstrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_add_unconstrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// audit mode ============================================================================================================
	subparser_audit := ap.AddSubParser("audit", "Audit constrained, unconstrained, and resource-based constrained delegations in Active Directory.")
	// Configuration flags
	subparser_audit_group_config, err := subparser_audit.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_audit_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_audit_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", false, "Distinguished name of the computer, user or group to audit for delegations.")
	}
	// LDAP Connection Settings
	subparser_audit_group_ldapSettings, err := subparser_audit.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_audit_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_audit_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_audit_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_audit_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_audit_group_auth, err := subparser_audit.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_audit_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_audit_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_audit_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_audit_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// clear mode ============================================================================================================
	subparser_clear := ap.AddSubParser("clear", "Clear a constrained, unconstrained, or resource-based constrained delegation from a computer, user or group.")
	subparser_clear.SetupSubParsing("delegationType", &delegationType, true)

	// subparser for clear constrained delegation ========================================================================================
	subparser_clear_constrained := subparser_clear.AddSubParser("constrained", "Clear a constrained delegation to a computer, user or group.")
	subparser_clear_constrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_clear_constrained_group_config, err := subparser_clear_constrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_constrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_clear_constrained_group_config.NewBoolArgument(&withProtocolTransition, "-w", "--with-protocol-transition", false, "Clear protocol transition on this object on this object.")
		subparser_clear_constrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to clear for delegations on.")
	}
	// LDAP Connection Settings
	subparser_clear_constrained_group_ldapSettings, err := subparser_clear_constrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_constrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_clear_constrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_clear_constrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_clear_constrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_clear_constrained_group_auth, err := subparser_clear_constrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_constrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_clear_constrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_clear_constrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_clear_constrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// subparser for clear ressource_based delegation ========================================================================================
	subparser_clear_ressource_based := subparser_clear.AddSubParser("rbcd", "Clear a ressource-based delegation to a computer, user or group.")
	subparser_clear_ressource_based.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_clear_ressource_based_group_config, err := subparser_clear_ressource_based.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_ressource_based_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_clear_ressource_based_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to clear delegations on.")
	}
	// LDAP Connection Settings
	subparser_clear_ressource_based_group_ldapSettings, err := subparser_clear_ressource_based.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_ressource_based_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_clear_ressource_based_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_clear_ressource_based_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_clear_ressource_based_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_clear_ressource_based_group_auth, err := subparser_clear_ressource_based.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_ressource_based_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_clear_ressource_based_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_clear_ressource_based_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_clear_ressource_based_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// subparser for clear unconstrained delegation ========================================================================================
	subparser_clear_unconstrained := subparser_clear.AddSubParser("unconstrained", "Clear a unconstrained delegation to a computer, user or group.")
	subparser_clear_unconstrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_clear_unconstrained_group_config, err := subparser_clear_unconstrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_unconstrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_clear_unconstrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to clear the delegations on.")
	}
	// LDAP Connection Settings
	subparser_clear_unconstrained_group_ldapSettings, err := subparser_clear_unconstrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_unconstrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_clear_unconstrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_clear_unconstrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_clear_unconstrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_clear_unconstrained_group_auth, err := subparser_clear_unconstrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_clear_unconstrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_clear_unconstrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_clear_unconstrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_clear_unconstrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// find mode ============================================================================================================
	subparser_find := ap.AddSubParser("find", "Find a constrained, unconstrained, or resource-based constrained delegation from a computer, user or group.")
	subparser_find.SetupSubParsing("delegationType", &delegationType, true)

	// subparser for find constrained delegation ========================================================================================
	subparser_find_constrained := subparser_find.AddSubParser("constrained", "Find a constrained delegation to a computer, user or group.")
	subparser_find_constrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_find_constrained_group_config, err := subparser_find_constrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_constrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_find_constrained_group_config.NewBoolArgument(&withProtocolTransition, "-w", "--with-protocol-transition", false, "Enable protocol transition on this object on this object.")
		subparser_find_constrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to search for delegations.")
	}
	// LDAP Connection Settings
	subparser_find_constrained_group_ldapSettings, err := subparser_find_constrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_constrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_find_constrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_find_constrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_find_constrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_find_constrained_group_auth, err := subparser_find_constrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_constrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_find_constrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_find_constrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_find_constrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// Add subparser for add protocol transition ========================================================================================
	subparser_add_protocoltransition := subparser_add.AddSubParser("protocoltransition", "Add a protocol transition to a computer, user or group.")
	subparser_add_protocoltransition.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_add_protocoltransition_group_config, err := subparser_add_protocoltransition.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_protocoltransition_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_add_protocoltransition_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to add the protocol transition to.")
	}
	// LDAP Connection Settings
	subparser_add_protocoltransition_group_ldapSettings, err := subparser_add_protocoltransition.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_protocoltransition_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_add_protocoltransition_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_add_protocoltransition_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_add_protocoltransition_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_add_protocoltransition_group_auth, err := subparser_add_protocoltransition.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_add_protocoltransition_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_add_protocoltransition_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_add_protocoltransition_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_add_protocoltransition_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// Find subparser for find ressource_based delegation ========================================================================================
	subparser_find_ressource_based := subparser_find.AddSubParser("rbcd", "Find a ressource-based delegation to a computer, user or group.")
	subparser_find_ressource_based.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_find_ressource_based_group_config, err := subparser_find_ressource_based.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_ressource_based_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_find_ressource_based_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to add the delegation to.")
	}
	// LDAP Connection Settings
	subparser_find_ressource_based_group_ldapSettings, err := subparser_find_ressource_based.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_ressource_based_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_find_ressource_based_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_find_ressource_based_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_find_ressource_based_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_find_ressource_based_group_auth, err := subparser_find_ressource_based.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_ressource_based_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_find_ressource_based_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_find_ressource_based_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_find_ressource_based_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// Find subparser for find unconstrained delegation ========================================================================================
	subparser_find_unconstrained := subparser_find.AddSubParser("unconstrained", "Find a unconstrained delegation to a computer, user or group.")
	subparser_find_unconstrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_find_unconstrained_group_config, err := subparser_find_unconstrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_unconstrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_find_unconstrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to search for delegations.")

	}
	// LDAP Connection Settings
	subparser_find_unconstrained_group_ldapSettings, err := subparser_find_unconstrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_unconstrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_find_unconstrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_find_unconstrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_find_unconstrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_find_unconstrained_group_auth, err := subparser_find_unconstrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_unconstrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_find_unconstrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_find_unconstrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_find_unconstrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// monitor mode ============================================================================================================
	subparser_monitor := ap.AddSubParser("monitor", "Monitor constrained, unconstrained, and resource-based constrained delegations in Active Directory.")
	// Configuration flags
	subparser_monitor_group_config, err := subparser_monitor.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_monitor_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
	}
	// LDAP Connection Settings
	subparser_monitor_group_ldapSettings, err := subparser_monitor.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_monitor_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_monitor_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_monitor_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_monitor_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_monitor_group_auth, err := subparser_monitor.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_monitor_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_monitor_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_monitor_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_monitor_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// remove mode ============================================================================================================
	subparser_remove := ap.AddSubParser("remove", "Remove a constrained, unconstrained, or resource-based constrained delegation from a computer, user or group.")
	subparser_remove.SetupSubParsing("delegationType", &delegationType, true)

	// Remove subparser for remove constrained delegation ========================================================================================
	subparser_remove_constrained := subparser_remove.AddSubParser("constrained", "Remove a constrained delegation to a computer, user or group.")
	subparser_remove_constrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_remove_constrained_group_config, err := subparser_remove_constrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_constrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_remove_constrained_group_config.NewBoolArgument(&withProtocolTransition, "-w", "--with-protocol-transition", false, "Enable protocol transition on this object on this object.")
		subparser_remove_constrained_group_config.NewBoolArgument(&removeProtocolTransition, "-r", "--remove-protocol-transition", false, "Disable protocol transition on this object.")
		subparser_remove_constrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove for delegations on.")
		subparser_remove_constrained_group_config.NewListOfStringsArgument(&allowedToDelegateTo, "-a", "--allowed-to-delegate-to", []string{}, true, "User or group to delegate to.")
	}
	// LDAP Connection Settings
	subparser_remove_constrained_group_ldapSettings, err := subparser_remove_constrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_constrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_remove_constrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_remove_constrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_remove_constrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_remove_constrained_group_auth, err := subparser_remove_constrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_constrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_remove_constrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_remove_constrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_remove_constrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// Remove subparser for remove protocol transition ========================================================================================
	subparser_remove_protocoltransition := subparser_remove.AddSubParser("protocoltransition", "Remove a protocol transition to a computer, user or group.")
	subparser_remove_protocoltransition.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_remove_protocoltransition_group_config, err := subparser_remove_protocoltransition.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_protocoltransition_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_remove_protocoltransition_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove the delegations on.")
	}
	// LDAP Connection Settings
	subparser_remove_protocoltransition_group_ldapSettings, err := subparser_remove_protocoltransition.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_protocoltransition_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_remove_protocoltransition_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_remove_protocoltransition_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_remove_protocoltransition_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_remove_protocoltransition_group_auth, err := subparser_remove_protocoltransition.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_protocoltransition_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_remove_protocoltransition_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_remove_protocoltransition_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_remove_protocoltransition_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// Remove subparser for remove ressource_based delegation ========================================================================================
	subparser_remove_ressource_based := subparser_remove.AddSubParser("rbcd", "Remove a ressource-based delegation to a computer, user or group.")
	subparser_remove_ressource_based.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_remove_ressource_based_group_config, err := subparser_remove_ressource_based.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_ressource_based_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_remove_ressource_based_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove delegations on.")
		subparser_remove_ressource_based_group_config.NewListOfStringsArgument(&allowedToActOnBehalfOfAnotherIdentity, "-a", "--allowed-to-act-on-behalf-of-another-identity", []string{}, true, "User or group to act on behalf of.")
	}
	// LDAP Connection Settings
	subparser_remove_ressource_based_group_ldapSettings, err := subparser_remove_ressource_based.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_ressource_based_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_remove_ressource_based_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_remove_ressource_based_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_remove_ressource_based_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_remove_ressource_based_group_auth, err := subparser_remove_ressource_based.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_ressource_based_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_remove_ressource_based_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_remove_ressource_based_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_remove_ressource_based_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// Remove subparser for remove unconstrained delegation ========================================================================================
	subparser_remove_unconstrained := subparser_remove.AddSubParser("unconstrained", "Remove a unconstrained delegation to a computer, user or group.")
	subparser_remove_unconstrained.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_remove_unconstrained_group_config, err := subparser_remove_unconstrained.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_unconstrained_group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		subparser_remove_unconstrained_group_config.NewStringArgument(&distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the user or group to remove the delegations on.")
	}
	// LDAP Connection Settings
	subparser_remove_unconstrained_group_ldapSettings, err := subparser_remove_unconstrained.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_unconstrained_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_remove_unconstrained_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_remove_unconstrained_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_remove_unconstrained_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_remove_unconstrained_group_auth, err := subparser_remove_unconstrained.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_unconstrained_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_remove_unconstrained_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_remove_unconstrained_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_remove_unconstrained_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()
}

func main() {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials: %s", err))
		return
	}

	if mode == "add" {
		if delegationType == "constrained" {
			if withProtocolTransition {
				err = mode_add.AddConstrainedDelegationWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error adding constrained delegation with protocol transition: %s", err))
				}
			} else {
				if removeProtocolTransition {
					err = mode_remove.RemoveProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
					if err != nil {
						logger.Warn(fmt.Sprintf("Error removing protocol transition: %s", err))
					}
				}
				err = mode_add.AddConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error adding constrained delegation: %s", err))
				}
			}
		} else if delegationType == "unconstrained" {
			err = mode_add.AddUnconstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error adding unconstrained delegation: %s", err))
			}
		} else if delegationType == "rbcd" {
			err = mode_add.AddRessourceBasedConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToActOnBehalfOfAnotherIdentity, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error adding ressource-based constrained delegation: %s", err))
			}
		} else if delegationType == "protocoltransition" {
			err = mode_add.AddProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error adding protocol transition: %s", err))
			}
		}

	} else if mode == "audit" {
		err = mode_audit.AuditUnconstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error auditing unconstrained delegations: %s", err))
		}
		err = mode_audit.AuditConstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error auditing constrained delegations: %s", err))
		}
		err = mode_audit.AuditConstrainedDelegationsWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error auditing constrained delegations with protocol transition: %s", err))
		}
		err = mode_audit.AuditRessourceBasedConstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error auditing ressource-based constrained delegations: %s", err))
		}

	} else if mode == "clear" {
		if delegationType == "constrained" {
			if withProtocolTransition {
				err = mode_clear.ClearConstrainedDelegationWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error clearing constrained delegation with protocol transition: %s", err))
				}
			} else {
				err = mode_clear.ClearConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error clearing constrained delegation: %s", err))
				}
			}
		} else if delegationType == "unconstrained" {
			err = mode_clear.ClearUnconstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error clearing unconstrained delegation: %s", err))
			}
		} else if delegationType == "rbcd" {
			err = mode_clear.ClearRessourceBasedConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error clearing ressource-based constrained delegation: %s", err))
			}
		}

	} else if mode == "find" {
		if delegationType == "constrained" {
			if withProtocolTransition {
				err = mode_find.FindConstrainedDelegationsWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error finding constrained delegations with protocol transition: %s", err))
				}
			} else {
				err = mode_find.FindConstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error finding constrained delegations: %s", err))
				}
			}
		} else if delegationType == "unconstrained" {
			err = mode_find.FindUnconstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error finding unconstrained delegations: %s", err))
			}
		} else if delegationType == "rbcd" {
			err = mode_find.FindRessourceBasedConstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error finding ressource-based constrained delegations: %s", err))
			}
		}

	} else if mode == "remove" {
		if delegationType == "constrained" {
			if withProtocolTransition {
				err = mode_remove.RemoveConstrainedDelegationWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error removing constrained delegation with protocol transition: %s", err))
				}
			} else {
				if removeProtocolTransition {
					err = mode_remove.RemoveProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
					if err != nil {
						logger.Warn(fmt.Sprintf("Error removing protocol transition: %s", err))
					}
				}
				err = mode_remove.RemoveConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToDelegateTo, debug)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error removing constrained delegation: %s", err))
				}
			}
		} else if delegationType == "unconstrained" {
			err = mode_remove.RemoveUnconstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error removing unconstrained delegation: %s", err))
			}
		} else if delegationType == "rbcd" {
			err = mode_remove.RemoveRessourceBasedConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, allowedToActOnBehalfOfAnotherIdentity, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error removing ressource-based constrained delegation: %s", err))
			}
		} else if delegationType == "protocoltransition" {
			err = mode_remove.RemoveProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, debug)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error removing protocol transition: %s", err))
			}
		}

	} else if mode == "monitor" {
		err = mode_monitor.MonitorDelegations(domainController, ldapPort, creds, useLdaps, useKerberos, debug)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error monitoring delegations: %s", err))
		}

	} else {
		logger.Warn(fmt.Sprintf("Invalid mode '%s'.", mode))
	}

	logger.Print("Done.")
}
