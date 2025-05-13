package main

import (
	"fmt"

	"github.com/TheManticoreProject/Delegations/core/mode_find"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
)

var (
	mode string

	// Configuration
	debug bool

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

	// find mode ============================================================================================================
	subparser_find := ap.AddSubParser("find", "Find constrained, unconstrained, and resource-based constrained delegations in Active Directory.")
	// Configuration flags
	subparser_find_group_config, err := subparser_find.NewArgumentGroup("Configuration")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_find_group_config.NewBoolArgument(&debug, "-d", "--debug", false, "Debug mode.")
	}
	// LDAP Connection Settings
	subparser_find_group_ldapSettings, err := subparser_find.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_find_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_find_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_find_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_find_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_find_group_auth, err := subparser_find.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_find_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_find_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_find_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_find_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// add mode ============================================================================================================
	subparser_add := ap.AddSubParser("add", "Add a constrained, unconstrained, or resource-based constrained delegation to a user or group.")
	subparser_add.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_add_group_config, err := subparser_add.NewArgumentGroup("Configuration")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_add_group_config.NewBoolArgument(&debug, "-d", "--debug", false, "Debug mode.")
	}
	// LDAP Connection Settings
	subparser_add_group_ldapSettings, err := subparser_add.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_add_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_add_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_add_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_add_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_add_group_auth, err := subparser_add.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_add_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_add_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_add_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_add_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	// remove mode ============================================================================================================
	subparser_remove := ap.AddSubParser("remove", "Remove a constrained, unconstrained, or resource-based constrained delegation from a user or group.")
	subparser_remove.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Configuration flags
	subparser_remove_group_config, err := subparser_remove.NewArgumentGroup("Configuration")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_remove_group_config.NewBoolArgument(&debug, "-d", "--debug", false, "Debug mode.")
	}
	// LDAP Connection Settings
	subparser_remove_group_ldapSettings, err := subparser_remove.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_remove_group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_remove_group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		subparser_remove_group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_remove_group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}
	// Authentication flags
	subparser_remove_group_auth, err := subparser_remove.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_remove_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		subparser_remove_group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		subparser_remove_group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_remove_group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()
}

func main() {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		fmt.Printf("[error] Error creating credentials: %s\n", err)
		return
	}

	if mode == "find" {
		mode_find.FindUnconstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos)
		mode_find.FindConstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos)
		mode_find.FindConstrainedDelegationsWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos)
		mode_find.FindRessourceBasedConstrainedDelegations(domainController, ldapPort, creds, useLdaps, useKerberos)
	} else if mode == "add" {
		// mode_add.AddUnconstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName)
		// mode_add.AddConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, AllowedToDelegateTo)
		// mode_add.AddConstrainedDelegationWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, AllowedToDelegateTo)
		// mode_add.AddRessourceBasedConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos, distinguishedName, AllowedToDelegateTo)
	} else if mode == "remove" {
		// mode_remove.RemoveUnconstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos)
		// mode_remove.RemoveConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos)
		// mode_remove.RemoveConstrainedDelegationWithProtocolTransition(domainController, ldapPort, creds, useLdaps, useKerberos)
		// mode_remove.RemoveRessourceBasedConstrainedDelegation(domainController, ldapPort, creds, useLdaps, useKerberos)
	}

	logger.Print("Done")
}
