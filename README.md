![](./.github/banner.png)

<p align="center">
      Delegations is a tool that allows you to work with unconstrained, constrained, and resource-based constrained delegations in Active Directory.
      <br>
      <a href="https://github.com/TheManticoreProject/Delegations/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/Delegations/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/Delegations">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/Delegations">
      <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
      <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
      <br>
</p>

## Features

- [x] Audit mode:
  - [x] Audit existing unconstrained delegations
  - [x] Audit existing constrained delegations with or without protocol transition
  - [x] Audit existing resource-based constrained delegations
- [x] Add mode:
  - [x] Add new unconstrained delegations
  - [x] Add new constrained delegations with or without protocol transition
  - [x] Add new resource-based constrained delegations
- [x] Find mode:
  - [x] Find unconstrained delegations
  - [x] Find constrained delegations with or without protocol transition
  - [x] Find resource-based constrained delegations
- [x] Remove mode:
  - [x] Remove existing unconstrained delegations
  - [x] Remove existing constrained delegations with or without protocol transition
  - [x] Remove existing resource-based constrained delegations

## Demonstration



## Usage

The first positional argument of the program is the mode:

```
$ ./Delegations
Delegations - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: Delegations <add|audit|find|remove>

   add     Add a constrained, unconstrained, or resource-based constrained delegation to a user or group.
   audit   Audit constrained, unconstrained, and resource-based constrained delegations in Active Directory.
   find    Find a constrained, unconstrained, or resource-based constrained delegation from a user or group.
   remove  Remove a constrained, unconstrained, or resource-based constrained delegation from a user or group.

```

Then for modes `add`, `remove` and `find`, the second positional argument is the delegation type:

```
$ ./Delegations add 
Delegations - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: Delegations add <constrained|rbcd|unconstrained>

   constrained    Add a constrained delegation to a user or group.
   unconstrained  Add a unconstrained delegation to a user or group.
   rbcd           Add a ressource-based delegation to a user or group.

```

For mode `audit` all delegation types are audited at once, no more positional arguments are needed, only options:

```
$ ./Delegations audit
Delegations - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: Delegations audit --domain <string> --username <string> [--password <string>] [--hashes <string>] [--debug] --dc-ip <string> [--ldap-port <tcp port>] [--use-ldaps] [--use-kerberos]


  Authentication:
    -d, --domain <string>   Active Directory domain to authenticate to.
    -u, --username <string> User to authenticate as.
    -p, --password <string> Password to authenticate with. (default: "")
    -H, --hashes <string>   NT/LM hashes, format is LMhash:NThash. (default: "")

  Configuration:
    -d, --debug     Debug mode. (default: false)

  LDAP Connection Settings:
    -dc, --dc-ip <string>       IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.
    -lp, --ldap-port <tcp port> Port number to connect to LDAP server. (default: 389)
    -L, --use-ldaps             Use LDAPS instead of LDAP. (default: false)
    -k, --use-kerberos          Use Kerberos instead of NTLM. (default: false)

```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits
  - [Remi GASCOU (Podalirius)](https://github.com/p0dalirius) for the creation of the [Delegations](https://github.com/p0dalirius/Delegations) project before transferring it to TheManticoreProject.

