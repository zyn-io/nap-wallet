# Nap Wallet fonts

These files are runtime assets. Nap serves or packages them locally so opening
the wallet does not contact a font CDN.

Downloaded from the `google/fonts` repository at commit
`809e4d8b8d7e9364a914909bb777679606c178b8` on 11 September 2026:

| Family | Runtime file | Upstream path | Licence |
|---|---|---|---|
| Bricolage Grotesque | `BricolageGrotesque.ttf` | `ofl/bricolagegrotesque/BricolageGrotesque[opsz,wdth,wght].ttf` | `BricolageGrotesque-OFL.txt` |
| IBM Plex Sans | `IBMPlexSans.ttf` | `ofl/ibmplexsans/IBMPlexSans[wdth,wght].ttf` | `IBMPlexSans-OFL.txt` |
| IBM Plex Mono | `IBMPlexMono-Regular.ttf`, `IBMPlexMono-Medium.ttf` | `ofl/ibmplexmono/` | `IBMPlexMono-OFL.txt` |

The desktop and extension build scripts copy this directory unchanged. Keep
font URLs in `zynzapd/ui/index.html` relative to `fonts/`; do not restore a
remote stylesheet or font origin.
