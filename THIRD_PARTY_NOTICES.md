# Third-Party Notices

The repository-level MIT license applies to the original source code of this
prototype. It does not replace the licenses of third-party data or tools.

## IANA service-name and port-number registry

`data/iana-service-names-port-numbers.csv` is an unchanged snapshot of the
IANA Service Name and Transport Protocol Port Number Registry:
<https://www.iana.org/assignments/service-names-port-numbers/>.

IANA and the IETF state that their protocol registry data may be freely used
for any purpose and dedicate applicable rights under CC0 1.0:
<https://www.iana.org/help/licensing-terms>.

The downloaded snapshot has SHA-256
`466e31f9db1eba0d193b86a8c94e0c7d9027678cf0c2d7280b726ab1b0eeee4a`.
The registry is not presented as evidence that traffic on a registered port
actually belongs to the registered application; it is used only as one
conservative endpoint-orientation and service-naming signal.

## CESNET Idle OS Traffic

The external **CESNET Idle OS Traffic** dataset is published under CC BY 4.0:
<https://doi.org/10.5281/zenodo.15004766>.

The large upstream archive is ignored and is not redistributed in the source
repository or electronic appendix. The appendix builder includes only the
unchanged `merged_tls.csv` member used by the recorded evaluation and one
compact PCAP fixture with their upstream metadata. Its generated notice and
manifest record the authors, DOI, CC BY 4.0 licence, selection rule, and
checksums required for attribution and reproduction.

## External programs

Zeek, nfdump, p0f, and Pandoc are separate programs with their own licences.
They are invoked when installed but are not relicensed or distributed by this
project.
