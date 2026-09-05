# Flag icons attribution

The PNG country flags in this directory (`{code}.png`, ISO 3166-1 alpha-2
codes, lowercase) were downloaded from **flagcdn.com** (the CDN of
**Flagpedia** — https://flagpedia.net), `w40` size variant:

- Per-flag URL pattern: `https://flagcdn.com/w40/{code}.png`
- Code list source: `https://flagcdn.com/en/codes.json`

## License

Flagpedia / flagcdn distributes country flag images free of charge under a
free license: the images are in the public domain and may be used for any
purpose, commercial or non-commercial, without attribution being required
(attribution is provided here as a courtesy). See https://flagpedia.net/about.

## Snapshot

- Initial snapshot: 2026-08-11; extended 2026-09-05 for DB-IP Country Lite coverage.
- Coverage: all country codes used by `xray_fluent/profiles/country_flags.py`
  (`_VALID_CODES`), including all 250 known country/territory codes in the pinned DB-IP database.
- Unknown country code `ZZ` has no flag; missing images are never approximated.
- The application never downloads flags at runtime; these files are committed
  to the repository and shipped with the build (`assets/` merge in `build.py`).
