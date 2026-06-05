<?php
// Intentionally empty SP-remote metadata. The interop test only fetches the
// IdP metadata and compiles a crewjam/saml SP from it; no pre-registered SP
// entries are required. Present (and mounted) to match the cirrusid IdP
// reference layout so the flatfile metadata source loads cleanly.
$metadata = [];
