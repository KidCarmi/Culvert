<?php
// Config overrides for the interop IdP. The cirrusid/simplesamlphp image
// requires this file from the generated config.php, so settings here win.
$config['enable.saml20-idp'] = true;
// The image ships modules disabled-by-default; enable the ones the IdP role
// needs explicitly so the saml IdP metadata route is registered.
$config['module.enable']['exampleauth'] = true;
$config['module.enable']['saml'] = true;
// Apache serves SSP under /simplesaml/ on plain HTTP port 80 in CI; pin the
// base path so generated metadata endpoint URLs resolve correctly.
$config['baseurlpath'] = 'simplesaml/';
$config['secretsalt'] = getenv('SSP_SECRET_SALT') ?: 'culvert-interop-salt';
