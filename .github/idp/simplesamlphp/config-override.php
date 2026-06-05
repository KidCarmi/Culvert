<?php
$config['enable.saml20-idp'] = true;
$config['module.enable']['exampleauth'] = true;
$config['secretsalt'] = getenv('SSP_SECRET_SALT') ?: 'culvert-interop-salt';
