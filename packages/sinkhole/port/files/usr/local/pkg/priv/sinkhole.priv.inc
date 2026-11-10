<?php

declare(strict_types=1);

global $priv_list;

$priv_list['page-firewall-sinkhole-general'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: General'),
    'descr' => gettext('Allow access to Sinkhole general settings.'),
    'match' => [
        'pkg_edit.php?xml=sinkhole.xml*',
    ],
];

$priv_list['page-firewall-sinkhole-lists'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Lists'),
    'descr' => gettext('Allow access to Sinkhole block-list configuration.'),
    'match' => [
        'sinkhole-lists.php*',
    ],
];

$priv_list['page-firewall-sinkhole-lists-edit'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Lists: Edit'),
    'descr' => gettext('Allow access to the Sinkhole block-list editor.'),
    'match' => [
        'sinkhole-lists_edit.php*',
    ],
];

$priv_list['page-firewall-sinkhole-services'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Services'),
    'descr' => gettext('Allow access to Sinkhole blocked-service configuration.'),
    'match' => [
        'sinkhole-services.php*',
    ],
];

$priv_list['page-firewall-sinkhole-scopes'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Scopes'),
    'descr' => gettext('Allow access to Sinkhole network and device scope configuration.'),
    'match' => [
        'sinkhole-scopes.php*',
    ],
];

$priv_list['page-firewall-sinkhole-scopes-edit'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Scopes: Edit'),
    'descr' => gettext('Allow access to the Sinkhole network and device scope editor.'),
    'match' => [
        'sinkhole-scopes_edit.php*',
    ],
];

$priv_list['page-firewall-sinkhole-alerts'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Alerts'),
    'descr' => gettext('Allow access to Sinkhole alert-rule configuration.'),
    'match' => [
        'sinkhole-alerts.php*',
    ],
];

$priv_list['page-firewall-sinkhole-alerts-edit'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Alerts: Edit'),
    'descr' => gettext('Allow access to the Sinkhole alert-rule editor.'),
    'match' => [
        'sinkhole-alerts_edit.php*',
    ],
];

$priv_list['page-firewall-sinkhole-bypass'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Bypass'),
    'descr' => gettext('Allow access to Sinkhole bypass protection settings and lists.'),
    'match' => [
        'sinkhole-bypass.php*',
    ],
];

$priv_list['page-firewall-sinkhole-bypass-edit'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Bypass: Edit'),
    'descr' => gettext('Allow access to the Sinkhole Bypass List editor.'),
    'match' => [
        'sinkhole-bypass_edit.php*',
    ],
];

$priv_list['page-firewall-sinkhole-ip'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: IP'),
    'descr' => gettext('Allow access to Sinkhole IP and country blocking settings.'),
    'match' => [
        'sinkhole-ip.php*',
    ],
];

$priv_list['page-firewall-sinkhole-ip-edit'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: IP: Edit'),
    'descr' => gettext('Allow access to the Sinkhole IP-list editor.'),
    'match' => [
        'sinkhole-ip_edit.php*',
    ],
];

$priv_list['page-firewall-sinkhole-status'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: Status'),
    'descr' => gettext('Allow access to Sinkhole status and manual list updates.'),
    'match' => [
        'sinkhole-status.php*',
    ],
];

$priv_list['page-firewall-sinkhole-about'] = [
    'name' => gettext('WebCfg - Firewall: Sinkhole: About'),
    'descr' => gettext('Allow access to Sinkhole package information.'),
    'match' => [
        'sinkhole-about.php*',
    ],
];
