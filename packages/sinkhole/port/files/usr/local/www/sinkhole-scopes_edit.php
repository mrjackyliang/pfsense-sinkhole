<?php

declare(strict_types=1);

/*
 * Sinkhole Scopes editor, kept so old bookmarks open the Clients editor.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-scopes-edit
##|*NAME=Firewall: Sinkhole: Scopes: Edit
##|*DESCR=Allow access to the Sinkhole network and device scope editor.
##|*MATCH=sinkhole-scopes_edit.php*
##|-PRIV

require_once('guiconfig.inc');

$query = [];

foreach (['type', 'id', 'invalid_position'] as $parameter) {
    if (is_string($_GET[$parameter] ?? null) && $_GET[$parameter] !== '') {
        $query[$parameter] = $_GET[$parameter];
    }
}

header('Location: sinkhole-clients_edit.php' . (($query === []) ? '' : '?' . http_build_query($query)));
exit;
