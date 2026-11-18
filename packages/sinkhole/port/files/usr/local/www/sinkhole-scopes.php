<?php

declare(strict_types=1);

/*
 * Sinkhole Scopes page, kept so old bookmarks open Blocking.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-scopes
##|*NAME=Firewall: Sinkhole: Scopes
##|*DESCR=Allow access to Sinkhole network and device scope configuration.
##|*MATCH=sinkhole-scopes.php*
##|-PRIV

require_once('guiconfig.inc');

header('Location: sinkhole-blocking.php');
exit;
