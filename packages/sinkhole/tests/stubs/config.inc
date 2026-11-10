<?php

declare(strict_types=1);

require_once(__DIR__ . '/pfctl_exec.inc');

if (function_exists('gettext') === false) {
    /**
     * Sinkhole Stub - Translate Text.
     *
     * @param string $message - Source text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    function gettext(string $message): string
    {
        return $message;
    }
}

/**
 * Stub pfSense configuration.
 *
 * @var array<string, mixed>
 *
 * @since 1.0.0
 */
$sinkholeStubConfiguration = [];

/**
 * Stub persisted pfSense configuration.
 *
 * Unsaved in-memory mutations stay separate so tests can detect a destructive
 * "parse_config()" refresh inside a pfSense-owned process.
 *
 * @var array<string, mixed>
 *
 * @since 1.0.0
 */
$sinkholeStubPersistedConfiguration = [];

/**
 * Stub configuration parse count.
 *
 * @var int
 *
 * @since 1.0.0
 */
$sinkholeStubParseConfigCount = 0;

/**
 * Stub configuration revision descriptions.
 *
 * @var list<string>
 *
 * @since 1.0.0
 */
$sinkholeStubWrites = [];

/**
 * Stub ordered platform operations.
 *
 * @var list<array{type: string, description?: string}>
 *
 * @since 1.0.0
 */
$sinkholeStubOperations = [];

/**
 * Stub system log messages.
 *
 * @var list<string>
 *
 * @since 1.0.0
 */
$sinkholeStubLogs = [];

/**
 * Stub log observer.
 *
 * @var callable(string): void|null
 *
 * @since 1.0.0
 */
$sinkholeStubLogObserver = null;

/**
 * Stub runtime gateway rows.
 *
 * Gateway fixtures model the resolved records returned by pfSense at run time.
 *
 * @var array<string|int, array<string, mixed>>
 *
 * @since 1.0.0
 */
$sinkholeStubGatewayRows = [];

/**
 * Stub runtime gateway helper arguments.
 *
 * Tests retain each inclusion-flag tuple so the all-gateways call stays exact.
 *
 * @var list<array{disabled: bool, localhost: bool, inactive: bool}>
 *
 * @since 1.0.0
 */
$sinkholeStubGatewayArguments = [];

/**
 * Stub dynamic DNS server addresses.
 *
 * DNS fixtures model addresses learned from dynamic interface configuration.
 *
 * @var list<mixed>
 *
 * @since 1.0.0
 */
$sinkholeStubDynamicNameservers = [];

/**
 * Stub dynamic DNS helper arguments.
 *
 * Tests retain the optional interface filter passed to the pfSense helper.
 *
 * @var list<string>
 *
 * @since 1.0.0
 */
$sinkholeStubDynamicNameserverArguments = [];

/**
 * Stub Unbound reconfiguration count.
 *
 * @var int
 *
 * @since 1.0.0
 */
$sinkholeStubUnboundConfigureCount = 0;

/**
 * Stub filter reconfiguration count.
 *
 * @var int
 *
 * @since 1.0.0
 */
$sinkholeStubFilterConfigureCount = 0;

/**
 * Stub background commands.
 *
 * @var list<string>
 *
 * @since 1.0.0
 */
$sinkholeStubBackgroundCommands = [];

/**
 * Stub logged-in user privileges.
 *
 * @var list<string>
 *
 * @since 1.0.0
 */
$sinkholeStubUserPrivileges = [];

/**
 * Stub synchronous commands.
 *
 * @var list<string>
 *
 * @since 1.0.0
 */
$sinkholeStubCommands = [];

/** @var array<string, int> @since 1.0.0 */
$sinkholeStubCommandStatuses = [];

/** @var array<string, list<string>> @since 1.0.0 */
$sinkholeStubExecOutputs = [];

/** @var array<string, int> @since 1.0.0 */
$sinkholeStubExecStatuses = [];

/** @var bool @since 1.0.0 */
$sinkholeStubIpAnchorLoaded = false;

/** @var bool @since 1.0.0 */
$sinkholeStubBypassAnchorLoaded = false;

/**
 * Stub cron operations.
 *
 * @var list<array>
 *
 * @since 1.0.0
 */
$sinkholeStubCronOperations = [];

/**
 * Stub configuration-set observer.
 *
 * @var callable(string, mixed): void|null
 *
 * @since 1.0.0
 */
$sinkholeStubConfigSetObserver = null;

/**
 * Stub normal configuration-write observer.
 *
 * Models pfSense write-config plugins without running them for write-only saves.
 *
 * @var callable(string): void|null
 *
 * @since 1.0.0
 */
$sinkholeStubWriteConfigObserver = null;

/**
 * Stub XML parser state.
 *
 * The callback-driven parser mirrors pfSense's path stack and repeated-tag
 * handling without loading production includes into the offline suite.
 *
 * @var array<string, mixed>
 *
 * @since 1.0.0
 */
$sinkholeStubXmlParseState = [];

/**
 * Sinkhole Stub - Configuration Get Path.
 *
 * @param string $path - Slash-separated path.
 * @param mixed $default - Missing value.
 *
 * @return mixed
 *
 * @since 1.0.0
 */
function config_get_path(string $path, mixed $default = null): mixed
{
    global $sinkholeStubConfiguration;

    if ($path === '') {
        return $sinkholeStubConfiguration;
    }

    $value = $sinkholeStubConfiguration;

    foreach (explode('/', $path) as $segment) {
        if (!is_array($value) || array_key_exists($segment, $value) === false) {
            return $default;
        }

        $value = $value[$segment];
    }

    return $value;
}

/**
 * Sinkhole Stub - Configuration Set Path.
 *
 * @param string $path - Slash-separated path.
 * @param mixed $value - Stored value.
 *
 * @return void
 *
 * @since 1.0.0
 */
function config_set_path(string $path, mixed $value): void
{
    global $sinkholeStubConfiguration;
    global $sinkholeStubConfigSetObserver;

    if (is_callable($sinkholeStubConfigSetObserver)) {
        $sinkholeStubConfigSetObserver($path, $value);
    }

    $segments = explode('/', $path);
    $cursor = &$sinkholeStubConfiguration;

    foreach ($segments as $index => $segment) {
        if ($index === count($segments) - 1) {
            $cursor[$segment] = $value;

            return;
        }

        if (!isset($cursor[$segment]) || !is_array($cursor[$segment])) {
            $cursor[$segment] = [];
        }

        $cursor = &$cursor[$segment];
    }
}

/**
 * Sinkhole Stub - Configuration Delete Path.
 *
 * @param string $path - Slash-separated path.
 *
 * @return void
 *
 * @since 1.0.0
 */
function config_del_path(string $path): void
{
    global $sinkholeStubConfiguration;

    $segments = explode('/', $path);
    $key = array_pop($segments);
    $cursor = &$sinkholeStubConfiguration;

    foreach ($segments as $segment) {
        if (!is_array($cursor) || array_key_exists($segment, $cursor) === false) {
            return;
        }

        $cursor = &$cursor[$segment];
    }

    if (is_array($cursor) && is_string($key)) {
        unset($cursor[$key]);
    }
}

/**
 * Sinkhole Stub - Configuration Path Enabled.
 *
 * @param string $section - Section name.
 * @param string $path - Child path.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function config_path_enabled(string $section, string $path = 'enable'): bool
{
    $sectionValue = config_get_path($section, []);

    return is_array($sectionValue) && isset($sectionValue[$path]);
}

/**
 * Sinkhole Stub - Write Configuration.
 *
 * @param string $description - Revision description.
 * @param bool $backup - Whether pfSense would back up the configuration.
 * @param bool $writeConfigOnly - Whether pfSense must skip synchronization plugins.
 *
 * @return void
 *
 * @since 1.0.0
 */
function write_config(
    string $description = '',
    bool $backup = true,
    bool $writeConfigOnly = false,
): void
{
    global $sinkholeStubConfiguration;
    global $sinkholeStubPersistedConfiguration;
    global $sinkholeStubOperations;
    global $sinkholeStubWriteConfigObserver;
    global $sinkholeStubWrites;

    unset($backup);

    $xml = sinkholeStubSerializeConfiguration($sinkholeStubConfiguration);
    $parsedConfiguration = sinkholeStubParseConfiguration($xml);

    $sinkholeStubConfiguration = $parsedConfiguration;
    $sinkholeStubPersistedConfiguration = $parsedConfiguration;
    $sinkholeStubWrites[] = $description;
    $sinkholeStubOperations[] = [
        'type' => 'write',
        'description' => $description,
    ];

    if ($writeConfigOnly === false && is_callable($sinkholeStubWriteConfigObserver)) {
        $sinkholeStubWriteConfigObserver($description);
    }
}

/**
 * Sinkhole Stub - Parse Configuration.
 *
 * Replaces live state with the last written document, matching pfSense 2.7.2's
 * destructive fallback when a caller refreshes during unsaved configuration work.
 *
 * @param bool $useCache - Whether the caller requested cached parsing.
 *
 * @return array<string, mixed>
 *
 * @since 1.0.0
 */
function parse_config(bool $useCache = false): array
{
    global $sinkholeStubConfiguration;
    global $sinkholeStubParseConfigCount;
    global $sinkholeStubPersistedConfiguration;
    unset($useCache);

    $sinkholeStubParseConfigCount++;
    $sinkholeStubConfiguration = $sinkholeStubPersistedConfiguration;

    return $sinkholeStubPersistedConfiguration;
}

/**
 * Sinkhole Stub - List Tags.
 *
 * Keeps the CE 2.7.2 repeated-element names available to both the serializer and
 * parser so a write has the same array boundaries as pfSense.
 *
 * @return array<string, true>
 *
 * @since 1.0.0
 */
function sinkholeStubListTags(): array
{
    $names = [
        'acls',
        'alias',
        'aliasurl',
        'allowedhostname',
        'allowedip',
        'authserver',
        'bridged',
        'build_port_path',
        'ca',
        'cacert',
        'cert',
        'checkipservice',
        'clone',
        'columnitem',
        'config',
        'container',
        'crl',
        'depends_on_package',
        'disk',
        'dnsserver',
        'dnsupdate',
        'domainoverrides',
        'dyndns',
        'earlyshellcmd',
        'element',
        'encryption-algorithm-option',
        'field',
        'fieldname',
        'gateway_group',
        'gateway_item',
        'gif',
        'gre',
        'group',
        'hash-algorithm-option',
        'hosts',
        'ifgroupentry',
        'igmpentry',
        'interface_array',
        'item',
        'key',
        'l7rules',
        'lagg',
        'lbaction',
        'lbpool',
        'lbprotocol',
        'member',
        'menu',
        'mobilekey',
        'monitor_type',
        'mount',
        'npt',
        'ntpserver',
        'onetoone',
        'openvpn-client',
        'openvpn-csc',
        'openvpn-server',
        'option',
        'package',
        'pages',
        'passthrumac',
        'phase1',
        'phase2',
        'pipe',
        'pool',
        'ppp',
        'pppoe',
        'priv',
        'proxyarpnet',
        'qinqentry',
        'queue',
        'radnsserver',
        'roll',
        'route',
        'row',
        'rrddatafile',
        'rule',
        'schedule',
        'servernat',
        'servers',
        'serversdisabled',
        'service',
        'shellcmd',
        'sshkeyfile',
        'staticmap',
        'subqueue',
        'switch',
        'swport',
        'tab',
        'timerange',
        'tunnel',
        'user',
        'vip',
        'virtual_server',
        'vlan',
        'vlangroup',
        'voucherdbfile',
        'vxlan',
        'wgpeer',
        'widget',
        'winsserver',
        'wolentry',
        'xmldatafile',
    ];
    $tags = array_fill_keys($names, true);
    $customTags = $GLOBALS['custom_listtags'] ?? [];

    foreach (is_array($customTags) ? $customTags : [] as $customTag) {
        if (is_string($customTag) && $customTag !== '') {
            $tags[strtolower($customTag)] = true;
        }
    }

    return $tags;
}

/**
 * Sinkhole Stub - Serialize Configuration.
 *
 * Converts the complete in-memory configuration into one XML document before any
 * test observes a successful configuration revision.
 *
 * @param array $configuration - Complete configuration.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeStubSerializeConfiguration(array $configuration): string
{
    $listTags = sinkholeStubListTags();
    $contents = sinkholeStubSerializeChildren($configuration, 1, $listTags);

    return '<?xml version="1.0"?>' . PHP_EOL
        . '<pfsense>' . PHP_EOL
        . $contents
        . '</pfsense>' . PHP_EOL;
}

/**
 * Sinkhole Stub - Serialize Children.
 *
 * Repeated list-tag arrays emit sibling elements; every other array emits child
 * elements whose names come directly from its keys.
 *
 * @param array $values - Configuration values.
 * @param int $indent - Indentation level.
 * @param array<string, true> $listTags - Repeated-element names.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeStubSerializeChildren(array $values, int $indent, array $listTags): string
{
    $xml = '';

    foreach ($values as $name => $value) {
        $elementName = (string) $name;

        sinkholeStubAssertXmlElementName($elementName);

        if (is_array($value)) {
            if (isset($listTags[strtolower($elementName)])) {
                foreach ($value as $listValue) {
                    if (is_array($listValue)) {
                        if (count($listValue) === 0) {
                            $xml .= sinkholeStubSerializeScalarElement($elementName, '', $indent);
                        } else {
                            $padding = str_repeat("\t", $indent);
                            $children = sinkholeStubSerializeChildren(
                                $listValue,
                                $indent + 1,
                                $listTags,
                            );
                            $xml .= $padding . '<' . $elementName . '>' . PHP_EOL;
                            $xml .= $children;
                            $xml .= $padding . '</' . $elementName . '>' . PHP_EOL;
                        }
                    } elseif ($listValue !== false) {
                        $xml .= sinkholeStubSerializeScalarElement(
                            $elementName,
                            $listValue,
                            $indent,
                        );
                    }
                }
            } elseif (count($value) === 0) {
                $xml .= sinkholeStubSerializeScalarElement($elementName, '', $indent);
            } else {
                $padding = str_repeat("\t", $indent);
                $children = sinkholeStubSerializeChildren($value, $indent + 1, $listTags);
                $xml .= $padding . '<' . $elementName . '>' . PHP_EOL;
                $xml .= $children;
                $xml .= $padding . '</' . $elementName . '>' . PHP_EOL;
            }
        } else {
            $xml .= sinkholeStubSerializeScalarElement($elementName, $value, $indent);
        }
    }

    return $xml;
}

/**
 * Sinkhole Stub - Serialize Scalar Element.
 *
 * Boolean true and empty strings become empty elements, while false booleans are
 * omitted just as they are by pfSense's writer.
 *
 * @param string $name - Element name.
 * @param mixed $value - Scalar value.
 * @param int $indent - Indentation level.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeStubSerializeScalarElement(string $name, mixed $value, int $indent): string
{
    if ($value === false) {
        return '';
    }

    $padding = str_repeat("\t", $indent);

    if ($value === true || $value === '') {
        return $padding . '<' . $name . '></' . $name . '>' . PHP_EOL;
    }

    $encoded = htmlentities((string) $value);

    if (sinkholeStubIsCdataElement($name)) {
        return $padding
            . '<'
            . $name
            . '><![CDATA['
            . $encoded
            . ']]></'
            . $name
            . '>'
            . PHP_EOL;
    }

    return $padding
        . '<'
        . $name
        . '>'
        . $encoded
        . '</'
        . $name
        . '>'
        . PHP_EOL;
}

/**
 * Sinkhole Stub - Assert XML Element Name.
 *
 * Configuration keys must fit the ASCII element-name grammar used throughout
 * pfSense; numeric array indexes outside list tags fail immediately.
 *
 * @param string $name - Element name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeStubAssertXmlElementName(string $name): void
{
    if (preg_match('/^[A-Za-z_:][A-Za-z0-9_.:-]*$/D', $name) !== 1) {
        throw new RuntimeException('Invalid XML element name in stub configuration: ' . $name);
    }
}

/**
 * Sinkhole Stub - Is CDATA Element.
 *
 * pfSense protects these text-oriented prefixes with CDATA while writing the
 * configuration document.
 *
 * @param string $name - Element name.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function sinkholeStubIsCdataElement(string $name): bool
{
    $prefixes = [
        'aclname',
        'auth_pass',
        'auth_prompt',
        'auth_user',
        'certca',
        'certname',
        'city',
        'common_name',
        'descr',
        'detail',
        'email',
        'encryption_password',
        'hint',
        'ldap_attr',
        'ldap_authcn',
        'ldap_basedn',
        'ldap_basedomain',
        'ldap_bind',
        'ldap_extended_query',
        'ldap_filter',
        'ldap_pam_groupdn',
        'ldap_pass',
        'ldap_user',
        'ldapbinddn',
        'ldapbindpass',
        'login_banner',
        'organization',
        'password',
        'rangedescr',
        'state',
        'text',
        'username',
        'varuserspassword',
        'varusersusername',
    ];

    foreach ($prefixes as $prefix) {
        if (str_starts_with($name, $prefix)) {
            return true;
        }
    }

    return false;
}

/**
 * Sinkhole Stub - Parse Configuration.
 *
 * Feeds serialized XML through callback rules equivalent to pfSense's raw parser
 * and returns the parsed root as the next in-memory configuration.
 *
 * @param string $xml - Complete XML document.
 *
 * @return array
 *
 * @since 1.0.0
 */
function sinkholeStubParseConfiguration(string $xml): array
{
    global $sinkholeStubXmlParseState;

    if (function_exists('xml_parser_create') === false) {
        throw new RuntimeException('The PHP XML parser extension is unavailable.');
    }

    $sinkholeStubXmlParseState = [
        'parsed' => [],
        'path' => [],
        'depth' => 0,
        'have_data' => 0,
        'list_tags' => sinkholeStubListTags(),
    ];
    $parser = xml_parser_create();

    xml_set_element_handler(
        $parser,
        'sinkholeStubStartElement',
        'sinkholeStubEndElement',
    );
    xml_set_character_data_handler($parser, 'sinkholeStubCharacterData');
    xml_parser_set_option($parser, XML_OPTION_SKIP_WHITE, 1);

    if (xml_parse($parser, $xml, true) === 0) {
        $error = xml_error_string(xml_get_error_code($parser));
        $line = xml_get_current_line_number($parser);

        throw new RuntimeException(sprintf('Stub XML error: %s at line %d.', $error, $line));
    }

    $parsed = $sinkholeStubXmlParseState['parsed']['pfsense'] ?? null;

    if ($parsed === '') {
        return [];
    }

    if (!is_array($parsed)) {
        throw new RuntimeException('The stub XML document has no pfSense root object.');
    }

    return $parsed;
}

/**
 * Sinkhole Stub - Start Element.
 *
 * Builds references along the lowercase XML path and appends an index for every
 * element name declared as a list tag.
 *
 * @param mixed $parser - XML parser.
 * @param string $name - Element name.
 * @param array $attributes - Element attributes.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeStubStartElement(mixed $parser, string $name, array $attributes): void
{
    global $sinkholeStubXmlParseState;
    unset($attributes);

    $name = strtolower($name);
    $sinkholeStubXmlParseState['path'][] = $name;
    $cursor = &$sinkholeStubXmlParseState['parsed'];

    foreach ($sinkholeStubXmlParseState['path'] as $pathSegment) {
        $cursor = &$cursor[$pathSegment];
    }

    if (isset($sinkholeStubXmlParseState['list_tags'][$name])) {
        if (!is_array($cursor)) {
            $cursor = [];
        }

        $sinkholeStubXmlParseState['path'][] = count($cursor);
    } elseif (isset($cursor)) {
        $line = xml_get_current_line_number($parser);

        throw new RuntimeException(sprintf(
            'Stub XML element %s occurs more than once at line %d.',
            $name,
            $line,
        ));
    }

    $sinkholeStubXmlParseState['depth']++;
    $sinkholeStubXmlParseState['have_data'] = $sinkholeStubXmlParseState['depth'];
}

/**
 * Sinkhole Stub - End Element.
 *
 * Empty ordinary elements become empty strings, while empty repeated elements are
 * removed from their containing list like pfSense's parser workaround.
 *
 * @param mixed $parser - XML parser.
 * @param string $name - Element name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeStubEndElement(mixed $parser, string $name): void
{
    global $sinkholeStubXmlParseState;
    unset($parser);

    $name = strtolower($name);

    if ($sinkholeStubXmlParseState['have_data'] === $sinkholeStubXmlParseState['depth']) {
        $cursor = &$sinkholeStubXmlParseState['parsed'];

        foreach ($sinkholeStubXmlParseState['path'] as $pathSegment) {
            $cursor = &$cursor[$pathSegment];
        }

        $cursor = '';
    }

    array_pop($sinkholeStubXmlParseState['path']);

    if (isset($sinkholeStubXmlParseState['list_tags'][$name])) {
        $cursor = &$sinkholeStubXmlParseState['parsed'];

        foreach ($sinkholeStubXmlParseState['path'] as $pathSegment) {
            $cursor = &$cursor[$pathSegment];
        }

        $lastValue = end($cursor);

        if (!is_array($lastValue) && (string) $lastValue === '') {
            array_pop($cursor);
        }

        array_pop($sinkholeStubXmlParseState['path']);
    }

    $sinkholeStubXmlParseState['depth']--;
}

/**
 * Sinkhole Stub - Character Data.
 *
 * Preserves spaces, trims XML formatting whitespace, and decodes entities at the
 * same callback boundary used by pfSense.
 *
 * @param mixed $parser - XML parser.
 * @param string $data - Character data.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeStubCharacterData(mixed $parser, string $data): void
{
    global $sinkholeStubXmlParseState;
    unset($parser);

    $data = trim($data, "\t\n\r");

    if ($data === '') {
        return;
    }

    $cursor = &$sinkholeStubXmlParseState['parsed'];

    foreach ($sinkholeStubXmlParseState['path'] as $pathSegment) {
        $cursor = &$cursor[$pathSegment];
    }

    if (is_string($cursor)) {
        $cursor .= html_entity_decode($data);
    } elseif (trim($data, ' ') !== '') {
        $cursor = html_entity_decode($data);
        $sinkholeStubXmlParseState['have_data']++;
    }
}

/**
 * Sinkhole Stub - Log Error.
 *
 * @param string $message - Log message.
 *
 * @return void
 *
 * @since 1.0.0
 */
function log_error(string $message): void
{
    global $sinkholeStubLogObserver;
    global $sinkholeStubLogs;

    $sinkholeStubLogs[] = $message;

    if (is_callable($sinkholeStubLogObserver)) {
        $sinkholeStubLogObserver($message);
    }
}

/**
 * Sinkhole Stub - Background Command.
 *
 * @param string $command - Fixed command.
 *
 * @return void
 *
 * @since 1.0.0
 */
function mwexec_bg(string $command): void
{
    global $sinkholeStubBackgroundCommands;

    $sinkholeStubBackgroundCommands[] = $command;
}

/**
 * Sinkhole Stub - Synchronous Command.
 *
 * @param string $command - Fixed command.
 *
 * @return int
 *
 * @since 1.0.0
 */
function mwexec(string $command): int
{
    global $sinkholeStubCommands;
    global $sinkholeStubCommandStatuses;
    global $sinkholeStubBypassAnchorLoaded;
    global $sinkholeStubIpAnchorLoaded;

    $sinkholeStubCommands[] = $command;

    if (isset($sinkholeStubCommandStatuses[$command])) {
        return $sinkholeStubCommandStatuses[$command];
    }

    if ($command === "/sbin/pfctl -a 'sinkhole/ip' -sr 2>/dev/null | /usr/bin/grep -q '.'") {
        return $sinkholeStubIpAnchorLoaded ? 0 : 1;
    }

    if ($command === "/sbin/pfctl -a 'sinkhole/bypass' -sr 2>/dev/null | /usr/bin/grep -q '.'") {
        return $sinkholeStubBypassAnchorLoaded ? 0 : 1;
    }

    if (
        str_starts_with($command, "/sbin/pfctl -a 'sinkhole/ip' -f '")
        && str_ends_with($command, "'")
    ) {
        $sinkholeStubIpAnchorLoaded = true;
    } elseif ($command === "/sbin/pfctl -a 'sinkhole/ip' -F all") {
        $sinkholeStubIpAnchorLoaded = false;
    } elseif (
        str_starts_with($command, "/sbin/pfctl -a 'sinkhole/bypass' -f '")
        && str_ends_with($command, "'")
    ) {
        $anchorPath = substr(
            $command,
            strlen("/sbin/pfctl -a 'sinkhole/bypass' -f '"),
            -1,
        );
        $anchorText = file_get_contents($anchorPath);
        $sinkholeStubBypassAnchorLoaded = is_string($anchorText)
            && str_contains($anchorText, 'block drop ');
    } elseif ($command === "/sbin/pfctl -a 'sinkhole/bypass' -F all") {
        $sinkholeStubBypassAnchorLoaded = false;
    }

    return 0;
}

/**
 * Sinkhole Stub - Install Cron Job.
 *
 * @param mixed ...$arguments - pfSense cron arguments.
 *
 * @return void
 *
 * @since 1.0.0
 */
function install_cron_job(mixed ...$arguments): void
{
    global $sinkholeStubCronOperations;

    $sinkholeStubCronOperations[] = $arguments;

    $command = (string) ($arguments[0] ?? '');
    $active = ($arguments[1] ?? false) === true;
    $items = config_get_path('cron/item', []);
    $items = is_array($items) ? array_values($items) : [];
    $jobIndex = null;

    foreach ($items as $index => $item) {
        if (is_array($item) && str_contains((string) ($item['command'] ?? ''), $command)) {
            $jobIndex = $index;

            break;
        }
    }

    $changed = false;
    $message = '';

    if ($active) {
        $cronItem = [
            'minute' => (string) ($arguments[2] ?? '0'),
            'hour' => (string) ($arguments[3] ?? '*'),
            'mday' => (string) ($arguments[4] ?? '*'),
            'month' => (string) ($arguments[5] ?? '*'),
            'wday' => (string) ($arguments[6] ?? '*'),
            'who' => (string) ($arguments[7] ?? 'root'),
            'command' => $command,
        ];

        if ($jobIndex === null) {
            $items[] = $cronItem;
            $changed = true;
            $message = 'Installed cron job for ' . $command;
        } elseif ($items[$jobIndex] !== $cronItem) {
            $items[$jobIndex] = $cronItem;
            $changed = true;
            $message = 'Updated cron job for ' . $command;
        }
    } elseif ($jobIndex !== null) {
        unset($items[$jobIndex]);
        $items = array_values($items);
        $changed = true;
        $message = 'Removed cron job for ' . $command;
    }

    if ($changed) {
        config_set_path('cron/item', $items);
        write_config($message);
    }
}

/**
 * Sinkhole Stub - Reset.
 *
 * @param array<string, mixed> $configuration - Initial configuration.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeStubReset(array $configuration): void
{
    global $sinkholeStubBackgroundCommands;
    global $sinkholeStubBypassAnchorLoaded;
    global $sinkholeStubConfigSetObserver;
    global $sinkholeStubConfiguration;
    global $sinkholeStubCommands;
    global $sinkholeStubCommandStatuses;
    global $sinkholeStubExecOutputs;
    global $sinkholeStubExecStatuses;
    global $sinkholeStubIpAnchorLoaded;
    global $sinkholeStubCronOperations;
    global $sinkholeStubDhcpLeaseArguments;
    global $sinkholeStubDhcpLeases;
    global $sinkholeStubDhcpBackend;
    global $sinkholeStubDirtySubsystems;
    global $sinkholeStubDynamicNameserverArguments;
    global $sinkholeStubDynamicNameservers;
    global $sinkholeStubArpEntries;
    global $sinkholeStubFilterConfigureCount;
    global $sinkholeStubGatewayArguments;
    global $sinkholeStubGatewayRows;
    global $sinkholeStubInterfaceAddresses;
    global $sinkholeStubInterfaces;
    global $sinkholeStubRealInterfaces;
    global $sinkholeStubLogs;
    global $sinkholeStubLogObserver;
    global $sinkholeStubOperations;
    global $sinkholeStubParseConfigCount;
    global $sinkholeStubPersistedConfiguration;
    global $sinkholeStubRunningProcesses;
    global $sinkholeStubUnboundConfigureCount;
    global $sinkholeStubUserPrivileges;
    global $sinkholeStubValidPidFiles;
    global $sinkholeStubWriteConfigObserver;
    global $sinkholeStubWrites;
    global $sinkholeStubXmlParseState;

    $sinkholeStubConfiguration = $configuration;
    $sinkholeStubPersistedConfiguration = $configuration;
    $sinkholeStubParseConfigCount = 0;
    $sinkholeStubWrites = [];
    $sinkholeStubOperations = [];
    $sinkholeStubLogs = [];
    $sinkholeStubLogObserver = null;
    $sinkholeStubGatewayRows = [];
    $sinkholeStubGatewayArguments = [];
    $sinkholeStubDynamicNameservers = [];
    $sinkholeStubDynamicNameserverArguments = [];
    $sinkholeStubUnboundConfigureCount = 0;
    $sinkholeStubFilterConfigureCount = 0;
    $sinkholeStubBackgroundCommands = [];
    $sinkholeStubUserPrivileges = [];
    $sinkholeStubCommands = [];
    $sinkholeStubCommandStatuses = [];
    $sinkholeStubExecOutputs = [];
    $sinkholeStubExecStatuses = [];
    $sinkholeStubIpAnchorLoaded = false;
    $sinkholeStubBypassAnchorLoaded = false;
    $sinkholeStubCronOperations = [];
    $sinkholeStubConfigSetObserver = null;
    $sinkholeStubWriteConfigObserver = null;
    $sinkholeStubXmlParseState = [];
    $sinkholeStubValidPidFiles = [];
    $sinkholeStubInterfaces = [];
    $sinkholeStubInterfaceAddresses = [];
    $sinkholeStubRealInterfaces = [];
    $sinkholeStubArpEntries = [];
    $sinkholeStubDhcpLeases = [];
    $sinkholeStubDhcpLeaseArguments = [];
    $sinkholeStubDhcpBackend = 'isc';
    $sinkholeStubDirtySubsystems = [];
    $sinkholeStubRunningProcesses = [
        'unbound' => true,
    ];
}
