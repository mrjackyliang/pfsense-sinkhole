<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use InvalidArgumentException;
use PfSense\Sinkhole\Domain\AlertConfiguration;
use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\BypassRuleConfiguration;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\IpConfiguration;
use PfSense\Sinkhole\Domain\IpNetwork;
use PfSense\Sinkhole\Domain\IpRuleConfiguration;
use PfSense\Sinkhole\Domain\RedirectConfiguration;
use PfSense\Sinkhole\Domain\ScopeConfiguration;
use PfSense\Sinkhole\Domain\ServiceConfiguration;
use PfSense\Sinkhole\Domain\Settings;
use PfSense\Sinkhole\Domain\UnboundCustomOptions;
use PfSense\Sinkhole\Domain\ValidationException;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/AlertConfiguration.php');
require_once(__DIR__ . '/BypassConfiguration.php');
require_once(__DIR__ . '/BypassListStore.php');
require_once(__DIR__ . '/BypassRuleConfiguration.php');
require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/ClientMap.php');
require_once(__DIR__ . '/Compiler.php');
require_once(__DIR__ . '/ClientSource.php');
require_once(__DIR__ . '/FileLock.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/PlatformAdapter.php');
require_once(__DIR__ . '/RedirectConfiguration.php');
require_once(__DIR__ . '/SavedListStore.php');
require_once(__DIR__ . '/Settings.php');
require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/IpConfiguration.php');
require_once(__DIR__ . '/IpNetwork.php');
require_once(__DIR__ . '/IpRuleConfiguration.php');
require_once(__DIR__ . '/IpStatusStore.php');
require_once(__DIR__ . '/ScopeConfiguration.php');
require_once(__DIR__ . '/ServiceConfiguration.php');
require_once(__DIR__ . '/StateStore.php');
require_once(__DIR__ . '/UnboundCustomOptions.php');
require_once(__DIR__ . '/ValidationException.php');
require_once(__DIR__ . '/Translator.php');

/**
 * pfSense Adapter.
 *
 * Adapts package orchestration to reviewed pfSense configuration, cron-adjacent,
 * service, logging, and background-command APIs.
 *
 * @since 1.0.0
 */
final class PfSenseAdapter implements PlatformAdapter, ClientSource
{
    /**
     * pfSense Adapter - Unbound Reload Command.
     *
     * The fixed chroot command contains no setting, URL, or downloaded list content.
     *
     * @since 1.0.0
     */
    public const UNBOUND_RELOAD_COMMAND = '/usr/sbin/chroot -u unbound -g unbound / '
        . '/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload';

    /**
     * pfSense Adapter - Paths.
     *
     * Production uses fixed package locations and tests inject disposable paths.
     *
     * @since 1.0.0
     * @private
     */
    private readonly PackagePaths $paths;

    /**
     * pfSense Adapter - State Store.
     *
     * The adapter saves the Resolver recovery point outside "config.xml".
     *
     * @since 1.0.0
     * @private
     */
    private readonly StateStore $stateStore;

    /**
     * pfSense Adapter - Client Map.
     *
     * Sync refreshes this local-data collaborator before enabling Unbound after a
     * compile, while tests can supply a deterministic source-backed instance.
     *
     * @since 1.0.0
     * @private
     */
    private readonly ClientMap $clientMap;

    /**
     * pfSense Adapter - Protected Address Helper Warnings.
     *
     * Optional runtime-discovery failures are logged once per adapter so repeated IP
     * and Bypass table refreshes do not flood the system log.
     *
     * @var array<string, true>
     *
     * @since 1.0.0
     * @private
     */
    private array $protectedAddressHelperWarnings = [];

    /**
     * pfSense Adapter - Constructor.
     *
     * Optional collaborators isolate filesystem side effects in domain tests.
     *
     * @param PackagePaths|null $paths      - Package paths.
     * @param StateStore|null   $stateStore - State store.
     * @param int $loadedGenerationWaitSeconds - Loaded marker wait limit.
     * @param ClientMap|null $clientMap - Client map.
     * @param bool $commandLineMode - Whether this adapter belongs to "sbin/sinkhole".
     *
     * @since 1.0.0
     */
    public function __construct(
        ?PackagePaths $paths = null,
        ?StateStore $stateStore = null,
        private readonly int $loadedGenerationWaitSeconds = 60,
        ?ClientMap $clientMap = null,
        private readonly bool $commandLineMode = false,
    ) {
        if ($this->loadedGenerationWaitSeconds < 0) {
            throw new RuntimeException('The loaded-generation wait limit is invalid.');
        }

        $this->paths = $paths ?? new PackagePaths();
        $this->stateStore = $stateStore ?? new StateStore(
            $this->paths->stateFile,
            $this->paths->statusFile,
        );
        $this->clientMap = $clientMap ?? new ClientMap(
            $this->paths,
            $this,
            $this->stateStore,
        );
    }

    /**
     * pfSense Adapter - Assert Environment.
     *
     * Loads only fixed system include paths and confirms every native function needed
     * by scheduled updater work is available.
     *
     * @return void
     *
     * @throws RuntimeException When pfSense APIs are unavailable.
     *
     * @since 1.0.0
     */
    public function assertEnvironment(): void
    {
        $requiredFiles = [
            '/etc/inc/config.inc',
            '/etc/inc/services.inc',
            '/etc/inc/system.inc',
            '/etc/inc/interfaces.inc',
            '/etc/inc/util.inc',
            '/etc/inc/pfsense-utils.inc',
        ];

        foreach ($requiredFiles as $requiredFile) {
            if (is_readable($requiredFile) === false) {
                throw new RuntimeException('Required pfSense file is unavailable: ' . $requiredFile);
            }

            require_once($requiredFile);
        }

        $requiredFunctions = [
            'config_get_path',
            'config_path_enabled',
            'log_error',
            'mwexec',
            'system_get_arp_table',
            'system_get_dhcpleases',
            'get_configured_interface_with_descr',
            'get_interface_ip',
            'get_interface_subnet',
            'get_interface_ipv6',
            'get_interface_subnetv6',
            'get_real_interface',
            'dhcp_is_backend',
            'is_process_running',
            'is_subsystem_dirty',
        ];

        foreach ($requiredFunctions as $requiredFunction) {
            if (function_exists($requiredFunction) === false) {
                throw new RuntimeException('Required pfSense function is unavailable: ' . $requiredFunction);
            }
        }
    }

    /**
     * pfSense Adapter - Settings.
     *
     * Missing settings become an empty record for domain-level validation.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getSettings(): array
    {
        $settings = config_get_path('installedpackages/sinkhole/config/0', []);

        return is_array($settings) ? $settings : [];
    }

    /**
     * pfSense Adapter - Lists.
     *
     * Lists live beside the generic settings record so pkg_edit.php saves cannot
     * replace custom-page data.
     *
     * @return mixed
     *
     * @since 1.0.0
     */
    public function getLists(): mixed
    {
        return config_get_path('installedpackages/sinkhole/lists/item', []);
    }

    /**
     * pfSense Adapter - Allowed Domains.
     *
     * Returns repeated configuration elements without trusting their contents.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getAllowedDomains(): array
    {
        $value = config_get_path('installedpackages/sinkhole/allowed_domains/item', []);

        return is_array($value) ? array_values($value) : [];
    }

    /**
     * pfSense Adapter - Host And Network Aliases.
     *
     * Exposes only address-bearing alias kinds that pfSense places in filter macro
     * definitions before checking package rules.
     *
     * @return array<string, string>
     *
     * @since 1.0.0
     */
    public function getHostNetworkAliases(): array
    {
        $rows = config_get_path('aliases/alias', []);
        $aliases = [];

        foreach ((is_array($rows)) ? $rows : [] as $row) {
            if (
                !is_array($row)
                || !is_string($row['name'] ?? null)
                || !is_string($row['type'] ?? null)
                || !in_array($row['type'], ['host', 'network'], true)
            ) {
                continue;
            }

            $aliases[$row['name']] = $row['type'];
        }

        return $aliases;
    }

    /**
     * pfSense Adapter - Redirect Configuration.
     *
     * Partitions saved values against the interfaces and aliases that currently
     * exist on the firewall.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getRedirectConfiguration(): array
    {
        return RedirectConfiguration::partition(
            config_get_path('installedpackages/sinkhole/redirect', []),
            $this->getConfiguredInterfaces(),
            $this->getHostNetworkAliases(),
        );
    }

    /**
     * pfSense Adapter - Bypass Configuration.
     *
     * The interface selection stays in the existing redirect branch so upgrades
     * preserve it and both features always share one client-facing scope.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getBypassConfiguration(): array
    {
        $redirect = $this->getRedirectConfiguration();
        $configuration = BypassConfiguration::partition(
            config_get_path('installedpackages/sinkhole/bypass', []),
            $redirect['interfaces'],
        );
        $tls = $this->dnsResolverTlsStatus();
        $configuration['discovery_hostname'] = $tls['enabled'] ? $tls['hostname'] : '';
        $configuration['discovery_port'] = $tls['enabled'] ? $tls['port'] : 0;
        $configuration['discovery_tls'] = $tls;
        $configuration['discovery_zone_present'] = $this->discoveryZonePresent();

        return $configuration;
    }

    /**
     * pfSense Adapter - Bypass Interfaces.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public function getBypassInterfaces(): array
    {
        return $this->getRedirectConfiguration()['interfaces'];
    }

    /**
     * pfSense Adapter - DNS Resolver TLS Status.
     *
     * Resolves the advertised hostname from the certificate's first DNS SAN, or
     * its common name when no DNS SAN exists. Wildcards cannot be DDR targets.
     *
     * @return array{enabled: bool, service_enabled: bool, hostname: string, port: int, reason: string}
     *
     * @since 1.0.0
     */
    public function dnsResolverTlsStatus(): array
    {
        $serviceEnabled = config_path_enabled('unbound')
            && config_path_enabled('unbound', 'enablessl');
        $result = [
            'enabled' => false,
            'service_enabled' => $serviceEnabled,
            'hostname' => '',
            'port' => 853,
            'reason' => '',
        ];

        if (!$serviceEnabled) {
            $result['reason'] = 'The DNS Resolver SSL/TLS service is off.';

            return $result;
        }

        $portValue = config_get_path('unbound/tlsport', '');
        $port = ($portValue === '' || $portValue === null) ? 853 : (int) $portValue;
        $result['port'] = $port;

        if ($port !== 853) {
            $result['reason'] = 'The DNS Resolver SSL/TLS service must listen on port 853.';

            return $result;
        }

        $certificateReference = config_get_path('unbound/sslcertref', '');
        $certificate = null;

        if (is_string($certificateReference) && $certificateReference !== '') {
            if (function_exists('lookup_cert')) {
                $candidate = lookup_cert($certificateReference);

                if (is_array($candidate) && is_array($candidate['item'] ?? null)) {
                    $certificate = $candidate['item'];
                } elseif (is_array($candidate) && is_string($candidate['crt'] ?? null)) {
                    $certificate = $candidate;
                }
            }

            if ($certificate === null) {
                $certificates = config_get_path('cert', []);

                foreach (is_array($certificates) ? $certificates : [] as $candidate) {
                    if (
                        is_array($candidate)
                        && ($candidate['refid'] ?? null) === $certificateReference
                    ) {
                        $certificate = $candidate;
                        break;
                    }
                }
            }
        }

        $encoded = is_array($certificate) && is_string($certificate['crt'] ?? null)
            ? $certificate['crt']
            : '';
        $pem = ($encoded === '') ? false : base64_decode($encoded, true);
        $parsed = is_string($pem) && function_exists('openssl_x509_parse')
            ? openssl_x509_parse($pem, false)
            : false;

        if (!is_array($parsed)) {
            $result['reason'] = 'The DNS Resolver SSL/TLS certificate is unavailable.';

            return $result;
        }

        $candidates = [];
        $subjectAlternativeName = $parsed['extensions']['subjectAltName'] ?? '';

        if (is_string($subjectAlternativeName)) {
            foreach (explode(',', $subjectAlternativeName) as $alternativeName) {
                $alternativeName = trim($alternativeName);

                if (str_starts_with($alternativeName, 'DNS:')) {
                    $candidates[] = trim(substr($alternativeName, 4));
                }
            }
        }

        $commonName = $parsed['subject']['CN'] ?? '';

        if ($candidates === [] && is_string($commonName)) {
            $candidates[] = $commonName;
        }

        foreach ($candidates as $candidate) {
            if (!is_string($candidate) || str_contains($candidate, '*')) {
                continue;
            }

            $hostname = DomainParser::normalizeDomain($candidate);

            if ($hostname !== null) {
                $result['hostname'] = $hostname;
                $result['enabled'] = true;

                return $result;
            }
        }

        $result['reason'] = 'The DNS Resolver SSL/TLS certificate has no usable DNS hostname.';

        return $result;
    }

    /**
     * pfSense Adapter - IP Configuration.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getIpConfiguration(): array
    {
        return IpConfiguration::partition(
            config_get_path('installedpackages/sinkhole/ip', []),
            $this->getConfiguredInterfaces(),
            $this->getHostNetworkAliases(),
        );
    }

    /**
     * pfSense Adapter - Save IP Configuration.
     *
     * @param array $storage - Complete validated storage record.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function saveIpConfiguration(array $storage): void
    {
        $partition = IpConfiguration::partition(
            $storage,
            $this->getConfiguredInterfaces(),
            $this->getHostNetworkAliases(),
        );

        if ($partition['invalid_values'] !== []) {
            $invalid = $partition['invalid_values'][0];

            throw new ValidationException(
                $invalid['reason_key'],
                $invalid['reason_arguments'] ?? [],
            );
        }

        config_set_path('installedpackages/sinkhole/ip', $storage);
        write_config(Translator::translate('revision_saved_ip_blocking'));

        if ($partition['enabled']) {
            foreach ([$this->paths->ipTableIpv4File, $this->paths->ipTableIpv6File] as $path) {
                if (!FileSystem::isRegularFile($path)) {
                    AtomicFile::write($path, '', 0600);
                }
            }
        }

        $this->applyIpAnchor();

        $this->reloadFilter();
    }

    /**
     * pfSense Adapter - IP Rule Text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function ipRuleText(): string
    {
        return ($this->ipBlockingWanted()) ? IpRuleConfiguration::referenceText() : '';
    }

    /**
     * pfSense Adapter - IP Anchor Text.
     *
     * Builds the complete independently loaded anchor from current validated
     * settings and fixed per-family table files.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function ipAnchorText(): string
    {
        if ($this->stateStore->removing()) {
            return '';
        }

        $configuration = $this->getIpConfiguration();

        if (
            $configuration['enabled'] === false
            || $configuration['invalid_values'] !== []
        ) {
            return '';
        }

        foreach ([$this->paths->ipTableIpv4File, $this->paths->ipTableIpv6File] as $path) {
            if (!FileSystem::isRegularFile($path)) {
                AtomicFile::write($path, '', 0600);
            }
        }

        return IpRuleConfiguration::anchorText(
            $this->ipInterfaceDetails($configuration['interfaces']),
            $configuration['directions'],
            $this->paths->ipTableIpv4File,
            $this->paths->ipTableIpv6File,
        );
    }

    /**
     * pfSense Adapter - Bypass Rule Text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function bypassRuleText(): string
    {
        return $this->bypassBlockingWanted()
            ? BypassRuleConfiguration::referenceText()
            : '';
    }

    /**
     * pfSense Adapter - Bypass Anchor Text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function bypassAnchorText(): string
    {
        if ($this->stateStore->removing()) {
            return '';
        }

        $configuration = $this->getBypassConfiguration();

        if (!$configuration['firewall_enabled'] || $configuration['invalid_values'] !== []) {
            return '';
        }

        if (
            $configuration['block_encrypted_dns']
            || $configuration['block_tor']
            || $configuration['block_vpn']
        ) {
            foreach (
                [$this->paths->bypassTableIpv4File, $this->paths->bypassTableIpv6File]
                as $path
            ) {
                if (!FileSystem::isRegularFile($path)) {
                    AtomicFile::write($path, '', 0600);
                }
            }
        }

        return BypassRuleConfiguration::anchorText(
            $this->ipInterfaceDetails($configuration['interfaces']),
            $configuration,
            $this->paths->bypassTableIpv4File,
            $this->paths->bypassTableIpv6File,
        );
    }

    /**
     * pfSense Adapter - IP Interface Details.
     *
     * @param list<string> $interfaces - Selected logical interfaces.
     *
     * @return list<array{interface: string, real_interface: string, ipv4: bool, ipv6: bool}>
     *
     * @since 1.0.0
     */
    public function ipInterfaceDetails(array $interfaces): array
    {
        if (function_exists('get_real_interface') === false) {
            require_once('/etc/inc/interfaces.inc');
        }

        if (function_exists('get_real_interface') === false) {
            throw new RuntimeException('The pfSense real-interface helper is unavailable.');
        }

        $configured = $this->getConfiguredInterfaces();
        $details = [];

        foreach ($interfaces as $interface) {
            if (!is_string($interface) || !isset($configured[$interface])) {
                continue;
            }

            $realInterface = get_real_interface($interface);

            if (!is_string($realInterface) || $realInterface === '') {
                continue;
            }

            $ipv4 = get_interface_ip($interface);
            $ipv6 = get_interface_ipv6($interface);
            $details[] = [
                'interface' => $interface,
                'real_interface' => $realInterface,
                'ipv4' => is_string($ipv4)
                    && filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false,
                'ipv6' => is_string($ipv6)
                    && filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false,
            ];
        }

        return $details;
    }

    /**
     * pfSense Adapter - IP Protected Addresses.
     *
     * Firewall interfaces, selected interface subnets, virtual IPs, and gateway and
     * DNS addresses from configuration or runtime state are removed from tables.
     *
     * @param list<string> $selectedInterfaces - Interfaces whose complete subnets are protected.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public function ipProtectedAddresses(array $selectedInterfaces = []): array
    {
        $addresses = [];

        foreach (array_keys($this->getConfiguredInterfaces()) as $interface) {
            foreach ([get_interface_ip($interface), get_interface_ipv6($interface)] as $candidate) {
                $this->addProtectedAddress($addresses, $candidate);
            }
        }

        if ($selectedInterfaces !== []) {
            $interfaceSubnets = $this->getInterfaceSubnets();

            foreach ($selectedInterfaces as $interface) {
                if (!is_string($interface)) {
                    continue;
                }

                foreach ($interfaceSubnets[$interface] ?? [] as $subnet) {
                    $addresses[IpNetwork::normalize($subnet)] = true;
                }
            }
        }

        $virtualIps = config_get_path('virtualip/vip', []);

        foreach (is_array($virtualIps) ? $virtualIps : [] as $virtualIp) {
            if (
                !is_array($virtualIp)
                || !in_array($virtualIp['mode'] ?? null, ['carp', 'ipalias'], true)
            ) {
                continue;
            }

            $candidate = $virtualIp['subnet'] ?? '';

            $this->addProtectedAddress($addresses, $candidate);
        }

        $dnsServers = config_get_path('system/dnsserver', []);

        foreach (is_array($dnsServers) ? $dnsServers : [$dnsServers] as $dnsServer) {
            $candidate = is_array($dnsServer) ? ($dnsServer['address'] ?? '') : $dnsServer;

            $this->addProtectedAddress($addresses, $candidate);
        }

        foreach ($this->dynamicDnsServerAddresses() as $dnsServer) {
            $this->addProtectedAddress($addresses, $dnsServer);
        }

        $gateways = config_get_path('gateways/gateway_item', []);

        foreach (is_array($gateways) ? $gateways : [] as $gateway) {
            $candidate = is_array($gateway) ? ($gateway['gateway'] ?? '') : '';

            $this->addProtectedAddress($addresses, $candidate);
        }

        foreach ($this->runtimeGatewayAddresses() as $gatewayAddress) {
            $this->addProtectedAddress($addresses, $gatewayAddress);
        }

        unset($addresses['']);

        return array_keys($addresses);
    }

    /**
     * pfSense Adapter - IP Allowlist Networks.
     *
     * @param list<string> $values - Valid literals and alias names.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public function ipAllowlistNetworks(array $values): array
    {
        $aliasRows = config_get_path('aliases/alias', []);
        $aliasValues = [];

        foreach (is_array($aliasRows) ? $aliasRows : [] as $row) {
            if (
                !is_array($row)
                || !is_string($row['name'] ?? null)
                || !in_array($row['type'] ?? null, ['host', 'network'], true)
            ) {
                continue;
            }

            $addressText = is_string($row['address'] ?? null) ? $row['address'] : '';
            $aliasValues[$row['name']] = preg_split('/\s+/', trim($addressText)) ?: [];
        }

        $networks = [];
        $resolve = function (string $candidate, array $trail = []) use (
            &$resolve,
            &$networks,
            $aliasValues,
        ): void {
            if (isset($aliasValues[$candidate])) {
                if (isset($trail[$candidate]) || count($trail) >= 32) {
                    return;
                }

                $trail[$candidate] = true;

                foreach ($aliasValues[$candidate] as $nestedCandidate) {
                    if (is_string($nestedCandidate) && $nestedCandidate !== '') {
                        $resolve($nestedCandidate, $trail);
                    }
                }

                return;
            }

            try {
                $networks[] = IpNetwork::normalize($candidate);

                if (count($networks) > IpNetwork::MAXIMUM_NETWORKS) {
                    throw new RuntimeException('The IP allowlist count limit was exceeded.');
                }
            } catch (InvalidArgumentException) {
                return;
            }
        };

        foreach ($values as $value) {
            if (is_string($value)) {
                $resolve($value);
            }
        }

        return IpNetwork::merge($networks);
    }

    /**
     * pfSense Adapter - DNS Resolver Running.
     *
     * Redirect rules are safe only while the configured Resolver process is
     * actually accepting the redirected queries.
     *
     * @return bool
     *
     * @throws RuntimeException When pfSense's process helper is unavailable.
     *
     * @since 1.0.0
     */
    public function isDnsResolverRunning(): bool
    {
        if (function_exists('is_process_running') === false) {
            require_once('/etc/inc/util.inc');
        }

        if (function_exists('is_process_running') === false) {
            throw new RuntimeException('The pfSense process helper is unavailable.');
        }

        return is_process_running('unbound');
    }

    /**
     * pfSense Adapter - Redirect Rule Text.
     *
     * The filter hook and minute reconciler share one complete wanted-rules
     * decision, including live Resolver process state.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function redirectRuleText(): string
    {
        $settings = Settings::fromStorage($this->getSettings());

        if (
            $settings['enabled'] === false
            || $this->isIntegrationActive() === false
            || $this->isDnsResolverRunning() === false
        ) {
            return '';
        }

        $configuration = $this->getRedirectConfiguration();

        if (
            $configuration['enabled'] === false
        ) {
            return '';
        }

        if (count($configuration['invalid_exemptions']) > 0) {
            $this->logRedirectPauseOnce($configuration['invalid_exemptions']);

            return '';
        }

        if (count($configuration['interfaces']) === 0) {
            return '';
        }

        $interfaceDetails = $this->getRedirectInterfaceDetails(
            $configuration['interfaces'],
        );

        return RedirectConfiguration::ruleText(
            $interfaceDetails,
            $configuration['exempt_sources'],
            $this->getHostNetworkAliases(),
            $configuration['exempt_destinations'],
        );
    }

    /**
     * pfSense Adapter - Configured Interfaces.
     *
     * Returns only configured, enabled interfaces using pfSense's canonical helper.
     *
     * @return array<string, string>
     *
     * @since 1.0.0
     */
    public function getConfiguredInterfaces(): array
    {
        if (function_exists('get_configured_interface_with_descr') === false) {
            return [];
        }

        $interfaces = get_configured_interface_with_descr();

        if (!is_array($interfaces)) {
            return [];
        }

        $result = [];

        foreach ($interfaces as $interface => $description) {
            if (is_string($interface) && $interface !== '' && is_scalar($description)) {
                $result[$interface] = (string) $description;
            }
        }

        return $result;
    }

    /**
     * pfSense Adapter - Redirect Interface Details.
     *
     * Resolves each selected logical interface through pfSense and records only the
     * address families currently present on it.
     *
     * @param list<string> $interfaces - Selected logical interfaces.
     *
     * @return list<array{
     *     interface: string,
     *     ipv4_interface: string,
     *     ipv4_target: string,
     *     ipv4_reason: string,
     *     ipv6_interface: string,
     *     ipv6_target: string,
     *     ipv6_reason: string
     * }>
     *
     * @throws RuntimeException When pfSense's interface resolver is unavailable.
     *
     * @since 1.0.0
     */
    public function getRedirectInterfaceDetails(array $interfaces): array
    {
        if (function_exists('get_real_interface') === false) {
            require_once('/etc/inc/interfaces.inc');
        }

        if (function_exists('get_real_interface') === false) {
            throw new RuntimeException('The pfSense interface resolver is unavailable.');
        }

        $configuredInterfaces = $this->getConfiguredInterfaces();
        $activeInterfaces = $this->resolverActiveInterfaces();
        $details = [];

        foreach ($interfaces as $interface) {
            if (!is_string($interface) || !array_key_exists($interface, $configuredInterfaces)) {
                continue;
            }

            $ipv4Address = get_interface_ip($interface);
            $ipv6Address = get_interface_ipv6($interface);
            $ipv4Interface = '';
            $ipv6Interface = '';
            $ipv4Target = '';
            $ipv6Target = '';
            $ipv4Reason = 'no_address';
            $ipv6Reason = 'no_address';

            if (
                is_string($ipv4Address)
                && filter_var($ipv4Address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            ) {
                $normalizedIpv4Address = $this->normalizeAddress($ipv4Address);
                $ipv4Reason = 'resolver_not_listening';

                if (
                    $activeInterfaces['automatic']
                    || in_array('lo0', $activeInterfaces['values'], true)
                    || in_array('127.0.0.1', $activeInterfaces['values'], true)
                ) {
                    $ipv4Target = '127.0.0.1';
                } elseif (
                    in_array($interface, $activeInterfaces['values'], true)
                    || in_array($normalizedIpv4Address, $activeInterfaces['values'], true)
                ) {
                    $ipv4Target = $normalizedIpv4Address;
                }

                if ($ipv4Target !== '') {
                    $realInterface = get_real_interface($interface);
                    $ipv4Interface = (is_string($realInterface)) ? $realInterface : '';

                    if ($ipv4Interface === '') {
                        $ipv4Target = '';
                    } else {
                        $ipv4Reason = '';
                    }
                }
            }

            if (
                is_string($ipv6Address)
                && filter_var($ipv6Address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
            ) {
                $normalizedIpv6Address = $this->normalizeAddress($ipv6Address);
                $ipv6Reason = 'resolver_not_listening';

                if (
                    $activeInterfaces['automatic']
                    || in_array($interface, $activeInterfaces['values'], true)
                    || in_array($normalizedIpv6Address, $activeInterfaces['values'], true)
                ) {
                    $ipv6Target = $normalizedIpv6Address;
                    $realInterface = get_real_interface($interface, 'inet6');
                    $ipv6Interface = (is_string($realInterface)) ? $realInterface : '';

                    if ($ipv6Interface === '') {
                        $ipv6Target = '';
                    } else {
                        $ipv6Reason = '';
                    }
                }
            }

            $details[] = [
                'interface' => $interface,
                'ipv4_interface' => $ipv4Interface,
                'ipv4_target' => $ipv4Target,
                'ipv4_reason' => $ipv4Reason,
                'ipv6_interface' => $ipv6Interface,
                'ipv6_target' => $ipv6Target,
                'ipv6_reason' => $ipv6Reason,
            ];
        }

        return $details;
    }

    /**
     * pfSense Adapter - Static Mappings.
     *
     * Copies DHCP mappings with their interface so identity never depends on the
     * array index that pfSense re-sorts on save.
     *
     * @return list<array>
     *
     * @since 1.0.0
     */
    public function getStaticMappings(): array
    {
        $mappings = [];

        foreach (array_keys($this->getConfiguredInterfaces()) as $interface) {
            $rows = config_get_path('dhcpd/' . $interface . '/staticmap', []);

            foreach (is_array($rows) ? $rows : [] as $row) {
                if (!is_array($row)) {
                    continue;
                }

                $row['interface'] = $interface;
                $mappings[] = $row;
            }
        }

        return $mappings;
    }

    /**
     * pfSense Adapter - Interface Subnets.
     *
     * Reads current IPv4 and IPv6 interface addresses, including track6 results,
     * and emits canonical non-link-local CIDRs.
     *
     * @return array<string, list<string>>
     *
     * @since 1.0.0
     */
    public function getInterfaceSubnets(): array
    {
        $subnets = [];

        foreach (array_keys($this->getConfiguredInterfaces()) as $interface) {
            $subnets[$interface] = [];
            $candidates = [
                [get_interface_ip($interface), get_interface_subnet($interface)],
                [get_interface_ipv6($interface), get_interface_subnetv6($interface)],
            ];

            foreach ($candidates as [$address, $prefix]) {
                if (!is_string($address) || (!is_int($prefix) && !is_string($prefix))) {
                    continue;
                }

                $cidr = self::networkCidr($address, $prefix);

                if ($cidr !== null) {
                    $subnets[$interface][] = $cidr;
                }
            }

            $subnets[$interface] = array_values(array_unique($subnets[$interface]));
            sort($subnets[$interface], SORT_STRING);
        }

        return $subnets;
    }

    /**
     * pfSense Adapter - Interface Addresses.
     *
     * @return array<string, list<string>>
     *
     * @since 1.0.0
     */
    public function getInterfaceAddresses(): array
    {
        $addresses = [];

        foreach (array_keys($this->getConfiguredInterfaces()) as $interface) {
            $addresses[$interface] = [];

            foreach ([get_interface_ip($interface), get_interface_ipv6($interface)] as $candidate) {
                if (
                    is_string($candidate)
                    && filter_var($candidate, FILTER_VALIDATE_IP) !== false
                ) {
                    $addresses[$interface][] = $this->normalizeAddress($candidate);
                }
            }
        }

        return $addresses;
    }

    /**
     * pfSense Adapter - ARP Entries.
     *
     * Uses pfSense's fixed local helper and performs no DNS lookup.
     *
     * @return list<array>
     *
     * @since 1.0.0
     */
    public function getArpEntries(): array
    {
        $entries = system_get_arp_table();

        return is_array($entries) ? array_values($entries) : [];
    }

    /**
     * pfSense Adapter - NDP Output.
     *
     * Runs the same fixed, input-free command as pfSense's diagnostics page.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function getNdpOutput(): string
    {
        $lines = [];
        $status = 0;
        exec('/usr/sbin/ndp -na', $lines, $status);

        if ($status !== 0) {
            throw new RuntimeException('Unable to read the IPv6 neighbor table.');
        }

        return implode(PHP_EOL, $lines) . (count($lines) > 0 ? PHP_EOL : '');
    }

    /**
     * pfSense Adapter - DHCP Leases.
     *
     * Passing ``false`` is mandatory: it prevents pfSense from running ``host`` or
     * reverse DNS lookups for unnamed leases.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getDhcpLeases(): array
    {
        $leases = system_get_dhcpleases(false);

        return is_array($leases) ? $leases : [];
    }

    /**
     * pfSense Adapter - DHCP Lease Context.
     *
     * Kea emits local timestamps. ISC remains in GMT unless an interface requests
     * local lease times through ``dhcpleaseinlocaltime``.
     *
     * @return array{
     *     times_local: bool,
     *     active: string,
     *     expired: string,
     *     reserved: string,
     *     never: string
     * }
     *
     * @since 1.0.0
     */
    public function getDhcpLeaseContext(): array
    {
        $timesLocal = dhcp_is_backend('kea');
        $dhcpdConfiguration = config_get_path('dhcpd', []);

        foreach ($timesLocal ? [] : (is_array($dhcpdConfiguration) ? $dhcpdConfiguration : []) as $dhcpd) {
            if (
                is_array($dhcpd)
                && $dhcpd !== []
                && ($dhcpd['dhcpleaseinlocaltime'] ?? null) === 'yes'
            ) {
                $timesLocal = true;
                break;
            }
        }

        return [
            'times_local' => $timesLocal,
            'active' => gettext('active'),
            'expired' => gettext('expired'),
            'reserved' => gettext('reserved'),
            'never' => gettext('Never'),
        ];
    }

    /**
     * pfSense Adapter - Network Scopes.
     *
     * Invalid saved rows remain in configuration but never reach runtime data.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getNetworks(): array
    {
        $lists = ListConfiguration::normalizeLists($this->getLists());

        return ScopeConfiguration::partitionNetworks(
            config_get_path('installedpackages/sinkhole/networks/item', []),
            $this->getConfiguredInterfaces(),
            $lists,
        )['networks'];
    }

    /**
     * pfSense Adapter - Device Scopes.
     *
     * Device order is retained so the client-map first-wins rule is deterministic.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getDevices(): array
    {
        $lists = ListConfiguration::normalizeLists($this->getLists());

        return ScopeConfiguration::partitionDevices(
            config_get_path('installedpackages/sinkhole/devices/item', []),
            $this->getStaticMappings(),
            $lists,
        )['devices'];
    }

    /**
     * pfSense Adapter - Alerts.
     *
     * Invalid saved rules remain in configuration but never reach runtime data.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getAlerts(): array
    {
        return $this->getAlertPartitions()['alerts'];
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getBlockedServices(): array
    {
        return ServiceConfiguration::partition(
            config_get_path('installedpackages/sinkhole/services', []),
        );
    }

    /**
     * pfSense Adapter - Alert Partitions.
     *
     * @return array{alerts: array<string, array>, invalid_rows: list<array>}
     *
     * @since 1.0.0
     */
    public function getAlertPartitions(): array
    {
        $lists = ListConfiguration::normalizeLists($this->getLists());
        $scopes = $this->getScopePartitions();

        return AlertConfiguration::partitionAlerts(
            config_get_path('installedpackages/sinkhole/alerts/item', []),
            $lists,
            $scopes['networks'],
            $scopes['devices'],
        );
    }

    /**
     * pfSense Adapter - Scope Partitions.
     *
     * Gives the WebGUI valid runtime rows and malformed repair rows together.
     *
     * @return array{networks: array, invalid_networks: list<array>, devices: array, invalid_devices: list<array>}
     *
     * @since 1.0.0
     */
    public function getScopePartitions(): array
    {
        $lists = ListConfiguration::normalizeLists($this->getLists());
        $networkPartition = ScopeConfiguration::partitionNetworks(
            config_get_path('installedpackages/sinkhole/networks/item', []),
            $this->getConfiguredInterfaces(),
            $lists,
        );
        $devicePartition = ScopeConfiguration::partitionDevices(
            config_get_path('installedpackages/sinkhole/devices/item', []),
            $this->getStaticMappings(),
            $lists,
        );

        return [
            'networks' => $networkPartition['networks'],
            'invalid_networks' => $networkPartition['invalid_rows'],
            'devices' => $devicePartition['devices'],
            'invalid_devices' => $devicePartition['invalid_rows'],
        ];
    }

    /**
     * pfSense Adapter - Save Scope Configuration.
     *
     * Saves both ordered scope groups and preserved malformed rows in one revision.
     *
     * @param array $networks - Valid networks.
     * @param array $devices - Valid devices in precedence order.
     * @param list<array> $invalidNetworks - Network repair rows.
     * @param list<array> $invalidDevices - Device repair rows.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function saveScopeConfiguration(
        array $networks,
        array $devices,
        array $invalidNetworks = [],
        array $invalidDevices = [],
    ): void {
        $networkRows = [];
        $deviceRows = [];

        foreach (array_values($networks) as $network) {
            $networkRows[] = self::scopeRowForStorage($network);
        }

        foreach (array_values($devices) as $device) {
            $deviceRows[] = self::scopeRowForStorage($device);
        }

        foreach ($invalidNetworks as $invalidRow) {
            if (is_array($invalidRow) && array_key_exists('row', $invalidRow)) {
                $networkRows[] = self::scopeRowForStorage($invalidRow['row']);
            }
        }

        foreach ($invalidDevices as $invalidRow) {
            if (is_array($invalidRow) && array_key_exists('row', $invalidRow)) {
                $deviceRows[] = self::scopeRowForStorage($invalidRow['row']);
            }
        }

        config_set_path('installedpackages/sinkhole/networks/item', $networkRows);
        config_set_path('installedpackages/sinkhole/devices/item', $deviceRows);
        write_config(Translator::translate('revision_saved_scopes'));
        $this->stateStore->markCompileNeeded();
    }

    /**
     * pfSense Adapter - Save Alert Configuration.
     *
     * @param array $alerts - Validated alert rules.
     * @param list<array> $invalidRows - Invalid rows preserved for repair.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function saveAlertConfiguration(array $alerts, array $invalidRows = []): void
    {
        $rows = [];

        foreach (array_values($alerts) as $alert) {
            $rows[] = self::alertRowForStorage($alert);
        }

        foreach ($invalidRows as $invalidRow) {
            if (is_array($invalidRow) && array_key_exists('row', $invalidRow)) {
                $rows[] = self::alertRowForStorage($invalidRow['row']);
            }
        }

        config_set_path('installedpackages/sinkhole/alerts/item', $rows);
        write_config(Translator::translate('revision_saved_alerts'));
        $this->stateStore->markCompileNeeded();
    }

    /**
     * pfSense Adapter - Save Blocked Services.
     *
     * @param array $configuration - Canonical per-scope service selections.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function saveBlockedServices(array $configuration): void
    {
        config_set_path(
            'installedpackages/sinkhole/services',
            ServiceConfiguration::storage($configuration),
        );
        write_config(Translator::translate('revision_saved_services'));
        $this->stateStore->markCompileNeeded();
    }

    /**
     * pfSense Adapter - Save List Configuration.
     *
     * Persists the complete stable-ID map and normalized allowlist in one pfSense
     * configuration revision.
     *
     * @param array $lists           - Validated list map.
     * @param array $allowedDomains  - Normalized allowed domains.
     * @param array $invalidRows     - Invalid rows to preserve for repair.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function saveListConfiguration(
        array $lists,
        array $allowedDomains,
        array $invalidRows = [],
    ): void
    {
        $storageLists = array_values($lists);

        foreach ($invalidRows as $invalidRow) {
            if (is_array($invalidRow) && array_key_exists('row', $invalidRow)) {
                $storageLists[] = $invalidRow['row'];
            }
        }

        config_set_path('installedpackages/sinkhole/lists/item', $storageLists);
        config_set_path('installedpackages/sinkhole/allowed_domains/item', array_values($allowedDomains));

        write_config(Translator::translate('revision_saved_lists'));
        $this->stateStore->markCompileNeeded();
    }

    /**
     * pfSense Adapter - Save Redirect Configuration.
     *
     * Revalidates the complete record, stores list values under repeated ``item``
     * children, and requests an asynchronous filter reload.
     *
     * @param array{enabled: bool, interfaces: list<string>, exempt_sources: list<string>, exempt_destinations?: list<string>} $configuration - Redirect configuration.
     *
     * @return void
     *
     * @throws InvalidArgumentException When current platform data invalidates a value.
     *
     * @since 1.0.0
     */
    public function saveRedirectConfiguration(array $configuration): void
    {
        $storage = [
            'enabled' => (($configuration['enabled'] ?? false) === true) ? 'on' : '',
            'interfaces' => [
                'item' => (is_array($configuration['interfaces'] ?? null))
                    ? array_values($configuration['interfaces'])
                    : [],
            ],
            'exempt_sources' => [
                'item' => (is_array($configuration['exempt_sources'] ?? null))
                    ? array_values($configuration['exempt_sources'])
                    : [],
            ],
            'exempt_destinations' => [
                'item' => (is_array($configuration['exempt_destinations'] ?? null))
                    ? array_values($configuration['exempt_destinations'])
                    : [],
            ],
        ];
        $partition = RedirectConfiguration::partition(
            $storage,
            $this->getConfiguredInterfaces(),
            $this->getHostNetworkAliases(),
        );

        if (count($partition['invalid_values']) > 0) {
            $invalidValue = $partition['invalid_values'][0];

            throw new ValidationException(
                $invalidValue['reason_key'],
                $invalidValue['reason_arguments'],
            );
        }

        config_set_path('installedpackages/sinkhole/redirect', $storage);
        write_config(Translator::translate('revision_saved_redirect'));

        $this->reloadFilter();
    }

    /**
     * pfSense Adapter - Save Bypass Configuration.
     *
     * Saves the new settings and the existing redirect record in one configuration
     * revision because the interface selection is shared by the whole page.
     *
     * @param array $storage - Complete Bypass storage record.
     * @param array $redirectConfiguration - Validated existing redirect fields.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function saveBypassConfiguration(
        array $storage,
        array $redirectConfiguration,
    ): void {
        $redirectStorage = [
            'enabled' => (($redirectConfiguration['enabled'] ?? false) === true) ? 'on' : '',
            'interfaces' => [
                'item' => is_array($redirectConfiguration['interfaces'] ?? null)
                    ? array_values($redirectConfiguration['interfaces'])
                    : [],
            ],
            'exempt_sources' => [
                'item' => is_array($redirectConfiguration['exempt_sources'] ?? null)
                    ? array_values($redirectConfiguration['exempt_sources'])
                    : [],
            ],
            'exempt_destinations' => [
                'item' => is_array($redirectConfiguration['exempt_destinations'] ?? null)
                    ? array_values($redirectConfiguration['exempt_destinations'])
                    : [],
            ],
        ];
        $redirect = RedirectConfiguration::partition(
            $redirectStorage,
            $this->getConfiguredInterfaces(),
            $this->getHostNetworkAliases(),
        );

        if ($redirect['invalid_values'] !== []) {
            $invalid = $redirect['invalid_values'][0];

            throw new ValidationException(
                $invalid['reason_key'],
                $invalid['reason_arguments'] ?? [],
            );
        }

        $configuration = BypassConfiguration::partition($storage, $redirect['interfaces']);

        if ($configuration['invalid_values'] !== []) {
            $invalid = $configuration['invalid_values'][0];

            throw new ValidationException(
                $invalid['reason_key'],
                $invalid['reason_arguments'] ?? [],
            );
        }

        if ($configuration['discovery'] === BypassConfiguration::DISCOVERY_ADVERTISE) {
            $tls = $this->dnsResolverTlsStatus();

            if (!$tls['enabled']) {
                throw new ValidationException(
                    'bypass_discovery_tls_required',
                    [$tls['reason']],
                );
            }
        }

        config_set_path('installedpackages/sinkhole/redirect', $redirectStorage);
        config_set_path('installedpackages/sinkhole/bypass', $storage);
        $discoveryZoneChanged = $this->setDiscoveryZoneCustomOptions(
            $this->discoveryZoneWanted($configuration)
                && $this->resolverIntegrationConfigured(),
        );

        if ($discoveryZoneChanged) {
            $this->writeAndReconfigure(Translator::translate('revision_saved_bypass'));
        } else {
            write_config(Translator::translate('revision_saved_bypass'));
        }

        $this->stateStore->markCompileNeeded();

        $this->refreshBypassTables($configuration);
        $this->reloadFilter();
    }

    /**
     * pfSense Adapter - Enable DNS Resolver Integration.
     *
     * Takes the single Python slot only when it is empty or already owned by Sinkhole,
     * saves prior values once, installs local data, and reconfigures Unbound.
     *
     * @param bool $runtimeLockHeld - Whether the caller already owns the runtime lock.
     *
     * @return array{active: bool, owner: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}
     *
     * @since 1.0.0
     */
    public function enableDnsResolverIntegration(bool $runtimeLockHeld = false): array
    {
        if ($runtimeLockHeld === false) {
            $lock = new FileLock($this->paths->runtimeLockFile);

            if ($lock->acquire(Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS) === false) {
                throw new RuntimeException('Timed out waiting for the Sinkhole runtime lock.');
            }

            try {
                return $this->enableDnsResolverIntegration(true);
            } finally {
                $lock->release();
            }
        }

        if (config_path_enabled('unbound') === false) {
            if ($this->setDiscoveryZoneCustomOptions(false)) {
                $this->writeAndReconfigure(Translator::translate(
                    'revision_disabled_resolver_integration',
                ));
            }

            return [
                'active' => false,
                'owner' => $this->pythonScriptOwner(),
                'reason' => 'DNS Resolver is disabled.',
                'reason_key' => 'dns_resolver_disabled',
                'reason_arguments' => [],
            ];
        }

        $owner = $this->pythonScriptOwner();

        if ($owner !== '' && $owner !== 'sinkhole') {
            if ($this->setDiscoveryZoneCustomOptions(false)) {
                $this->writeAndReconfigure(Translator::translate(
                    'revision_disabled_resolver_integration',
                ));
            }

            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'The DNS Resolver Python script slot is owned by ' . $owner . '.',
                'reason_key' => 'dns_resolver_python_slot_owned',
                'reason_arguments' => [$owner],
            ];
        }

        if ($owner === '') {
            $unbound = config_get_path('unbound', []);
            $unbound = is_array($unbound) ? $unbound : [];

            $this->stateStore->savePreviousUnboundSettingsOnce([
                'python' => $this->configurationSnapshot($unbound, 'python'),
                'python_order' => $this->configurationSnapshot($unbound, 'python_order'),
                'python_script' => $this->configurationSnapshot($unbound, 'python_script'),
            ]);
        }

        $usesMemoryFileSystem = $this->usesMemoryFileSystem();
        $configurationChanged = $this->installModuleCopies($usesMemoryFileSystem);

        $this->prepareRuntimeStateDirectory();

        if ($usesMemoryFileSystem) {
            $this->restoreRuntimeData();
        } else {
            FileSystem::removeDirectory($this->paths->mirrorRootDirectory);
        }

        $configurationChanged = $this->enableConfigurationFlag('unbound/python')
            || $configurationChanged;
        $configurationChanged = $this->setConfigurationValue('unbound/python_order', 'pre_validator')
            || $configurationChanged;
        $configurationChanged = $this->setConfigurationValue('unbound/python_script', 'sinkhole')
            || $configurationChanged;
        $configurationChanged = $this->syncEarlyShellCommand(true) || $configurationChanged;
        $configurationChanged = $this->setDiscoveryZoneCustomOptions(
            $this->discoveryZoneWanted(),
        ) || $configurationChanged;

        if ($configurationChanged) {
            $this->writeAndReconfigure(Translator::translate(
                'revision_enabled_resolver_integration',
            ));
            $this->reloadFilter();
        }

        return [
            'active' => true,
            'owner' => 'sinkhole',
            'reason' => '',
            'reason_key' => '',
            'reason_arguments' => [],
        ];
    }

    /**
     * pfSense Adapter - Disable DNS Resolver Integration.
     *
     * Restores the saved Python settings when Sinkhole still owns the slot, removes
     * runtime files and the boot command, and reconfigures Unbound after changes.
     *
     * @param bool $runtimeLockHeld - Whether the caller already owns the runtime lock.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function disableDnsResolverIntegration(bool $runtimeLockHeld = false): void
    {
        if ($runtimeLockHeld === false) {
            $lock = new FileLock($this->paths->runtimeLockFile);

            if ($lock->acquire(Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS) === false) {
                throw new RuntimeException('Timed out waiting for the Sinkhole runtime lock.');
            }

            try {
                $this->disableDnsResolverIntegration(true);

                return;
            } finally {
                $lock->release();
            }
        }

        $owner = $this->pythonScriptOwner();
        $configurationChanged = $this->syncEarlyShellCommand(false);
        $configurationChanged = $this->setDiscoveryZoneCustomOptions(false)
            || $configurationChanged;
        $restored = false;

        if ($owner === 'sinkhole') {
            $previous = $this->stateStore->previousUnboundSettings() ?? [
                'python' => [
                    'present' => false,
                    'value' => null,
                ],
                'python_order' => [
                    'present' => false,
                    'value' => null,
                ],
                'python_script' => [
                    'present' => false,
                    'value' => null,
                ],
            ];

            $configurationChanged = $this->restoreConfigurationSnapshot(
                'unbound/python',
                $previous['python'] ?? [],
            ) || $configurationChanged;
            $configurationChanged = $this->restoreConfigurationSnapshot(
                'unbound/python_order',
                $previous['python_order'] ?? [],
            ) || $configurationChanged;
            $configurationChanged = $this->restoreConfigurationSnapshot(
                'unbound/python_script',
                $previous['python_script'] ?? [],
            ) || $configurationChanged;
            $restored = true;
        }

        $runtimeFailure = null;

        try {
            $this->removeRuntimeFiles();
        } catch (Throwable $throwable) {
            $runtimeFailure = $throwable;
        }

        try {
            $this->stateStore->clearDeployment();
        } catch (Throwable $throwable) {
            $runtimeFailure ??= $throwable;
        }

        if ($configurationChanged) {
            $this->writeAndReconfigure(Translator::translate(
                'revision_disabled_resolver_integration',
            ));
            $this->reloadFilter();
        }

        if ($restored) {
            $this->stateStore->clearPreviousUnboundSettings();
        }

        if ($runtimeFailure !== null) {
            throw $runtimeFailure;
        }
    }

    /**
     * pfSense Adapter - Uninstall.
     *
     * Disables integration first and removes persistent package data only when Keep
     * Settings is off.
     *
     * @param bool $keepSettings - Whether lists, settings and state remain installed.
     * @param bool $runtimeLockHeld - Whether the caller already owns the runtime lock.
     * @param int $ipCleanupLockTimeoutSeconds - Maximum update-lock wait for IP cleanup.
     * @param bool $clearIpRuntime - Whether this call owns IP runtime cleanup.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function uninstall(
        bool $keepSettings = true,
        bool $runtimeLockHeld = false,
        int $ipCleanupLockTimeoutSeconds = Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS,
        bool $clearIpRuntime = true,
    ): void
    {
        $firstFailure = null;
        $integrationDisabled = false;

        try {
            $this->disableDnsResolverIntegration($runtimeLockHeld);
            $integrationDisabled = true;
        } catch (Throwable $throwable) {
            $firstFailure = $throwable;
        }

        if ($integrationDisabled) {
            try {
                $this->stateStore->clearPreviousUnboundSettings();
            } catch (Throwable $throwable) {
                $firstFailure ??= $throwable;
            }
        }

        if (!$integrationDisabled) {
            try {
                $this->removeRuntimeFiles();
            } catch (Throwable $throwable) {
                $firstFailure ??= $throwable;
            }
        }

        foreach ([
            $this->paths->alertRepeatStateFile,
            $this->paths->statusFile,
        ] as $path) {
            try {
                FileSystem::removeFixedFile($path);
            } catch (Throwable $throwable) {
                $firstFailure ??= $throwable;
            }
        }

        if ($clearIpRuntime) {
            try {
                $this->clearIpRuntimeData($ipCleanupLockTimeoutSeconds);
            } catch (Throwable $throwable) {
                $firstFailure ??= $throwable;
            }

            try {
                $this->clearBypassRuntimeData($ipCleanupLockTimeoutSeconds);
            } catch (Throwable $throwable) {
                $firstFailure ??= $throwable;
            }
        }

        if ($keepSettings === false) {
            try {
                $this->removePersistentData();
            } catch (Throwable $throwable) {
                $firstFailure ??= $throwable;
            }
        }

        if ($firstFailure !== null) {
            throw $firstFailure;
        }
    }

    /**
     * pfSense Adapter - Remove Persistent Data.
     *
     * Removal calls this only while it owns the update lock, after a stop request has
     * made concurrent jobs leave package-owned lists and state untouched.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function removePersistentData(): void
    {
        $installedPackages = config_get_path('installedpackages', []);

        if (is_array($installedPackages) && isset($installedPackages['sinkhole'])) {
            config_del_path('installedpackages/sinkhole');
            // Keep the removal marker available until pfSense has persisted the deletion.
            write_config(
                Translator::translate('revision_removed_settings'),
                true,
                true,
            );
        }

        FileSystem::removeDirectory($this->paths->persistentDirectory);
    }

    /**
     * pfSense Adapter - DNS Resolver Status.
     *
     * Reports slot ownership separately from active-state checks so the Status page
     * can explain conflicts and missing runtime data.
     *
     * @param bool $enabled - Package enablement.
     *
     * @return array{active: bool, owner: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}
     *
     * @since 1.0.0
     */
    public function dnsResolverStatus(bool $enabled): array
    {
        $owner = $this->pythonScriptOwner();

        if ($enabled === false) {
            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'Sinkhole is disabled.',
                'reason_key' => 'sinkhole_disabled',
                'reason_arguments' => [],
            ];
        }

        if (config_path_enabled('unbound') === false) {
            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'DNS Resolver is disabled.',
                'reason_key' => 'dns_resolver_disabled',
                'reason_arguments' => [],
            ];
        }

        if ($owner !== '' && $owner !== 'sinkhole') {
            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'The DNS Resolver Python script slot is owned by ' . $owner . '.',
                'reason_key' => 'dns_resolver_python_slot_owned',
                'reason_arguments' => [$owner],
            ];
        }

        if ($owner !== 'sinkhole') {
            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'Sinkhole does not own the DNS Resolver Python script slot.',
                'reason_key' => 'sinkhole_not_resolver_owner',
                'reason_arguments' => [],
            ];
        }

        if (config_path_enabled('unbound', 'python') === false) {
            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'DNS Resolver Python mode is disabled.',
                'reason_key' => 'dns_resolver_python_disabled',
                'reason_arguments' => [],
            ];
        }

        if (config_get_path('unbound/python_order', '') !== 'pre_validator') {
            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'Sinkhole is not in the DNS Resolver pre-validator position.',
                'reason_key' => 'sinkhole_resolver_position_invalid',
                'reason_arguments' => [],
            ];
        }

        if (
            FileSystem::isRegularFile($this->paths->runtimeScriptFile) === false
            || $this->runtimeGenerationMissing()
        ) {
            return [
                'active' => false,
                'owner' => $owner,
                'reason' => 'Sinkhole runtime files are unavailable.',
                'reason_key' => 'sinkhole_runtime_unavailable',
                'reason_arguments' => [],
            ];
        }

        return [
            'active' => true,
            'owner' => $owner,
            'reason' => '',
            'reason_key' => '',
            'reason_arguments' => [],
        ];
    }

    /**
     * pfSense Adapter - Python Script Owner.
     *
     * An empty string means the single Resolver slot is available.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function pythonScriptOwner(): string
    {
        $owner = config_get_path('unbound/python_script', '');

        return is_string($owner) ? trim($owner) : '';
    }

    /**
     * pfSense Adapter - Run Updater In Background.
     *
     * The Status page invokes one fixed command through pfSense's background helper;
     * no setting or URL becomes shell text.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function runUpdaterInBackground(): void
    {
        if (function_exists('mwexec_bg') === false) {
            require_once('/etc/inc/util.inc');
        }

        if (function_exists('mwexec_bg') === false) {
            throw new RuntimeException('The pfSense background command helper is unavailable.');
        }

        mwexec_bg($this->paths->command . ' --manual');
    }

    /**
     * pfSense Adapter - Run Apply In Background.
     *
     * Configuration pages and sync enqueue one fixed apply command and return without
     * performing downloads or compilation in the request process.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function runApplyInBackground(): void
    {
        if (function_exists('mwexec_bg') === false) {
            require_once('/etc/inc/util.inc');
        }

        if (function_exists('mwexec_bg') === false) {
            throw new RuntimeException('The pfSense background command helper is unavailable.');
        }

        mwexec_bg($this->paths->command . ' --apply');
    }

    /**
     * pfSense Adapter - Run Client Refresh In Background.
     *
     * Sync hands off the fixed client-map command after configuration work without
     * performing neighbor or lease collection in the request process.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function runClientRefreshInBackground(): void
    {
        if (function_exists('mwexec_bg') === false) {
            require_once('/etc/inc/util.inc');
        }

        if (function_exists('mwexec_bg') === false) {
            throw new RuntimeException('The pfSense background command helper is unavailable.');
        }

        mwexec_bg($this->paths->command . ' --refresh-clients');
    }

    /**
     * pfSense Adapter - Reload Filter.
     *
     * Uses pfSense's event-driven filter configuration entry point so WebGUI and
     * lifecycle requests do not wait for rule generation or pfctl.
     *
     * @return void
     *
     * @throws RuntimeException When the native reload helper is unavailable.
     *
     * @since 1.0.0
     */
    public function reloadFilter(): void
    {
        if (function_exists('filter_configure') === false) {
            require_once('/etc/inc/filter.inc');
        }

        if (function_exists('filter_configure') === false) {
            throw new RuntimeException('The pfSense filter reload helper is unavailable.');
        }

        filter_configure();
    }

    /**
     * pfSense Adapter - Apply IP Anchor.
     *
     * Loads the complete wanted anchor from a root-private file, or flushes the
     * anchor when IP blocking is disabled, invalid, or being removed.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function applyIpAnchor(): string
    {
        $anchorText = $this->ipAnchorText();

        if ($anchorText === '') {
            $this->flushIpAnchor();

            return 'flushed';
        }

        $previousAnchorText = null;

        if (FileSystem::isRegularFile($this->paths->ipAnchorFile)) {
            $contents = file_get_contents($this->paths->ipAnchorFile);

            if (!is_string($contents)) {
                throw new RuntimeException('Unable to read the previous Sinkhole IP anchor.');
            }

            $previousAnchorText = $contents;
        }

        AtomicFile::write($this->paths->ipAnchorFile, $anchorText, 0600);

        $loadCommand = '/sbin/pfctl -a '
            . escapeshellarg(IpRuleConfiguration::ANCHOR)
            . ' -f '
            . escapeshellarg($this->paths->ipAnchorFile);

        if (mwexec($loadCommand) !== 0) {
            if ($previousAnchorText === null) {
                FileSystem::removeFixedFile($this->paths->ipAnchorFile);
            } else {
                AtomicFile::write($this->paths->ipAnchorFile, $previousAnchorText, 0600);
            }

            throw new RuntimeException('Unable to load the Sinkhole IP anchor.');
        }

        AtomicFile::write(
            $this->paths->ipAnchorDigestFile,
            hash('sha256', $anchorText) . PHP_EOL,
            0600,
        );

        return 'loaded';
    }

    /**
     * pfSense Adapter - Apply Bypass Anchor.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function applyBypassAnchor(): string
    {
        $anchorText = $this->bypassAnchorText();

        if ($anchorText === '') {
            $this->flushBypassAnchor();

            return 'flushed';
        }

        $previousAnchorText = null;

        if (FileSystem::isRegularFile($this->paths->bypassAnchorFile)) {
            $contents = file_get_contents($this->paths->bypassAnchorFile);

            if (!is_string($contents)) {
                throw new RuntimeException('Unable to read the previous Sinkhole Bypass anchor.');
            }

            $previousAnchorText = $contents;
        }

        AtomicFile::write($this->paths->bypassAnchorFile, $anchorText, 0600);
        $loadCommand = '/sbin/pfctl -a '
            . escapeshellarg(BypassRuleConfiguration::ANCHOR)
            . ' -f '
            . escapeshellarg($this->paths->bypassAnchorFile);

        if (mwexec($loadCommand) !== 0) {
            if ($previousAnchorText === null) {
                FileSystem::removeFixedFile($this->paths->bypassAnchorFile);
            } else {
                AtomicFile::write($this->paths->bypassAnchorFile, $previousAnchorText, 0600);
            }

            throw new RuntimeException('Unable to load the Sinkhole Bypass anchor.');
        }

        AtomicFile::write(
            $this->paths->bypassAnchorDigestFile,
            hash('sha256', $anchorText) . PHP_EOL,
            0600,
        );

        return 'loaded';
    }

    /**
     * pfSense Adapter - Refresh Bypass Tables.
     *
     * Rebuilds fixed table files from only currently effective lists before the
     * anchor is loaded. Disabling every list-backed kind removes stale files.
     *
     * @param array $configuration - Valid partitioned Bypass configuration.
     * @param BypassListStore|null $store - Optional existing list store.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function refreshBypassTables(
        array $configuration,
        ?BypassListStore $store = null,
    ): void {
        $usesTables = ($configuration['block_encrypted_dns'] ?? false) === true
            || ($configuration['block_tor'] ?? false) === true
            || ($configuration['block_vpn'] ?? false) === true;

        if (!$usesTables) {
            FileSystem::removeFixedFile($this->paths->bypassTableIpv4File);
            FileSystem::removeFixedFile($this->paths->bypassTableIpv6File);
            $this->applyBypassAnchor();

            return;
        }

        $store ??= new BypassListStore($this->paths);
        $networks = [];

        $lists = is_array($configuration['lists'] ?? null)
            ? $configuration['lists']
            : [];

        foreach ($lists as $identifier => $list) {
            if (
                !is_array($list)
                || ($list['enabled'] ?? false) !== true
                || !is_string($identifier)
                || !is_string($list['kind'] ?? null)
                || !BypassConfiguration::kindEnabled($configuration, $list['kind'])
                || !$store->hasSavedCopy($identifier)
            ) {
                continue;
            }

            $networks = array_merge($networks, $store->readNetworks($identifier));

            if (count($networks) > IpNetwork::MAXIMUM_NETWORKS) {
                throw new RuntimeException('The merged Bypass List network limit was exceeded.');
            }
        }

        $blocked = IpNetwork::subtract(
            IpNetwork::merge($networks),
            $this->ipProtectedAddresses(
                is_array($configuration['interfaces'] ?? null)
                    ? $configuration['interfaces']
                    : [],
            ),
        );
        $ipv4 = array_values(array_filter(
            $blocked,
            static fn(string $network): bool => IpNetwork::family($network) === 'ipv4',
        ));
        $ipv6 = array_values(array_filter(
            $blocked,
            static fn(string $network): bool => IpNetwork::family($network) === 'ipv6',
        ));

        AtomicFile::write(
            $this->paths->bypassTableIpv4File,
            ($ipv4 === []) ? '' : implode(PHP_EOL, $ipv4) . PHP_EOL,
            0600,
        );
        AtomicFile::write(
            $this->paths->bypassTableIpv6File,
            ($ipv6 === []) ? '' : implode(PHP_EOL, $ipv6) . PHP_EOL,
            0600,
        );
        $this->applyBypassAnchor();
        $this->replaceBypassTable(
            BypassRuleConfiguration::TABLE_IPV4,
            $this->paths->bypassTableIpv4File,
        );
        $this->replaceBypassTable(
            BypassRuleConfiguration::TABLE_IPV6,
            $this->paths->bypassTableIpv6File,
        );
    }

    /**
     * pfSense Adapter - Flush IP Anchor.
     *
     * Reads rule, table, and anchor state before mutating pf. Empty output or a
     * missing anchor is already flushed, while loaded contents still use pfctl.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function flushIpAnchor(): void
    {
        $rules = [];
        $rulesStatus = 0;
        $rulesCommand = '/sbin/pfctl -a '
            . escapeshellarg(IpRuleConfiguration::ANCHOR)
            . ' -sr 2>/dev/null';

        exec($rulesCommand, $rules, $rulesStatus);

        $tables = [];
        $tablesStatus = 0;
        $tablesCommand = '/sbin/pfctl -a '
            . escapeshellarg(IpRuleConfiguration::ANCHOR)
            . ' -sT 2>/dev/null';

        exec($tablesCommand, $tables, $tablesStatus);

        $listedRules = array_filter(
            $rules,
            static fn(string $rule): bool => trim($rule) !== '',
        );
        $listedTables = array_filter(
            $tables,
            static fn(string $table): bool => trim($table) !== '',
        );
        $anchorIsEmpty = count($listedRules) === 0
            && count($listedTables) === 0;

        if ($anchorIsEmpty === true) {
            FileSystem::removeFixedFile($this->paths->ipAnchorFile);
            FileSystem::removeFixedFile($this->paths->ipAnchorDigestFile);

            return;
        }

        if ($rulesStatus !== 0 || $tablesStatus !== 0) {
            $anchorListCommands = [
                '/sbin/pfctl -a ' . escapeshellarg('sinkhole') . ' -sA 2>/dev/null',
                '/sbin/pfctl -sA 2>/dev/null',
            ];

            foreach ($anchorListCommands as $anchorListCommand) {
                $anchors = [];
                $anchorsStatus = 0;

                exec($anchorListCommand, $anchors, $anchorsStatus);

                if ($anchorsStatus !== 0) {
                    continue;
                }

                $listedAnchors = array_filter(
                    $anchors,
                    static fn(string $anchor): bool => trim($anchor) !== '',
                );
                $anchorIsListed = in_array(
                    IpRuleConfiguration::ANCHOR,
                    array_map('trim', $listedAnchors),
                    true,
                );

                if ($anchorIsListed === false) {
                    FileSystem::removeFixedFile($this->paths->ipAnchorFile);
                    FileSystem::removeFixedFile($this->paths->ipAnchorDigestFile);

                    return;
                }
            }
        }

        $flushCommand = '/sbin/pfctl -a '
            . escapeshellarg(IpRuleConfiguration::ANCHOR)
            . ' -F all';

        if (mwexec($flushCommand) !== 0) {
            throw new RuntimeException('Unable to flush the Sinkhole IP anchor.');
        }

        FileSystem::removeFixedFile($this->paths->ipAnchorFile);
        FileSystem::removeFixedFile($this->paths->ipAnchorDigestFile);
    }

    /**
     * pfSense Adapter - Flush Bypass Anchor.
     *
     * Uses the same absent-anchor checks as the independent IP anchor and keeps all
     * pfctl listing stderr away from package and WebGUI output.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function flushBypassAnchor(): void
    {
        $rules = [];
        $rulesStatus = 0;
        exec(
            '/sbin/pfctl -a '
                . escapeshellarg(BypassRuleConfiguration::ANCHOR)
                . ' -sr 2>/dev/null',
            $rules,
            $rulesStatus,
        );
        $tables = [];
        $tablesStatus = 0;
        exec(
            '/sbin/pfctl -a '
                . escapeshellarg(BypassRuleConfiguration::ANCHOR)
                . ' -sT 2>/dev/null',
            $tables,
            $tablesStatus,
        );
        $listedRules = array_filter(
            $rules,
            static fn(string $rule): bool => trim($rule) !== '',
        );
        $listedTables = array_filter(
            $tables,
            static fn(string $table): bool => trim($table) !== '',
        );

        if ($listedRules === [] && $listedTables === []) {
            FileSystem::removeFixedFile($this->paths->bypassAnchorFile);
            FileSystem::removeFixedFile($this->paths->bypassAnchorDigestFile);

            return;
        }

        if ($rulesStatus !== 0 || $tablesStatus !== 0) {
            foreach ([
                '/sbin/pfctl -a ' . escapeshellarg('sinkhole') . ' -sA 2>/dev/null',
                '/sbin/pfctl -sA 2>/dev/null',
            ] as $anchorListCommand) {
                $anchors = [];
                $anchorsStatus = 0;
                exec($anchorListCommand, $anchors, $anchorsStatus);

                if ($anchorsStatus !== 0) {
                    continue;
                }

                $listedAnchors = array_map('trim', array_filter(
                    $anchors,
                    static fn(string $anchor): bool => trim($anchor) !== '',
                ));

                if (!in_array(BypassRuleConfiguration::ANCHOR, $listedAnchors, true)) {
                    FileSystem::removeFixedFile($this->paths->bypassAnchorFile);
                    FileSystem::removeFixedFile($this->paths->bypassAnchorDigestFile);

                    return;
                }
            }
        }

        $flushCommand = '/sbin/pfctl -a '
            . escapeshellarg(BypassRuleConfiguration::ANCHOR)
            . ' -F all';

        if (mwexec($flushCommand) !== 0) {
            throw new RuntimeException('Unable to flush the Sinkhole Bypass anchor.');
        }

        FileSystem::removeFixedFile($this->paths->bypassAnchorFile);
        FileSystem::removeFixedFile($this->paths->bypassAnchorDigestFile);
    }

    /**
     * pfSense Adapter - Replace IP Table.
     *
     * Updates replace table contents inside the independently managed anchor and
     * never place downloaded list content on a command line.
     *
     * @param string $table - Fixed Sinkhole table name.
     * @param string $file - Fixed table file path.
     *
     * @return bool Whether the table was replaced or created.
     *
     * @since 1.0.0
     */
    public function replaceIpTable(string $table, string $file): bool
    {
        $this->assertIpTable($table, $file);

        $replaceCommand = '/sbin/pfctl -a '
            . escapeshellarg(IpRuleConfiguration::ANCHOR)
            . ' -t '
            . escapeshellarg($table)
            . ' -T replace -f '
            . escapeshellarg($file);

        if (mwexec($replaceCommand) !== 0) {
            throw new RuntimeException('Unable to replace a Sinkhole IP table.');
        }

        return true;
    }

    /**
     * pfSense Adapter - Replace Bypass Table.
     *
     * @param string $table - Fixed Bypass table name.
     * @param string $file - Fixed table file.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function replaceBypassTable(string $table, string $file): bool
    {
        $this->assertBypassTable($table, $file);
        $replaceCommand = '/sbin/pfctl -a '
            . escapeshellarg(BypassRuleConfiguration::ANCHOR)
            . ' -t '
            . escapeshellarg($table)
            . ' -T replace -f '
            . escapeshellarg($file);

        if (mwexec($replaceCommand) !== 0) {
            throw new RuntimeException('Unable to replace a Sinkhole Bypass table.');
        }

        return true;
    }

    /**
     * pfSense Adapter - Reconcile IP Anchor.
     *
     * The minute check reloads immediately when the stored loaded digest differs
     * or pf reports that the wanted anchor has no rules.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function reconcileIpAnchor(): string
    {
        $anchorText = $this->ipAnchorText();
        $status = $this->ipAnchorStatus($anchorText);

        if ($anchorText === '') {
            if (
                $status['anchor_loaded'] === false
                && !FileSystem::isRegularFile($this->paths->ipAnchorFile)
                && !FileSystem::isRegularFile($this->paths->ipAnchorDigestFile)
            ) {
                return 'matching';
            }

            $this->flushIpAnchor();

            return 'reloaded';
        }

        if ($status['loaded']) {
            return 'matching';
        }

        $this->applyIpAnchor();

        return 'reloaded';
    }

    /**
     * pfSense Adapter - Reconcile Bypass Anchor.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function reconcileBypassAnchor(): string
    {
        $anchorText = $this->bypassAnchorText();
        $status = $this->bypassAnchorStatus($anchorText);

        if ($anchorText === '') {
            if (
                !$status['anchor_loaded']
                && !FileSystem::isRegularFile($this->paths->bypassAnchorFile)
                && !FileSystem::isRegularFile($this->paths->bypassAnchorDigestFile)
            ) {
                return 'matching';
            }

            $this->flushBypassAnchor();

            return 'reloaded';
        }

        if ($status['loaded']) {
            return 'matching';
        }

        $this->applyBypassAnchor();

        return 'reloaded';
    }

    /**
     * pfSense Adapter - IP Anchor Status.
     *
     * @param string|null $expectedAnchorText - Current wanted anchor text.
     *
     * @return array{loaded: bool, anchor_loaded: bool, out_of_date: bool, rule_count: int, ipv4_entries: int, ipv6_entries: int}
     *
     * @since 1.0.0
     */
    public function ipAnchorStatus(?string $expectedAnchorText = null): array
    {
        $expectedAnchorText ??= $this->ipAnchorText();
        $anchorLoaded = $this->ipAnchorHasRules();

        $loadedDigest = '';

        if (FileSystem::isRegularFile($this->paths->ipAnchorDigestFile)) {
            $contents = file_get_contents($this->paths->ipAnchorDigestFile);
            $loadedDigest = is_string($contents) ? trim(substr($contents, 0, 128)) : '';
        }

        $expectedDigest = ($expectedAnchorText === '')
            ? ''
            : hash('sha256', $expectedAnchorText);
        $loaded = $anchorLoaded
            && $expectedDigest !== ''
            && $loadedDigest !== ''
            && hash_equals($expectedDigest, $loadedDigest);
        $ruleCount = 0;

        if ($anchorLoaded && FileSystem::isRegularFile($this->paths->ipAnchorFile)) {
            $contents = file_get_contents($this->paths->ipAnchorFile);

            if (is_string($contents)) {
                $ruleCount = count(array_filter(
                    explode("\n", str_replace(["\r\n", "\r"], "\n", $contents)),
                    static fn(string $line): bool => str_starts_with($line, 'block drop '),
                ));
            }
        }

        return [
            'loaded' => $loaded,
            'anchor_loaded' => $anchorLoaded,
            'out_of_date' => ($expectedAnchorText === '') ? $anchorLoaded : !$loaded,
            'rule_count' => $ruleCount,
            'ipv4_entries' => $this->fixedFileLineCount($this->paths->ipTableIpv4File),
            'ipv6_entries' => $this->fixedFileLineCount($this->paths->ipTableIpv6File),
        ];
    }

    /**
     * pfSense Adapter - Bypass Anchor Status.
     *
     * @param string|null $expectedAnchorText - Current wanted anchor text.
     *
     * @return array{loaded: bool, anchor_loaded: bool, out_of_date: bool, rule_count: int, ipv4_entries: int, ipv6_entries: int}
     *
     * @since 1.0.0
     */
    public function bypassAnchorStatus(?string $expectedAnchorText = null): array
    {
        $expectedAnchorText ??= $this->bypassAnchorText();
        $anchorLoaded = $this->bypassAnchorHasRules();
        $loadedDigest = '';

        if (FileSystem::isRegularFile($this->paths->bypassAnchorDigestFile)) {
            $contents = file_get_contents($this->paths->bypassAnchorDigestFile);
            $loadedDigest = is_string($contents) ? trim(substr($contents, 0, 128)) : '';
        }

        $expectedDigest = ($expectedAnchorText === '')
            ? ''
            : hash('sha256', $expectedAnchorText);
        $loaded = $anchorLoaded
            && $expectedDigest !== ''
            && $loadedDigest !== ''
            && hash_equals($expectedDigest, $loadedDigest);
        $ruleCount = 0;

        if ($anchorLoaded && FileSystem::isRegularFile($this->paths->bypassAnchorFile)) {
            $contents = file_get_contents($this->paths->bypassAnchorFile);

            if (is_string($contents)) {
                $ruleCount = count(array_filter(
                    explode("\n", str_replace(["\r\n", "\r"], "\n", $contents)),
                    static fn(string $line): bool => str_starts_with($line, 'block drop '),
                ));
            }
        }

        return [
            'loaded' => $loaded,
            'anchor_loaded' => $anchorLoaded,
            'out_of_date' => ($expectedAnchorText === '') ? $anchorLoaded : !$loaded,
            'rule_count' => $ruleCount,
            'ipv4_entries' => $this->fixedFileLineCount($this->paths->bypassTableIpv4File),
            'ipv6_entries' => $this->fixedFileLineCount($this->paths->bypassTableIpv6File),
        ];
    }

    /**
     * pfSense Adapter - Clear IP Runtime Data.
     *
     * @param int $lockTimeoutSeconds - Maximum update-lock wait.
     * @param bool $updateLockHeld - Whether the caller already owns the update lock.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearIpRuntimeData(
        int $lockTimeoutSeconds = Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS,
        bool $updateLockHeld = false,
    ): void
    {
        $updateLock = null;

        if (!$updateLockHeld) {
            $updateLock = new FileLock($this->paths->updateLockFile);

            if ($updateLock->acquire($lockTimeoutSeconds) === false) {
                throw new RuntimeException('Timed out waiting to clear Sinkhole IP runtime data.');
            }
        }

        try {
            $firstFailure = null;

            try {
                $this->flushIpAnchor();
            } catch (Throwable $throwable) {
                $firstFailure = $throwable;
            }

            foreach ([
                $this->paths->ipTableIpv4File,
                $this->paths->ipTableIpv6File,
                $this->paths->ipAnchorFile,
                $this->paths->ipAnchorDigestFile,
                $this->paths->geoLite2ArchiveFile,
                $this->paths->geoLite2MetadataFile,
                $this->paths->ipStatusFile,
            ] as $path) {
                try {
                    FileSystem::removeFixedFile($path);
                } catch (Throwable $throwable) {
                    $firstFailure ??= $throwable;
                }
            }

            if ($firstFailure !== null) {
                throw $firstFailure;
            }
        } finally {
            if ($updateLock instanceof FileLock) {
                $updateLock->release();
            }
        }
    }

    /**
     * pfSense Adapter - Clear Bypass Runtime Data.
     *
     * @param int $lockTimeoutSeconds - Maximum update-lock wait.
     * @param bool $updateLockHeld - Whether the caller owns the update lock.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearBypassRuntimeData(
        int $lockTimeoutSeconds = Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS,
        bool $updateLockHeld = false,
    ): void {
        $updateLock = null;

        if (!$updateLockHeld) {
            $updateLock = new FileLock($this->paths->updateLockFile);

            if (!$updateLock->acquire($lockTimeoutSeconds)) {
                throw new RuntimeException('Timed out waiting to clear Sinkhole Bypass runtime data.');
            }
        }

        try {
            $firstFailure = null;

            try {
                $this->flushBypassAnchor();
            } catch (Throwable $throwable) {
                $firstFailure = $throwable;
            }

            foreach ([
                $this->paths->bypassTableIpv4File,
                $this->paths->bypassTableIpv6File,
                $this->paths->bypassAnchorFile,
                $this->paths->bypassAnchorDigestFile,
            ] as $path) {
                try {
                    FileSystem::removeFixedFile($path);
                } catch (Throwable $throwable) {
                    $firstFailure ??= $throwable;
                }
            }

            try {
                FileSystem::removeDirectory($this->paths->bypassListDirectory);
            } catch (Throwable $throwable) {
                $firstFailure ??= $throwable;
            }

            if ($firstFailure !== null) {
                throw $firstFailure;
            }
        } finally {
            if ($updateLock instanceof FileLock) {
                $updateLock->release();
            }
        }
    }

    /**
     * pfSense Adapter - IP Status.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function ipStatus(): array
    {
        return (new IpStatusStore($this->paths->ipStatusFile))->read();
    }

    /**
     * pfSense Adapter - Fixed File Line Count.
     *
     * @param string $path - Fixed package-owned file.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private function fixedFileLineCount(string $path): int
    {
        if (!FileSystem::isRegularFile($path)) {
            return 0;
        }

        $handle = @fopen($path, 'rb');

        if ($handle === false) {
            return 0;
        }

        $count = 0;

        try {
            while (($line = fgets($handle)) !== false) {
                if (trim($line) !== '') {
                    $count++;
                }
            }
        } finally {
            fclose($handle);
        }

        return $count;
    }

    /**
     * pfSense Adapter - IP Anchor Has Rules.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function ipAnchorHasRules(): bool
    {
        $statusCommand = '/sbin/pfctl -a '
            . escapeshellarg(IpRuleConfiguration::ANCHOR)
            . ' -sr 2>/dev/null | /usr/bin/grep -q '
            . escapeshellarg('.');

        return mwexec($statusCommand) === 0;
    }

    /** @since 1.0.0 */
    private function bypassAnchorHasRules(): bool
    {
        $statusCommand = '/sbin/pfctl -a '
            . escapeshellarg(BypassRuleConfiguration::ANCHOR)
            . ' -sr 2>/dev/null | /usr/bin/grep -q '
            . escapeshellarg('.');

        return mwexec($statusCommand) === 0;
    }

    /**
     * pfSense Adapter - IP Blocking Wanted.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function ipBlockingWanted(): bool
    {
        if ($this->stateStore->removing()) {
            return false;
        }

        $configuration = $this->getIpConfiguration();

        return $configuration['enabled']
            && $configuration['invalid_values'] === [];
    }

    /** @since 1.0.0 */
    private function bypassBlockingWanted(): bool
    {
        if ($this->stateStore->removing()) {
            return false;
        }

        $configuration = $this->getBypassConfiguration();

        return $configuration['firewall_enabled']
            && $configuration['invalid_values'] === [];
    }

    /** @since 1.0.0 */
    private function assertIpTable(string $table, string $file): void
    {
        $expected = [
            IpRuleConfiguration::TABLE_IPV4 => $this->paths->ipTableIpv4File,
            IpRuleConfiguration::TABLE_IPV6 => $this->paths->ipTableIpv6File,
        ];

        if (!isset($expected[$table]) || $expected[$table] !== $file) {
            throw new InvalidArgumentException('The Sinkhole IP table target is invalid.');
        }
    }

    /** @since 1.0.0 */
    private function assertBypassTable(string $table, string $file): void
    {
        $expected = [
            BypassRuleConfiguration::TABLE_IPV4 => $this->paths->bypassTableIpv4File,
            BypassRuleConfiguration::TABLE_IPV6 => $this->paths->bypassTableIpv6File,
        ];

        if (!isset($expected[$table]) || $expected[$table] !== $file) {
            throw new InvalidArgumentException('The Sinkhole Bypass table target is invalid.');
        }
    }

    /**
     * pfSense Adapter - Clear Redirect Rule Error.
     *
     * Removes pfSense's fixed package-error name with lstat/unlink semantics, so a
     * substituted symbolic link is removed rather than followed.
     *
     * @param string|null $errorPath - Test-only package error path override.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearRedirectRuleError(?string $errorPath = null): void
    {
        FileSystem::removeFixedFile($errorPath ?? $this->paths->redirectRuleErrorFile);
    }

    /**
     * pfSense Adapter - Redirect Rule Status.
     *
     * The generated-rule comment locates Sinkhole's loaded block. When rules are
     * wanted, the extracted block must exactly match the current hook text after
     * line-ending normalization.
     *
     * @param string $rulesPath - pfSense generated rules path.
     * @param string $errorPath - pfSense package parse-error path.
     * @param string|null $expectedRuleText - Current hook text or null to generate it.
     *
     * @return array{loaded: bool, comment_present: bool, out_of_date: bool, parse_error: string, rejected_text: string}
     *
     * @since 1.0.0
     */
    public function redirectRuleStatus(
        string $rulesPath = '/tmp/rules.debug',
        string $errorPath = '/tmp/rules.packages.sinkhole',
        ?string $expectedRuleText = null,
    ): array {
        $rules = '';

        if (FileSystem::isRegularFile($rulesPath)) {
            $contents = file_get_contents($rulesPath);
            $rules = (is_string($contents)) ? $contents : '';
        }

        $commentPresent = str_contains($rules, '# Sinkhole DNS redirect');
        $expectedRuleText ??= $this->redirectRuleText();
        $canonicalExpectedRuleText = $this->canonicalRuleText($expectedRuleText);
        $loadedRuleText = $this->redirectBlockText($rules);
        $loaded = $commentPresent;

        if ($canonicalExpectedRuleText !== '') {
            $loaded = $loadedRuleText !== ''
                && hash_equals(
                    hash('sha256', $canonicalExpectedRuleText),
                    hash('sha256', $loadedRuleText),
                );
        }
        $outOfDate = $commentPresent
            && ($canonicalExpectedRuleText === '' || $loaded === false);
        $parseError = '';
        $rejectedText = '';

        if ($commentPresent === false && FileSystem::isRegularFile($errorPath)) {
            $contents = file_get_contents($errorPath);

            if (is_string($contents)) {
                $boundedContents = substr($contents, 0, 16384);
                $sections = preg_split('/\r?\n\r?\n/', $boundedContents, 2);
                $parseError = trim((is_array($sections)) ? $sections[0] : $boundedContents);
                $rejectedText = (is_array($sections) && isset($sections[1]))
                    ? $this->canonicalRuleText($sections[1])
                    : '';
            } else {
                $parseError = 'pfSense kept an unreadable Sinkhole package rule error file.';
            }
        }

        return [
            'loaded' => $loaded,
            'comment_present' => $commentPresent,
            'out_of_date' => $outOfDate,
            'parse_error' => $parseError,
            'rejected_text' => $rejectedText,
        ];
    }

    /**
     * pfSense Adapter - IP Rule Status.
     *
     * Keeps the package-facing status boundary while reporting the independently
     * loaded anchor rather than text from pfSense's generated main ruleset.
     *
     * @return array{loaded: bool, anchor_loaded: bool, out_of_date: bool, rule_count: int, ipv4_entries: int, ipv6_entries: int}
     *
     * @since 1.0.0
     */
    public function ipRuleStatus(): array
    {
        return $this->ipAnchorStatus();
    }

    /** @since 1.0.0 */
    public function bypassRuleStatus(): array
    {
        return $this->bypassAnchorStatus();
    }

    /**
     * pfSense Adapter - Reconcile Redirect Rules.
     *
     * A non-blocking minute job records the first wanted-versus-loaded mismatch
     * and asks pfSense to reload only when the next check also disagrees.
     *
     * @param string $rulesPath - pfSense generated rules path.
     * @param string $errorPath - pfSense package parse-error path.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function reconcileRedirectRules(
        string $rulesPath = '/tmp/rules.debug',
        string $errorPath = '/tmp/rules.packages.sinkhole',
    ): string {
        $lock = new FileLock($this->paths->redirectCheckLockFile);

        if ($lock->acquire() === false) {
            return 'locked';
        }

        try {
            if (is_subsystem_dirty('packagelock')) {
                FileSystem::removeFixedFile($this->paths->redirectCheckStateFile);

                return 'package-locked';
            }

            $ipReconciliation = $this->reconcileIpAnchor();
            $bypassReconciliation = $this->reconcileBypassAnchor();
            $anchorReconciliation = (
                $ipReconciliation === 'reloaded'
                || $bypassReconciliation === 'reloaded'
            ) ? 'reloaded' : $ipReconciliation;
            $ruleText = $this->redirectRuleText();
            $configuration = $this->getRedirectConfiguration();
            $pauseHash = (count($configuration['invalid_exemptions']) > 0)
                ? $this->redirectInvalidExemptionsHash($configuration['invalid_exemptions'])
                : '';
            $wanted = $ruleText !== '';
            $status = $this->redirectRuleStatus($rulesPath, $errorPath, $ruleText);
            $loaded = $status['loaded'];
            $previous = $this->readRedirectCheckObservation();
            $rejectedText = $status['rejected_text'];

            if (
                $wanted
                && $loaded === false
                && $rejectedText !== ''
                && hash_equals(
                    hash('sha256', $this->canonicalRuleText($ruleText)),
                    hash('sha256', $rejectedText),
                )
            ) {
                $rejectedHash = hash('sha256', $rejectedText);

                if (($previous['rejected_hash'] ?? '') !== $rejectedHash) {
                    $this->log(
                        'pfSense rejected the current Sinkhole package rules; '
                        . 'automatic reloads are paused until the rule text changes.',
                    );
                }

                $this->writeRedirectCheckObservation(
                    null,
                    null,
                    $rejectedHash,
                    $pauseHash,
                );

                return 'rejected';
            }

            if ($wanted === $loaded) {
                $this->writeRedirectCheckObservation(null, null, '', $pauseHash);

                return $anchorReconciliation;
            }

            if (
                $previous === null
                || $previous['wanted'] === null
                || $previous['loaded'] === null
                || $previous['wanted'] === $previous['loaded']
                || $previous['wanted'] !== $wanted
                || $previous['loaded'] !== $loaded
            ) {
                $this->writeRedirectCheckObservation(
                    $wanted,
                    $loaded,
                    $previous['rejected_hash'] ?? '',
                    $pauseHash,
                );

                return 'mismatch';
            }

            $this->reloadFilter();

            $this->writeRedirectCheckObservation(
                null,
                null,
                $previous['rejected_hash'],
                $pauseHash,
            );

            return 'reloaded';
        } finally {
            $lock->release();
        }
    }

    /**
     * pfSense Adapter - Clear Redirect Check Files.
     *
     * Schedule removal waits as requested for an active check, then removes both
     * transient fixed names without touching persistent configuration storage.
     *
     * @param int $lockTimeoutSeconds - Maximum redirect-check lock wait.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function clearRedirectCheckFiles(int $lockTimeoutSeconds = 0): bool
    {
        $lock = new FileLock($this->paths->redirectCheckLockFile);

        if ($lock->acquire($lockTimeoutSeconds) === false) {
            return false;
        }

        $failure = null;

        try {
            FileSystem::removeFixedFile($this->paths->redirectCheckStateFile);
        } catch (Throwable $throwable) {
            $failure = $throwable;
        } finally {
            $lock->release();
        }

        try {
            FileSystem::removeFixedFile($this->paths->redirectCheckLockFile);
        } catch (Throwable $throwable) {
            $failure ??= $throwable;
        }

        if ($failure !== null) {
            throw $failure;
        }

        return true;
    }

    /**
     * pfSense Adapter - Refresh Configuration.
     *
     * A command-line updater re-reads config.xml before rerun snapshots; fresh
     * processes already have current configuration, while pfSense-owned hooks and
     * requests preserve their live unsaved configuration.
     *
     * @return void
     *
     * @throws RuntimeException When pfSense cannot reload its configuration.
     *
     * @since 1.0.0
     */
    public function refreshConfiguration(): void
    {
        if ($this->commandLineMode === false) {
            return;
        }

        global $config;

        if (function_exists('config_read_file')) {
            if (config_read_file(false, false) === false) {
                throw new RuntimeException('Unable to refresh the pfSense configuration.');
            }

            return;
        }

        if (function_exists('parse_config')) {
            $refreshed = parse_config(true);

            if (!is_array($refreshed)) {
                throw new RuntimeException('Unable to refresh the pfSense configuration.');
            }

            $config = $refreshed;
        }
    }

    /**
     * pfSense Adapter - Is Integration Active.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function isIntegrationActive(): bool
    {
        return $this->dnsIntegrationWanted()
            && $this->stateStore->removing() === false
            && $this->pythonScriptOwner() === 'sinkhole'
            && config_path_enabled('unbound', 'python')
            && config_path_enabled('unbound');
    }

    /**
     * pfSense Adapter - DNS Integration Wanted.
     *
     * General DNS blocking and Bypass DNS answers independently justify owning the
     * Resolver module. Firewall-only protections never take the Python slot.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function dnsIntegrationWanted(): bool
    {
        $settings = Settings::fromStorage($this->getSettings());
        $bypass = $this->getBypassConfiguration();

        return $settings['enabled']
            || ($bypass['dns_enabled'] && $bypass['invalid_values'] === []);
    }

    /**
     * pfSense Adapter - Runtime Generation Missing.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function runtimeGenerationMissing(): bool
    {
        $generationPath = FileSystem::resolveManagedGeneration(
            $this->paths->runtimeDataDirectory,
            $this->paths->runtimeStorageDirectory,
        );

        if (
            $generationPath === null
            || FileSystem::isRegularFile($generationPath . '/generation') === false
            || FileSystem::isRegularFile($generationPath . '/manifest.json') === false
        ) {
            return true;
        }

        $manifestContents = file_get_contents($generationPath . '/manifest.json');
        $manifest = is_string($manifestContents)
            ? json_decode($manifestContents, true, 32)
            : null;

        return !is_array($manifest)
            || ($manifest['schema_version'] ?? null) !== Compiler::MANIFEST_SCHEMA_VERSION
            || !is_array($manifest['scopes'] ?? null)
            || !is_array($manifest['scopes']['global'] ?? null)
            || !is_array($manifest['scopes']['networks'] ?? null)
            || !is_array($manifest['scopes']['devices'] ?? null)
            || !is_array($manifest['alerts'] ?? null)
            || !is_array($manifest['bypass'] ?? null)
            || ($manifest['bypass_file'] ?? null) !== 'bypass.tsv'
            || !FileSystem::isRegularFile($generationPath . '/bypass.tsv');
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function updateShouldStop(): bool
    {
        return $this->stateStore->stopRequested() || $this->stateStore->removing();
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function synchronizeIntegrationUnderLock(): void
    {
        $this->stateStore->sweepTemporaryFiles();
        FileSystem::sweepStaleEntries(
            $this->paths->persistentDirectory,
            ['.compile-'],
        );
        FileSystem::sweepStaleEntries(
            $this->paths->runtimeStorageDirectory,
            [
                '.sinkhole-new-',
                '.sinkhole-restore-',
                '.sinkhole-link-',
                '.sinkhole-module-',
                '.sinkhole-atomic-',
            ],
        );
        FileSystem::sweepStaleEntries(
            $this->paths->mirrorRootDirectory,
            ['.sinkhole-atomic-'],
        );
        FileSystem::sweepStaleEntries(
            $this->paths->mirrorStorageDirectory,
            [
                '.sinkhole-new-',
                '.sinkhole-restore-',
                '.sinkhole-link-',
                '.sinkhole-module-',
                '.sinkhole-atomic-',
            ],
        );

        if ($this->stateStore->removing()) {
            $this->disableDnsResolverIntegration(true);

            return;
        }

        if (!$this->dnsIntegrationWanted()) {
            $this->disableDnsResolverIntegration(true);

            return;
        }

        if ($this->integrationCanBeEnabled() === false) {
            $result = $this->enableDnsResolverIntegration(true);

            if ($result['active'] === false) {
                $this->log($result['reason']);
            }

            return;
        }

        $store = new SavedListStore($this->paths);
        $compiler = new Compiler(
            $this->paths,
            $store,
            $this->stateStore,
            null,
            new BypassListStore($this->paths),
        );
        $deploymentStatus = $this->stateStore->deploymentStatus(
            $this->runtimeGenerationMissing(),
        );

        $ownerBeforeDeployment = $this->pythonScriptOwner();
        $compileResult = null;

        if ($compiler->isNeeded() || $deploymentStatus['needed']) {
            $compileResult = $compiler->compile(
                $this->getLists(),
                $this->getAllowedDomains(),
                $this->usesMemoryFileSystem(),
                function (): bool {
                    $this->refreshConfiguration();

                    return $this->integrationCanBeEnabled();
                },
                function (): array {
                    $this->refreshConfiguration();
                    $dnsBlockingEnabled = Settings::fromStorage(
                        $this->getSettings(),
                    )['enabled'];

                    return [
                        'lists' => $dnsBlockingEnabled ? $this->getLists() : [],
                        'allowed_domains' => $this->getAllowedDomains(),
                        'networks' => $dnsBlockingEnabled ? $this->getNetworks() : [],
                        'devices' => $dnsBlockingEnabled ? $this->getDevices() : [],
                        'alerts' => $dnsBlockingEnabled ? $this->getAlerts() : [],
                        'services' => $dnsBlockingEnabled
                            ? $this->getBlockedServices()
                            : [],
                        'bypass' => $this->getBypassConfiguration(),
                    ];
                },
                true,
            );

            $this->clientMap->refresh();

            if (FileSystem::isRegularFile($this->paths->runtimeClientMapFile) === false) {
                throw new RuntimeException(
                    'The Sinkhole client map is unavailable before Resolver enablement.',
                );
            }
        }

        $result = $this->enableDnsResolverIntegration(true);

        if ($result['active'] === false) {
            $this->log($result['reason']);

            return;
        }

        if (
            $ownerBeforeDeployment === ''
            && is_array($compileResult)
            && $compileResult['deployed'] === true
        ) {
            $this->stateStore->clearCacheClearOwed($compileResult['generation']);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function reloadUnboundAfterDeploy(string $generation): void
    {
        if ($generation === '') {
            throw new RuntimeException('The deployed generation is invalid.');
        }

        $deadline = microtime(true) + $this->loadedGenerationWaitSeconds;
        $loaded = false;

        do {
            if (FileSystem::isRegularFile($this->paths->loadedGenerationFile)) {
                $contents = file_get_contents($this->paths->loadedGenerationFile);

                if (is_string($contents) && trim($contents) === $generation) {
                    $loaded = true;
                    break;
                }
            }

            if (microtime(true) >= $deadline) {
                break;
            }

            usleep(250000);
        } while (true);

        if ($loaded === false) {
            $this->log(
                'Timed out waiting for Unbound to load generation '
                . $generation
                . '; reloading it to clear its cache anyway.',
            );
        }

        if (function_exists('mwexec') === false) {
            require_once('/etc/inc/util.inc');
        }

        if (function_exists('mwexec') === false) {
            throw new RuntimeException('The pfSense command helper is unavailable.');
        }

        if (mwexec(self::UNBOUND_RELOAD_COMMAND) !== 0) {
            throw new RuntimeException('Unable to reload Unbound to clear its cache.');
        }
    }

    /**
     * pfSense Adapter - Cron Minute.
     *
     * @return int
     *
     * @since 1.0.0
     */
    public function cronMinute(): int
    {
        return $this->stateStore->cronMinute();
    }

    /**
     * pfSense Adapter - Package Paths.
     *
     * Lifecycle functions share the adapter's fixed production paths; tests use the
     * same accessor to keep every side effect inside a disposable root.
     *
     * @return PackagePaths
     *
     * @since 1.0.0
     */
    public function packagePaths(): PackagePaths
    {
        return $this->paths;
    }

    /**
     * pfSense Adapter - Log.
     *
     * Removes line breaks and bounds operational messages before the system log call.
     *
     * @param string $message - Safe message.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function log(string $message): void
    {
        $safeMessage = substr(str_replace(["\r", "\n"], ' ', $message), 0, 1000);

        log_error('Sinkhole: ' . $safeMessage);
    }

    /**
     * pfSense Adapter - Resolver Active Interfaces.
     *
     * Mirrors Unbound's empty-or-all automatic binding and canonicalizes literal
     * address selectors for comparisons with selected interface addresses.
     *
     * @return array{automatic: bool, values: list<string>}
     *
     * @since 1.0.0
     * @private
     */
    private function resolverActiveInterfaces(): array
    {
        $storedValue = config_get_path('unbound/active_interface', '');
        $rawValues = [];

        if (is_string($storedValue)) {
            if (trim($storedValue) === '') {
                return [
                    'automatic' => true,
                    'values' => [],
                ];
            }

            $rawValues = explode(',', $storedValue);
        } elseif (is_array($storedValue)) {
            $rawValues = array_values($storedValue);
        }

        $values = [];

        foreach ($rawValues as $rawValue) {
            if (!is_string($rawValue)) {
                continue;
            }

            $value = trim($rawValue);

            if ($value === '') {
                continue;
            }

            if ($value === 'all') {
                return [
                    'automatic' => true,
                    'values' => [],
                ];
            }

            $normalizedAddress = $this->normalizeAddress($value);
            $values[($normalizedAddress === '') ? $value : $normalizedAddress] = true;
        }

        return [
            'automatic' => false,
            'values' => array_keys($values),
        ];
    }

    /**
     * pfSense Adapter - Normalize Address.
     *
     * @param string $value - IPv4 or IPv6 address.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function normalizeAddress(string $value): string
    {
        $packed = inet_pton($value);
        $normalized = ($packed === false) ? false : inet_ntop($packed);

        return ($normalized === false) ? '' : strtolower($normalized);
    }

    /**
     * pfSense Adapter - Add Protected Address.
     *
     * Runtime IPv6 gateways can carry an interface scope, which is removed before
     * validation so the address can participate in network subtraction.
     *
     * @param array<string, true> $addresses - Protected addresses.
     * @param mixed $candidate - Candidate address.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function addProtectedAddress(array &$addresses, mixed $candidate): void
    {
        if (!is_string($candidate)) {
            return;
        }

        $address = trim($candidate);
        $scopePosition = strpos($address, '%');

        if ($scopePosition !== false && str_contains($address, ':')) {
            $address = substr($address, 0, $scopePosition);
        }

        if ($address === '' || filter_var($address, FILTER_VALIDATE_IP) === false) {
            return;
        }

        $normalizedAddress = $this->normalizeAddress($address);

        if ($normalizedAddress !== '') {
            $addresses[$normalizedAddress] = true;
        }
    }

    /**
     * pfSense Adapter - Dynamic DNS Server Addresses.
     *
     * pfSense stores DHCP- and PPP-learned DNS servers in runtime files rather than
     * the static system configuration read above.
     *
     * @return list<mixed>
     *
     * @since 1.0.0
     * @private
     */
    private function dynamicDnsServerAddresses(): array
    {
        if (
            $this->protectedAddressHelperAvailable(
                'get_dynamic_nameservers',
                'system.inc',
            ) === false
        ) {
            return [];
        }

        try {
            $dnsServers = get_dynamic_nameservers();
        } catch (Throwable) {
            $this->logProtectedAddressHelperWarningOnce('get_dynamic_nameservers');

            return [];
        }

        if (!is_array($dnsServers)) {
            $this->logProtectedAddressHelperWarningOnce('get_dynamic_nameservers');

            return [];
        }

        return array_values($dnsServers);
    }

    /**
     * pfSense Adapter - Runtime Gateway Addresses.
     *
     * The runtime gateway view resolves dynamic gateway placeholders and includes
     * disabled or inactive failover entries that still need protection.
     *
     * @return list<mixed>
     *
     * @since 1.0.0
     * @private
     */
    private function runtimeGatewayAddresses(): array
    {
        if (
            $this->protectedAddressHelperAvailable(
                'return_gateways_array',
                'gwlb.inc',
            ) === false
        ) {
            return [];
        }

        try {
            $gateways = return_gateways_array(true, false, true);
        } catch (Throwable) {
            $this->logProtectedAddressHelperWarningOnce('return_gateways_array');

            return [];
        }

        if (!is_array($gateways)) {
            $this->logProtectedAddressHelperWarningOnce('return_gateways_array');

            return [];
        }

        $addresses = [];

        foreach ($gateways as $gateway) {
            if (is_array($gateway)) {
                $addresses[] = $gateway['gateway'] ?? '';
            }
        }

        return $addresses;
    }

    /**
     * pfSense Adapter - Protected Address Helper Available.
     *
     * Optional helpers are loaded from pfSense's fixed include names and fail open
     * when an older or incomplete platform does not provide them.
     *
     * @param string $functionName - Helper function name.
     * @param string $includeFile - Fixed pfSense include file.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function protectedAddressHelperAvailable(
        string $functionName,
        string $includeFile,
    ): bool {
        if (function_exists($functionName)) {
            return true;
        }

        try {
            @require_once($includeFile);
        } catch (Throwable) {
            $this->logProtectedAddressHelperWarningOnce($functionName);

            return false;
        }

        if (function_exists($functionName) === false) {
            $this->logProtectedAddressHelperWarningOnce($functionName);

            return false;
        }

        return true;
    }

    /**
     * pfSense Adapter - Log Protected Address Helper Warning Once.
     *
     * One warning identifies each unavailable runtime source while static protected
     * addresses continue through the current table update.
     *
     * @param string $functionName - Helper function name.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function logProtectedAddressHelperWarningOnce(string $functionName): void
    {
        if (isset($this->protectedAddressHelperWarnings[$functionName])) {
            return;
        }

        $this->protectedAddressHelperWarnings[$functionName] = true;

        $this->log(
            'The pfSense '
                . $functionName
                . ' helper is unavailable; its runtime addresses were not added '
                . 'to the protected set.',
        );
    }

    /**
     * pfSense Adapter - Canonical Rule Text.
     *
     * @param string $ruleText - Generated or rejected rule text.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function canonicalRuleText(string $ruleText): string
    {
        return trim(str_replace(["\r\n", "\r"], "\n", $ruleText));
    }

    /**
     * pfSense Adapter - Redirect Block Text.
     *
     * Extracts only the contiguous Sinkhole NAT block from the complete generated
     * ruleset so stale extra or missing lines cannot pass an exact-text check.
     *
     * @param string $rules - Complete generated pfSense rules.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function redirectBlockText(string $rules): string
    {
        $normalizedRules = str_replace(["\r\n", "\r"], "\n", $rules);
        $lines = explode("\n", $normalizedRules);
        $blockLines = [];
        $inBlock = false;

        foreach ($lines as $line) {
            if ($line === '# Sinkhole DNS redirect') {
                $blockLines = [$line];
                $inBlock = true;

                continue;
            }

            if ($inBlock === false) {
                continue;
            }

            if (str_starts_with($line, 'no rdr on ') || str_starts_with($line, 'rdr pass on ')) {
                $blockLines[] = $line;

                continue;
            }

            break;
        }

        return $this->canonicalRuleText(implode("\n", $blockLines));
    }

    /**
     * pfSense Adapter - Redirect Invalid Exemptions Hash.
     *
     * Stable ordering makes one saved invalid set produce one observation even if
     * platform enumeration order changes.
     *
     * @param list<array{field: string, field_key: string, value: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}> $invalidValues - Invalid exemptions.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function redirectInvalidExemptionsHash(array $invalidValues): string
    {
        $canonicalValues = [];

        foreach ($invalidValues as $invalidValue) {
            $canonicalValues[] = ($invalidValue['field'] ?? '')
                . "\0"
                . ($invalidValue['value'] ?? '')
                . "\0"
                . ($invalidValue['reason'] ?? '');
        }

        sort($canonicalValues, SORT_STRING);

        return hash('sha256', implode("\n", $canonicalValues));
    }

    /**
     * pfSense Adapter - Log Redirect Pause Once.
     *
     * @param list<array{field: string, field_key: string, value: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}> $invalidValues - Invalid exemptions.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function logRedirectPauseOnce(array $invalidValues): void
    {
        $pauseHash = $this->redirectInvalidExemptionsHash($invalidValues);
        $previous = $this->readRedirectCheckObservation();

        if (($previous['pause_hash'] ?? '') === $pauseHash) {
            return;
        }

        $this->log(
            'DNS redirect is paused because a saved exempt source or destination is invalid.',
        );
        $this->writeRedirectCheckObservation(
            $previous['wanted'] ?? null,
            $previous['loaded'] ?? null,
            $previous['rejected_hash'] ?? '',
            $pauseHash,
        );
    }

    /**
     * pfSense Adapter - Read Redirect Check Observation.
     *
     * Treats the fixed transient file as untrusted and accepts only bounded mismatch
     * observations and SHA-256 hashes used to suppress repeated operational logs.
     *
     * @return array{wanted: bool|null, loaded: bool|null, rejected_hash: string, pause_hash: string}|null
     *
     * @since 1.0.0
     * @private
     */
    private function readRedirectCheckObservation(): ?array
    {
        $status = @lstat($this->paths->redirectCheckStateFile);

        if (!is_array($status)) {
            return null;
        }

        if (
            ($status['mode'] & 0170000) !== 0100000
            || $status['size'] > 1024
        ) {
            FileSystem::removeFixedFile($this->paths->redirectCheckStateFile);

            return null;
        }

        $contents = file_get_contents($this->paths->redirectCheckStateFile);
        $observation = (is_string($contents))
            ? json_decode($contents, true, 8)
            : null;

        if (
            !is_array($observation)
            || !(is_bool($observation['wanted'] ?? null) || ($observation['wanted'] ?? null) === null)
            || !(is_bool($observation['loaded'] ?? null) || ($observation['loaded'] ?? null) === null)
        ) {
            FileSystem::removeFixedFile($this->paths->redirectCheckStateFile);

            return null;
        }

        $rejectedHash = $observation['rejected_hash'] ?? '';
        $pauseHash = $observation['pause_hash'] ?? '';

        if (
            !is_string($rejectedHash)
            || !is_string($pauseHash)
            || ($rejectedHash !== '' && preg_match('/^[a-f0-9]{64}$/D', $rejectedHash) !== 1)
            || ($pauseHash !== '' && preg_match('/^[a-f0-9]{64}$/D', $pauseHash) !== 1)
        ) {
            FileSystem::removeFixedFile($this->paths->redirectCheckStateFile);

            return null;
        }

        return [
            'wanted' => $observation['wanted'] ?? null,
            'loaded' => $observation['loaded'] ?? null,
            'rejected_hash' => $rejectedHash,
            'pause_hash' => $pauseHash,
        ];
    }

    /**
     * pfSense Adapter - Write Redirect Check Observation.
     *
     * The root cron process atomically replaces one mode-0600 file under
     * "/var/run" so filter reconciliation never writes under "/cf/conf".
     *
     * @param bool|null $wanted - Whether the hook currently wants redirect rules.
     * @param bool|null $loaded - Whether pfSense currently has valid rules loaded.
     * @param string $rejectedHash - Latest rejected-rule hash.
     * @param string $pauseHash - Latest invalid-exemption hash.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function writeRedirectCheckObservation(
        ?bool $wanted,
        ?bool $loaded,
        string $rejectedHash = '',
        string $pauseHash = '',
    ): void {
        if (
            $wanted === null
            && $loaded === null
            && $rejectedHash === ''
            && $pauseHash === ''
        ) {
            FileSystem::removeFixedFile($this->paths->redirectCheckStateFile);

            return;
        }

        $contents = json_encode([
            'wanted' => $wanted,
            'loaded' => $loaded,
            'rejected_hash' => $rejectedHash,
            'pause_hash' => $pauseHash,
        ]);

        if (!is_string($contents)) {
            throw new RuntimeException('Unable to encode the redirect check observation.');
        }

        AtomicFile::write(
            $this->paths->redirectCheckStateFile,
            $contents . PHP_EOL,
            0600,
        );
    }

    /**
     * pfSense Adapter - Integration Can Be Enabled.
     *
     * Sync may deploy data before setting the Python slot only when current settings,
     * Resolver state, and ownership make the immediately following enable safe.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function integrationCanBeEnabled(): bool
    {
        $owner = $this->pythonScriptOwner();

        return $this->dnsIntegrationWanted()
            && config_path_enabled('unbound')
            && ($owner === '' || $owner === 'sinkhole');
    }

    /**
     * pfSense Adapter - Scope Row For Storage.
     *
     * Direct form lists become repeated ``item`` elements while already parsed
     * malformed rows retain their repairable named-child representation.
     *
     * @param mixed $row - Scope row.
     *
     * @return mixed
     *
     * @since 1.0.0
     * @private
     */
    private static function scopeRowForStorage(mixed $row): mixed
    {
        if (!is_array($row)) {
            return $row;
        }

        foreach (['lists', 'allowed_domains'] as $field) {
            if (!array_key_exists($field, $row) || !is_array($row[$field])) {
                continue;
            }

            if (count($row[$field]) === 1 && array_key_exists('item', $row[$field])) {
                continue;
            }

            if (array_is_list($row[$field])) {
                $row[$field] = [
                    'item' => array_values($row[$field]),
                ];
            }
        }

        return $row;
    }

    /**
     * pfSense Adapter - Alert Row For Storage.
     *
     * Free text stays under ``descr`` for pfSense CDATA handling, and every list
     * value uses repeated ``item`` children.
     *
     * @param mixed $row - Alert row.
     *
     * @return mixed
     *
     * @since 1.0.0
     * @private
     */
    private static function alertRowForStorage(mixed $row): mixed
    {
        if (!is_array($row)) {
            return $row;
        }

        if (isset($row['description']) && !isset($row['descr'])) {
            $row['descr'] = $row['description'];
            unset($row['description']);
        }

        if (array_key_exists('any_list', $row)) {
            $row['lists_any'] = $row['any_list'] ? 'on' : '';
            unset($row['any_list']);
        }

        if (array_key_exists('everyone', $row)) {
            $row['clients_everyone'] = $row['everyone'] ? 'on' : '';
            unset($row['everyone']);
        }

        foreach (['notice', 'remote', 'enabled'] as $field) {
            if (array_key_exists($field, $row) && is_bool($row[$field])) {
                $row[$field] = $row[$field] ? 'on' : '';
            }
        }

        foreach (['lists', 'networks', 'devices'] as $field) {
            if (!array_key_exists($field, $row) || !is_array($row[$field])) {
                continue;
            }

            if (count($row[$field]) === 1 && array_key_exists('item', $row[$field])) {
                continue;
            }

            if (array_is_list($row[$field])) {
                $row[$field] = ['item' => array_values($row[$field])];
            }
        }

        return $row;
    }

    /**
     * pfSense Adapter - Install Module Copies.
     *
     * Copies the reviewed installed source into both the persistent boot mirror and
     * Unbound's runtime chroot with appropriate read permissions.
     *
     * @param bool $mirrorRuntime - Whether RAM-disk boot data is required.
     *
     * @return bool
     *
     * @throws RuntimeException When the source or either copy is unavailable.
     *
     * @since 1.0.0
     * @private
     */
    private function installModuleCopies(bool $mirrorRuntime): bool
    {
        if (FileSystem::isRegularFile($this->paths->moduleSourceFile) === false) {
            throw new RuntimeException('The Sinkhole Unbound module is invalid.');
        }

        $source = file_get_contents($this->paths->moduleSourceFile);

        if ($source === false) {
            throw new RuntimeException('Unable to read the Sinkhole Unbound module.');
        }

        FileSystem::ensureOwnedDirectoryIfMissing(
            $this->paths->runtimeRootDirectory,
            0755,
            $this->paths->runtimeUser,
            $this->paths->runtimeGroup,
        );
        FileSystem::ensureOwnedDirectory(
            $this->paths->runtimeStorageDirectory,
            0755,
            $this->paths->storageUser,
            $this->paths->storageGroup,
        );

        $mirrorPath = $this->paths->mirrorRootDirectory . '/sinkhole.py';
        $mirrorSource = $mirrorRuntime && FileSystem::isRegularFile($mirrorPath)
            ? file_get_contents($mirrorPath)
            : false;
        $runtimeSource = FileSystem::isRegularFile($this->paths->runtimeScriptFile)
            ? file_get_contents($this->paths->runtimeScriptFile)
            : false;
        $changed = ($mirrorRuntime && $mirrorSource !== $source) || $runtimeSource !== $source;

        if ($mirrorRuntime && $mirrorSource !== $source) {
            FileSystem::ensureDirectory($this->paths->persistentDirectory, 0700);
            FileSystem::ensureDirectory($this->paths->mirrorRootDirectory, 0700);

            AtomicFile::write($mirrorPath, $source, 0600);
        }

        if ($runtimeSource !== $source) {
            AtomicFile::write(
                $this->paths->runtimeScriptFile,
                $source,
                0644,
                $this->paths->runtimeStorageDirectory,
            );
        }

        return $changed;
    }

    /**
     * pfSense Adapter - Restore Runtime Data.
     *
     * Restores a newer or missing runtime generation from the persistent mirror without
     * touching the network or rebuilding lists during Unbound startup.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function restoreRuntimeData(): void
    {
        $this->restoreRuntimeClientMap();
        $mirrorGenerationPath = FileSystem::resolveManagedGeneration(
            $this->paths->mirrorDataDirectory,
            $this->paths->mirrorStorageDirectory,
        );

        if ($mirrorGenerationPath === null) {
            return;
        }

        $mirrorStamp = $mirrorGenerationPath . '/generation';

        if (FileSystem::isRegularFile($mirrorStamp) === false) {
            return;
        }

        $runtimeGenerationPath = FileSystem::resolveManagedGeneration(
            $this->paths->runtimeDataDirectory,
            $this->paths->runtimeStorageDirectory,
        );
        $runtimeStamp = ($runtimeGenerationPath === null)
            ? ''
            : $runtimeGenerationPath . '/generation';
        $mirrorGeneration = file_get_contents($mirrorStamp);
        $runtimeGeneration = $runtimeStamp !== '' && FileSystem::isRegularFile($runtimeStamp)
            ? file_get_contents($runtimeStamp)
            : false;

        if ($mirrorGeneration !== false && $mirrorGeneration === $runtimeGeneration) {
            return;
        }

        FileSystem::ensureOwnedDirectoryIfMissing(
            $this->paths->runtimeRootDirectory,
            0755,
            $this->paths->runtimeUser,
            $this->paths->runtimeGroup,
        );
        FileSystem::ensureOwnedDirectory(
            $this->paths->runtimeStorageDirectory,
            0755,
            $this->paths->storageUser,
            $this->paths->storageGroup,
        );

        $temporaryPath = FileSystem::createTemporaryDirectory(
            $this->paths->runtimeStorageDirectory,
            '.sinkhole-restore-',
            0755,
        );

        try {
            FileSystem::copyDirectory(
                $mirrorGenerationPath,
                $temporaryPath,
                0755,
                0644,
            );
            FileSystem::activateDirectory(
                $temporaryPath,
                $this->paths->runtimeStorageDirectory,
                $this->paths->runtimeDataDirectory,
            );
        } finally {
            if (is_dir($temporaryPath)) {
                FileSystem::removeDirectory($temporaryPath);
            }
        }
    }

    /**
     * pfSense Adapter - Restore Runtime Client Map.
     *
     * Restores the fixed mirrored client document independently from generation
     * activation so a current generation cannot suppress a missing map repair.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function restoreRuntimeClientMap(): void
    {
        if (FileSystem::isRegularFile($this->paths->mirrorClientMapFile) === false) {
            return;
        }

        $contents = file_get_contents($this->paths->mirrorClientMapFile);

        if ($contents === false) {
            throw new RuntimeException('Unable to read the mirrored client map.');
        }

        $runtimeContents = FileSystem::isRegularFile($this->paths->runtimeClientMapFile)
            ? file_get_contents($this->paths->runtimeClientMapFile)
            : false;

        if ($runtimeContents === $contents) {
            return;
        }

        FileSystem::ensureReplaceableOwnedDirectory(
            $this->paths->runtimeClientDirectory,
            0755,
            $this->paths->storageUser,
            $this->paths->storageGroup,
        );
        if (chmod($this->paths->runtimeClientDirectory, 0755) === false) {
            throw new RuntimeException('Unable to restore the client map directory mode.');
        }

        if (
            $this->paths->storageUser !== ''
            && lchown($this->paths->runtimeClientDirectory, $this->paths->storageUser) === false
        ) {
            throw new RuntimeException('Unable to restore the client map directory owner.');
        }

        if (
            $this->paths->storageGroup !== ''
            && lchgrp($this->paths->runtimeClientDirectory, $this->paths->storageGroup) === false
        ) {
            throw new RuntimeException('Unable to restore the client map directory group.');
        }

        AtomicFile::write($this->paths->runtimeClientMapFile, $contents, 0644);

        if (
            $this->paths->storageUser !== ''
            && lchown($this->paths->runtimeClientMapFile, $this->paths->storageUser) === false
        ) {
            throw new RuntimeException('Unable to restore the client map owner.');
        }

        if (
            $this->paths->storageGroup !== ''
            && lchgrp($this->paths->runtimeClientMapFile, $this->paths->storageGroup) === false
        ) {
            throw new RuntimeException('Unable to restore the client map group.');
        }
    }

    /**
     * pfSense Adapter - Remove Runtime Files.
     *
     * Attempts every fixed runtime and mirror path before reporting the first
     * failure, so one damaged entry cannot strand later package-owned files.
     *
     * @return void
     *
     * @throws Throwable When one or more runtime paths cannot be removed.
     *
     * @since 1.0.0
     * @private
     */
    private function removeRuntimeFiles(): void
    {
        $clientLock = new FileLock($this->paths->clientLockFile);

        if ($clientLock->acquire(Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS) === false) {
            throw new RuntimeException('Timed out waiting for the Sinkhole client refresh lock.');
        }

        try {
            $this->removeRuntimeFilesUnderClientLock();
        } finally {
            $clientLock->release();
        }
    }

    /**
     * pfSense Adapter - Remove Runtime Files Under Client Lock.
     *
     * Once removal owns the refresh lock, an in-flight builder cannot recreate the
     * fixed client-map path after cleanup.
     *
     * @return void
     *
     * @throws Throwable When one or more runtime paths cannot be removed.
     *
     * @since 1.0.0
     * @private
     */
    private function removeRuntimeFilesUnderClientLock(): void
    {
        $firstFailure = null;

        $this->attemptRuntimeRemoval(
            $firstFailure,
            function (): void {
                if (
                    (file_exists($this->paths->runtimeScriptFile) || is_link($this->paths->runtimeScriptFile))
                    && unlink($this->paths->runtimeScriptFile) === false
                ) {
                    throw new RuntimeException('Unable to remove the Sinkhole Unbound module.');
                }
            },
        );
        $this->attemptRuntimeRemoval(
            $firstFailure,
            function (): void {
                FileSystem::removeActivatedDirectory(
                    $this->paths->runtimeDataDirectory,
                    $this->paths->runtimeStorageDirectory,
                );
            },
        );
        $this->attemptRuntimeRemoval(
            $firstFailure,
            function (): void {
                FileSystem::removeDirectory($this->paths->runtimeStorageDirectory);
            },
        );
        $this->attemptRuntimeRemoval(
            $firstFailure,
            function (): void {
                FileSystem::removeDirectory($this->paths->runtimeClientDirectory);
            },
        );
        $this->attemptRuntimeRemoval(
            $firstFailure,
            function (): void {
                FileSystem::removeRuntimeStateDirectory($this->paths->runtimeStateDirectory);
            },
        );
        $this->attemptRuntimeRemoval(
            $firstFailure,
            function (): void {
                FileSystem::removeDirectory($this->paths->mirrorRootDirectory);
            },
        );

        if ($firstFailure !== null) {
            throw $firstFailure;
        }
    }

    /**
     * pfSense Adapter - Attempt Runtime Removal.
     *
     * Cleanup retains the first failure while allowing every later fixed path to be
     * attempted in the same disable operation.
     *
     * @param Throwable|null $firstFailure - First failure.
     * @param callable(): void $operation   - Removal operation.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function attemptRuntimeRemoval(
        ?Throwable &$firstFailure,
        callable $operation,
    ): void {
        try {
            $operation();
        } catch (Throwable $throwable) {
            $firstFailure ??= $throwable;
        }
    }

    /**
     * pfSense Adapter - Synchronize Early Shell Command.
     *
     * Removes every duplicate of Sinkhole's fixed command, then adds exactly one only
     * while enabled on a RAM-disk installation.
     *
     * @param bool $enabled - Package enablement.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function syncEarlyShellCommand(bool $enabled): bool
    {
        $savedCommands = config_get_path('system/earlyshellcmd', []);

        if (is_string($savedCommands) && $savedCommands !== '') {
            $savedCommands = [$savedCommands];
        }

        if (!is_array($savedCommands)) {
            $savedCommands = [];
        }

        $command = $this->paths->earlyShellCommand();
        $commands = [];

        foreach ($savedCommands as $savedCommand) {
            if (is_string($savedCommand) && $savedCommand !== $command) {
                $commands[] = $savedCommand;
            }
        }

        if ($enabled && $this->usesMemoryFileSystem()) {
            $commands[] = $command;
        }

        if ($commands === array_values($savedCommands)) {
            return false;
        }

        config_set_path('system/earlyshellcmd', $commands);

        return true;
    }

    /**
     * pfSense Adapter - Uses Memory File System.
     *
     * Reads pfSense's RAM-disk switch through its configuration API.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function usesMemoryFileSystem(): bool
    {
        if (function_exists('config_path_enabled')) {
            return config_path_enabled('system', 'use_mfs_tmpvar');
        }

        $system = config_get_path('system', []);

        return is_array($system) && isset($system['use_mfs_tmpvar']);
    }

    /**
     * pfSense Adapter - Prepare Runtime State Directory.
     *
     * The module alone writes its loaded-generation marker in this isolated
     * "unbound:unbound" directory.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function prepareRuntimeStateDirectory(): void
    {
        FileSystem::ensureOwnedDirectoryIfMissing(
            $this->paths->runtimeRootDirectory,
            0755,
            $this->paths->runtimeUser,
            $this->paths->runtimeGroup,
        );
        FileSystem::ensureReplaceableOwnedDirectory(
            $this->paths->runtimeStateDirectory,
            0755,
            $this->paths->runtimeUser,
            $this->paths->runtimeGroup,
        );
    }

    /**
     * pfSense Adapter - Discovery Zone Wanted.
     *
     * The managed transparent zone exists only while the package, a valid selected
     * interface, and a Discovery answer mode are all active.
     *
     * @param array|null $configuration - Partitioned Bypass configuration.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function discoveryZoneWanted(?array $configuration = null): bool
    {
        $settings = Settings::fromStorage($this->getSettings());
        $configuration ??= $this->getBypassConfiguration();

        return $settings['enabled']
            && ($configuration['discovery'] ?? BypassConfiguration::DISCOVERY_OFF)
                !== BypassConfiguration::DISCOVERY_OFF
            && ($configuration['interfaces'] ?? []) !== []
            && ($configuration['invalid_values'] ?? []) === [];
    }

    /**
     * pfSense Adapter - Resolver Integration Configured.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function resolverIntegrationConfigured(): bool
    {
        return config_path_enabled('unbound')
            && config_path_enabled('unbound', 'python')
            && $this->pythonScriptOwner() === 'sinkhole';
    }

    /**
     * pfSense Adapter - Decoded Custom Options.
     *
     * A missing or empty value is an empty text box. An invalid stored type or
     * invalid Base64 value is left untouched rather than replacing admin data.
     *
     * @return string|null
     *
     * @since 1.0.0
     * @private
     */
    private function decodedCustomOptions(): ?string
    {
        $encoded = config_get_path('unbound/custom_options', null);

        if ($encoded === null || $encoded === '') {
            return '';
        }

        if (is_string($encoded) === false) {
            return null;
        }

        $decoded = base64_decode($encoded, true);

        return is_string($decoded) ? $decoded : null;
    }

    /**
     * pfSense Adapter - Set Discovery Zone Custom Options.
     *
     * @param bool $wanted - Whether the managed zone block is wanted.
     *
     * @return bool Whether config.xml changed.
     *
     * @since 1.0.0
     * @private
     */
    private function setDiscoveryZoneCustomOptions(bool $wanted): bool
    {
        $customOptions = $this->decodedCustomOptions();

        if ($customOptions === null) {
            return false;
        }

        $reconciled = UnboundCustomOptions::reconcileDiscoveryZone(
            $customOptions,
            $wanted,
        );

        if ($reconciled === $customOptions) {
            return false;
        }

        config_set_path('unbound/custom_options', base64_encode($reconciled));

        return true;
    }

    /**
     * pfSense Adapter - Discovery Zone Present.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function discoveryZonePresent(): bool
    {
        $customOptions = $this->decodedCustomOptions();

        return $customOptions !== null
            && UnboundCustomOptions::hasDiscoveryZone($customOptions);
    }

    /**
     * pfSense Adapter - Configuration Snapshot.
     *
     * Saves presence separately because an enabled pfSense boolean is serialized as
     * an empty element and cannot be distinguished through a string default.
     *
     * @param array  $section - Configuration section.
     * @param string $key     - Direct child key.
     *
     * @return array{present: bool, value: mixed}
     *
     * @since 1.0.0
     * @private
     */
    private function configurationSnapshot(array $section, string $key): array
    {
        return [
            'present' => isset($section[$key]),
            'value' => $section[$key] ?? null,
        ];
    }

    /**
     * pfSense Adapter - Restore Configuration Snapshot.
     *
     * Deletes keys that were absent before Sinkhole and restores present empty
     * elements exactly as pfSense stored them.
     *
     * @param string $path     - Configuration path.
     * @param mixed  $snapshot - Saved presence and value.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function restoreConfigurationSnapshot(string $path, mixed $snapshot): bool
    {
        $segments = explode('/', $path);
        $key = array_pop($segments);
        $sectionPath = implode('/', $segments);
        $section = config_get_path($sectionPath, []);
        $section = is_array($section) ? $section : [];
        $present = is_array($snapshot) && ($snapshot['present'] ?? false) === true;
        $currentlyPresent = is_string($key) && isset($section[$key]);

        if ($present === false) {
            if ($currentlyPresent === false) {
                return false;
            }

            config_del_path($path);

            return true;
        }

        $value = is_array($snapshot) ? ($snapshot['value'] ?? null) : null;

        if ($currentlyPresent && $section[$key] === $value) {
            return false;
        }

        config_set_path($path, $value);

        return true;
    }

    /**
     * pfSense Adapter - Enable Configuration Flag.
     *
     * Matches "services_unbound.php" by storing the boolean result of "isset".
     *
     * @param string $path - Boolean configuration path.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function enableConfigurationFlag(string $path): bool
    {
        if (config_path_enabled('unbound', 'python')) {
            return false;
        }

        config_set_path($path, true);

        return true;
    }

    /**
     * pfSense Adapter - Set Configuration Value.
     *
     * Avoids unnecessary revisions and Unbound restarts when the desired value is
     * already present.
     *
     * @param string $path  - Configuration path.
     * @param mixed  $value - Desired value.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function setConfigurationValue(string $path, mixed $value): bool
    {
        if (config_get_path($path, '') === $value) {
            return false;
        }

        config_set_path($path, $value);

        return true;
    }

    /**
     * pfSense Adapter - Network CIDR.
     *
     * Masks an interface address to its network boundary and rejects IPv4 and IPv6
     * link-local ranges.
     *
     * @param string $address - Interface address.
     * @param int|string $prefix - Prefix length.
     *
     * @return string|null
     *
     * @since 1.0.0
     * @private
     */
    private static function networkCidr(string $address, int|string $prefix): ?string
    {
        try {
            $address = ScopeConfiguration::normalizeIpAddress($address);
        } catch (InvalidArgumentException) {
            return null;
        }

        if (!is_int($prefix) && ctype_digit($prefix) === false) {
            return null;
        }

        $packed = inet_pton($address);

        if ($packed === false) {
            return null;
        }

        $maximum = strlen($packed) * 8;
        $prefix = (int) $prefix;

        if ($prefix < 0 || $prefix > $maximum) {
            return null;
        }

        if (
            (strlen($packed) === 4 && ord($packed[0]) === 169 && ord($packed[1]) === 254)
            || (
                strlen($packed) === 16
                && ord($packed[0]) === 0xfe
                && (ord($packed[1]) & 0xc0) === 0x80
            )
        ) {
            return null;
        }

        $network = '';

        foreach (str_split($packed) as $index => $byte) {
            $remaining = $prefix - ($index * 8);
            $mask = $remaining >= 8 ? 0xff : ($remaining <= 0 ? 0 : (0xff << (8 - $remaining)) & 0xff);
            $network .= chr(ord($byte) & $mask);
        }

        $networkAddress = inet_ntop($network);

        return ($networkAddress === false) ? null : strtolower($networkAddress) . '/' . $prefix;
    }

    /**
     * pfSense Adapter - Write And Reconfigure.
     *
     * Persists one configuration revision before asking pfSense to regenerate and
     * restart the DNS Resolver.
     *
     * @param string $description - Revision description.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function writeAndReconfigure(string $description): void
    {
        write_config($description);
        services_unbound_configure();
    }
}
