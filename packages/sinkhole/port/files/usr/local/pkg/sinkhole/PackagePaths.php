<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use InvalidArgumentException;

/**
 * Package Paths.
 *
 * Centralizes every package-owned path so production uses fixed locations while
 * tests can use disposable directories without a pfSense installation.
 *
 * @since 1.0.0
 */
final class PackagePaths
{
    /**
     * Package Paths - Persistent Directory.
     *
     * Lists and integration state live beside the pfSense configuration so they
     * survive reboots and RAM-disk installations.
     *
     * @since 1.0.0
     */
    public const PERSISTENT_DIRECTORY = '/cf/conf/sinkhole';

    /**
     * Package Paths - Updates File.
     *
     * Latest-release metadata stays with package settings so notice de-duplication
     * survives reboots and package upgrades.
     *
     * @since 1.0.0
     */
    public const UPDATES_FILE = self::PERSISTENT_DIRECTORY . '/updates.json';

    /**
     * Package Paths - Update Status File.
     *
     * Detached self-update progress remains readable across WebGUI requests while
     * the package replaces its own installed files.
     *
     * @since 1.0.0
     */
    public const UPDATE_STATUS_FILE = self::PERSISTENT_DIRECTORY . '/update-status.json';

    /**
     * Package Paths - Runtime Root Directory.
     *
     * Unbound treats this directory as its chroot root at run time.
     *
     * @since 1.0.0
     */
    public const RUNTIME_ROOT_DIRECTORY = '/var/unbound';

    /**
     * Package Paths - Module Source File.
     *
     * The port installs the reviewed module source at this fixed package path.
     *
     * @since 1.0.0
     */
    public const MODULE_SOURCE_FILE = '/usr/local/pkg/sinkhole/sinkhole_unbound.py';

    /**
     * Package Paths - Restore Script.
     *
     * pfSense runs this fixed package script before services on RAM-disk systems.
     *
     * @since 1.0.0
     */
    public const RESTORE_SCRIPT = '/usr/local/pkg/sinkhole/restore-runtime.sh';

    /**
     * Package Paths - Command.
     *
     * Cron and the Status page invoke this fixed package command.
     *
     * @since 1.0.0
     */
    public const COMMAND = '/usr/local/sbin/sinkhole';

    /**
     * Package Paths - Update Check Command.
     *
     * The independent GitHub release schedule invokes this fixed command.
     *
     * @since 1.0.0
     */
    public const UPDATE_CHECK_COMMAND = self::COMMAND . ' --check-updates';

    /**
     * Package Paths - Self Update Command.
     *
     * The About page launches this command as a detached package operation.
     *
     * @since 1.0.0
     */
    public const SELF_UPDATE_COMMAND = self::COMMAND . ' --self-update';

    /**
     * Package Paths - Update Schedule Path.
     *
     * Stable randomized cron components live outside the editable settings row.
     *
     * @since 1.0.0
     */
    public const UPDATE_SCHEDULE_PATH = 'installedpackages/sinkhole/update_schedule';

    /**
     * Package Paths - Update Lock File.
     *
     * Download and apply jobs share this long-running transient lock.
     *
     * @since 1.0.0
     */
    public const UPDATE_LOCK_FILE = '/var/run/sinkhole-update.lock';

    /**
     * Package Paths - Runtime Lock File.
     *
     * Compilation activation and Resolver integration share this short lock.
     *
     * @since 1.0.0
     */
    public const RUNTIME_LOCK_FILE = '/var/run/sinkhole-runtime.lock';

    /**
     * Package Paths - Client Refresh Lock File.
     *
     * Client discovery uses an independent non-blocking lock.
     *
     * @since 1.0.0
     */
    public const CLIENT_LOCK_FILE = '/var/run/sinkhole-clients.lock';

    /**
     * Package Paths - Alert Lock File.
     *
     * The minute alert reader uses an independent non-blocking lock.
     *
     * @since 1.0.0
     */
    public const ALERT_LOCK_FILE = '/var/run/sinkhole-alerts.lock';

    /**
     * Package Paths - Redirect Check Lock File.
     *
     * The minute redirect reconciler uses an independent non-blocking lock.
     *
     * @since 1.0.0
     */
    public const REDIRECT_CHECK_LOCK_FILE = '/var/run/sinkhole-redirect-check.lock';

    /**
     * Package Paths - Redirect Check State File.
     *
     * One transient observation lets the minute job require two mismatches before
     * it asks pfSense to reload the filter.
     *
     * @since 1.0.0
     */
    public const REDIRECT_CHECK_STATE_FILE = '/var/run/sinkhole-redirect-check.json';

    /**
     * Package Paths - Redirect Rule Error File.
     *
     * pfSense writes the most recent rejected package rule text at this fixed name.
     *
     * @since 1.0.0
     */
    public const REDIRECT_RULE_ERROR_FILE = '/tmp/rules.packages.sinkhole';

    /**
     * Package Paths - Status File.
     *
     * Frequently changing job status stays on the runtime filesystem so scheduled
     * work never rewrites the persistent configuration filesystem for status alone.
     *
     * @since 1.0.0
     */
    public const STATUS_FILE = '/var/run/sinkhole-status.json';

    /**
     * Package Paths - Status Lock File.
     *
     * @since 1.0.0
     */
    public const STATUS_LOCK_FILE = '/var/run/sinkhole-status.json.lock';

    /**
     * Package Paths - Boot Restore Status File.
     *
     * The early boot restore writes one outcome here for package Sync to relay after
     * pfSense has started syslogd.
     *
     * @since 1.0.0
     */
    public const BOOT_STATUS_FILE = '/var/run/sinkhole-boot-restore';

    /**
     * Package Paths - Alert Repeat State File.
     *
     * @since 1.0.0
     */
    public const ALERT_REPEAT_STATE_FILE = '/var/db/sinkhole-alerts.json';

    /**
     * Package Paths - Catalog Cache Directory.
     *
     * Popular-list catalogs are transient remote data and stay outside the saved
     * pfSense configuration tree.
     *
     * @since 1.0.0
     */
    public const CATALOG_CACHE_DIRECTORY = '/var/db';

    /** @var string @since 1.0.0 */
    public const ADGUARD_HOME_CATALOG_CACHE_FILE = '/var/db/sinkhole-catalog-adguard-home.json';

    /** @var string @since 1.0.0 */
    public const PFBLOCKERNG_CATALOG_CACHE_FILE = '/var/db/sinkhole-catalog-pfblockerng.json';

    /** @var string @since 1.0.0 */
    public const SERVICE_REGISTRY_CACHE_FILE = '/var/db/sinkhole-services-registry.json';

    /** @var string @since 1.0.0 */
    public const IP_TABLE_IPV4_FILE = '/var/db/sinkhole-block-v4.txt';

    /** @var string @since 1.0.0 */
    public const IP_TABLE_IPV6_FILE = '/var/db/sinkhole-block-v6.txt';

    /** @var string @since 1.0.0 */
    public const IP_ANCHOR_FILE = '/var/run/sinkhole-ip-anchor.conf';

    /** @var string @since 1.0.0 */
    public const IP_ANCHOR_DIGEST_FILE = '/var/run/sinkhole-ip-anchor.sha256';

    /** @var string @since 1.0.0 */
    public const GEOLITE2_ARCHIVE_FILE = '/var/db/sinkhole-geolite2-country.zip';

    /** @var string @since 1.0.0 */
    public const GEOLITE2_METADATA_FILE = '/var/db/sinkhole-geolite2-country.json';

    /** @var string @since 1.0.0 */
    public const IP_STATUS_FILE = '/var/run/sinkhole-ip-status.json';

    /** @var string @since 1.0.0 */
    public const BYPASS_TABLE_IPV4_FILE = '/var/db/sinkhole-bypass-v4.txt';

    /** @var string @since 1.0.0 */
    public const BYPASS_TABLE_IPV6_FILE = '/var/db/sinkhole-bypass-v6.txt';

    /** @var string @since 1.0.0 */
    public const BYPASS_ANCHOR_FILE = '/var/run/sinkhole-bypass-anchor.conf';

    /** @var string @since 1.0.0 */
    public const BYPASS_ANCHOR_DIGEST_FILE = '/var/run/sinkhole-bypass-anchor.sha256';

    /**
     * Package Paths - Persistent Directory Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $persistentDirectory;

    /**
     * Package Paths - List Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $listDirectory;

    /**
     * Package Paths - State File.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $stateFile;

    /**
     * Package Paths - Updates File Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $updatesFile;

    /**
     * Package Paths - Update Status File Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $updateStatusFile;

    /**
     * Package Paths - Mirror Root Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $mirrorRootDirectory;

    /**
     * Package Paths - Mirror Data Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $mirrorDataDirectory;

    /**
     * Package Paths - Mirror Storage Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $mirrorStorageDirectory;

    /**
     * Package Paths - Mirror Client Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $mirrorClientDirectory;

    /**
     * Package Paths - Mirror Client Map File.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $mirrorClientMapFile;

    /**
     * Package Paths - Runtime Root Directory Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeRootDirectory;

    /**
     * Package Paths - Runtime Data Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeDataDirectory;

    /**
     * Package Paths - Runtime Storage Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeStorageDirectory;

    /**
     * Package Paths - Runtime State Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeStateDirectory;

    /**
     * Package Paths - Runtime Client Directory.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeClientDirectory;

    /**
     * Package Paths - Runtime Client Map File.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeClientMapFile;

    /**
     * Package Paths - Loaded Generation File.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $loadedGenerationFile;

    /** @var string @since 1.0.0 */
    public readonly string $eventsFile;

    /** @var string @since 1.0.0 */
    public readonly string $eventsProcessingFile;

    /** @var string @since 1.0.0 */
    public readonly string $eventsDroppedFile;

    /**
     * Package Paths - Runtime Script File.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeScriptFile;

    /**
     * Package Paths - Module Source File Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $moduleSourceFile;

    /**
     * Package Paths - Command Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $command;

    /**
     * Package Paths - Update Lock File Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $updateLockFile;

    /**
     * Package Paths - Runtime Lock File Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeLockFile;

    /**
     * Package Paths - Client Lock File Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $clientLockFile;

    /** @var string @since 1.0.0 */
    public readonly string $alertLockFile;

    /** @var string @since 1.0.0 */
    public readonly string $redirectCheckLockFile;

    /** @var string @since 1.0.0 */
    public readonly string $redirectCheckStateFile;

    /** @var string @since 1.0.0 */
    public readonly string $redirectRuleErrorFile;

    /** @var string @since 1.0.0 */
    public readonly string $statusFile;

    /** @var string @since 1.0.0 */
    public readonly string $statusLockFile;

    /** @var string @since 1.0.0 */
    public readonly string $bootStatusFile;

    /** @var string @since 1.0.0 */
    public readonly string $alertRepeatStateFile;

    /** @var string @since 1.0.0 */
    public readonly string $catalogCacheDirectory;

    /** @var string @since 1.0.0 */
    public readonly string $adGuardHomeCatalogCacheFile;

    /** @var string @since 1.0.0 */
    public readonly string $pfBlockerNgCatalogCacheFile;

    /** @var string @since 1.0.0 */
    public readonly string $serviceRegistryCacheFile;

    /** @var string @since 1.0.0 */
    public readonly string $ipListDirectory;

    /** @var string @since 1.0.0 */
    public readonly string $ipTableIpv4File;

    /** @var string @since 1.0.0 */
    public readonly string $ipTableIpv6File;

    /** @var string @since 1.0.0 */
    public readonly string $ipAnchorFile;

    /** @var string @since 1.0.0 */
    public readonly string $ipAnchorDigestFile;

    /** @var string @since 1.0.0 */
    public readonly string $geoLite2ArchiveFile;

    /** @var string @since 1.0.0 */
    public readonly string $geoLite2MetadataFile;

    /** @var string @since 1.0.0 */
    public readonly string $ipStatusFile;

    /** @var string @since 1.0.0 */
    public readonly string $bypassListDirectory;

    /** @var string @since 1.0.0 */
    public readonly string $bypassTableIpv4File;

    /** @var string @since 1.0.0 */
    public readonly string $bypassTableIpv6File;

    /** @var string @since 1.0.0 */
    public readonly string $bypassAnchorFile;

    /** @var string @since 1.0.0 */
    public readonly string $bypassAnchorDigestFile;

    /**
     * Package Paths - Restore Script Instance.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $restoreScript;

    /**
     * Package Paths - Runtime User.
     *
     * Tests may provide an empty value when they pre-create the runtime root.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeUser;

    /**
     * Package Paths - Runtime Group.
     *
     * Tests may provide an empty value when they pre-create the runtime root.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $runtimeGroup;

    /**
     * Package Paths - Storage User.
     *
     * Compiler generations and temporary files stay outside Unbound's ownership.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $storageUser;

    /**
     * Package Paths - Storage Group.
     *
     * @var string
     *
     * @since 1.0.0
     */
    public readonly string $storageGroup;

    /**
     * Package Paths - Constructor.
     *
     * Optional overrides keep filesystem behavior testable while production callers
     * use the fixed package locations above.
     *
     * @param array<string, string> $overrides - Path overrides.
     *
     * @since 1.0.0
     */
    public function __construct(array $overrides = [])
    {
        $this->persistentDirectory = $overrides['persistent_directory'] ?? self::PERSISTENT_DIRECTORY;
        $this->listDirectory = $overrides['list_directory'] ?? $this->persistentDirectory . '/lists';
        $this->stateFile = $overrides['state_file'] ?? $this->persistentDirectory . '/state.json';
        $this->updatesFile = $overrides['updates_file']
            ?? $this->persistentDirectory . '/updates.json';
        $this->updateStatusFile = $overrides['update_status_file']
            ?? $this->persistentDirectory . '/update-status.json';
        $this->mirrorRootDirectory = $overrides['mirror_root_directory']
            ?? $this->persistentDirectory . '/unbound';
        $this->mirrorStorageDirectory = $overrides['mirror_storage_directory']
            ?? $this->mirrorRootDirectory . '/sinkhole.d';
        $this->mirrorDataDirectory = $overrides['mirror_data_directory']
            ?? $this->mirrorRootDirectory . '/sinkhole';
        $this->mirrorClientDirectory = $overrides['mirror_client_directory']
            ?? $this->mirrorRootDirectory . '/sinkhole-clients';
        $this->mirrorClientMapFile = $overrides['mirror_client_map_file']
            ?? $this->mirrorClientDirectory . '/clients.json';
        $this->runtimeRootDirectory = $overrides['runtime_root_directory']
            ?? self::RUNTIME_ROOT_DIRECTORY;
        $this->runtimeStorageDirectory = $overrides['runtime_storage_directory']
            ?? $this->runtimeRootDirectory . '/sinkhole.d';
        $this->runtimeDataDirectory = $overrides['runtime_data_directory']
            ?? $this->runtimeRootDirectory . '/sinkhole';
        $this->runtimeStateDirectory = $overrides['runtime_state_directory']
            ?? $this->runtimeRootDirectory . '/sinkhole-state';
        $this->runtimeClientDirectory = $overrides['runtime_client_directory']
            ?? $this->runtimeRootDirectory . '/sinkhole-clients';
        $this->runtimeClientMapFile = $overrides['runtime_client_map_file']
            ?? $this->runtimeClientDirectory . '/clients.json';
        $this->loadedGenerationFile = $overrides['loaded_generation_file']
            ?? $this->runtimeStateDirectory . '/loaded';
        $this->eventsFile = $overrides['events_file']
            ?? $this->runtimeStateDirectory . '/events';
        $this->eventsProcessingFile = $overrides['events_processing_file']
            ?? $this->runtimeStateDirectory . '/events.processing';
        $this->eventsDroppedFile = $overrides['events_dropped_file']
            ?? $this->runtimeStateDirectory . '/events-dropped';
        $this->runtimeScriptFile = $overrides['runtime_script_file']
            ?? $this->runtimeRootDirectory . '/sinkhole.py';
        $this->moduleSourceFile = $overrides['module_source_file'] ?? self::MODULE_SOURCE_FILE;
        $this->command = $overrides['command'] ?? self::COMMAND;
        $this->updateLockFile = $overrides['update_lock_file'] ?? self::UPDATE_LOCK_FILE;
        $this->runtimeLockFile = $overrides['runtime_lock_file'] ?? self::RUNTIME_LOCK_FILE;
        $this->clientLockFile = $overrides['client_lock_file'] ?? self::CLIENT_LOCK_FILE;
        $this->alertLockFile = $overrides['alert_lock_file'] ?? self::ALERT_LOCK_FILE;
        $this->redirectCheckLockFile = $overrides['redirect_check_lock_file']
            ?? self::REDIRECT_CHECK_LOCK_FILE;
        $this->redirectCheckStateFile = $overrides['redirect_check_state_file']
            ?? self::REDIRECT_CHECK_STATE_FILE;
        $this->redirectRuleErrorFile = $overrides['redirect_rule_error_file']
            ?? self::REDIRECT_RULE_ERROR_FILE;
        $this->statusFile = $overrides['status_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-status.json'
                : self::STATUS_FILE);
        $this->statusLockFile = $overrides['status_lock_file']
            ?? (isset($overrides['status_file']) || isset($overrides['runtime_root_directory'])
                ? $this->statusFile . '.lock'
                : self::STATUS_LOCK_FILE);
        $this->bootStatusFile = $overrides['boot_status_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-boot-restore'
                : self::BOOT_STATUS_FILE);
        $this->alertRepeatStateFile = $overrides['alert_repeat_state_file']
            ?? self::ALERT_REPEAT_STATE_FILE;
        $this->catalogCacheDirectory = $overrides['catalog_cache_directory']
            ?? self::CATALOG_CACHE_DIRECTORY;
        $this->adGuardHomeCatalogCacheFile = $overrides['adguard_home_catalog_cache_file']
            ?? $this->catalogCacheDirectory . '/sinkhole-catalog-adguard-home.json';
        $this->pfBlockerNgCatalogCacheFile = $overrides['pfblockerng_catalog_cache_file']
            ?? $this->catalogCacheDirectory . '/sinkhole-catalog-pfblockerng.json';
        $this->serviceRegistryCacheFile = $overrides['service_registry_cache_file']
            ?? $this->catalogCacheDirectory . '/sinkhole-services-registry.json';
        $this->ipListDirectory = $overrides['ip_list_directory']
            ?? $this->persistentDirectory . '/ip-lists';
        $this->ipTableIpv4File = $overrides['ip_table_ipv4_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-block-v4.txt'
                : self::IP_TABLE_IPV4_FILE);
        $this->ipTableIpv6File = $overrides['ip_table_ipv6_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-block-v6.txt'
                : self::IP_TABLE_IPV6_FILE);
        $this->ipAnchorFile = $overrides['ip_anchor_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-ip-anchor.conf'
                : self::IP_ANCHOR_FILE);
        $this->ipAnchorDigestFile = $overrides['ip_anchor_digest_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-ip-anchor.sha256'
                : self::IP_ANCHOR_DIGEST_FILE);
        $this->geoLite2ArchiveFile = $overrides['geolite2_archive_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-geolite2-country.zip'
                : self::GEOLITE2_ARCHIVE_FILE);
        $this->geoLite2MetadataFile = $overrides['geolite2_metadata_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-geolite2-country.json'
                : self::GEOLITE2_METADATA_FILE);
        $this->ipStatusFile = $overrides['ip_status_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-ip-status.json'
                : self::IP_STATUS_FILE);
        $this->bypassListDirectory = $overrides['bypass_list_directory']
            ?? $this->persistentDirectory . '/bypass-lists';
        $this->bypassTableIpv4File = $overrides['bypass_table_ipv4_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-bypass-v4.txt'
                : self::BYPASS_TABLE_IPV4_FILE);
        $this->bypassTableIpv6File = $overrides['bypass_table_ipv6_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-bypass-v6.txt'
                : self::BYPASS_TABLE_IPV6_FILE);
        $this->bypassAnchorFile = $overrides['bypass_anchor_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-bypass-anchor.conf'
                : self::BYPASS_ANCHOR_FILE);
        $this->bypassAnchorDigestFile = $overrides['bypass_anchor_digest_file']
            ?? (isset($overrides['runtime_root_directory'])
                ? $this->runtimeRootDirectory . '/sinkhole-bypass-anchor.sha256'
                : self::BYPASS_ANCHOR_DIGEST_FILE);
        $this->restoreScript = $overrides['restore_script'] ?? self::RESTORE_SCRIPT;
        $this->runtimeUser = $overrides['runtime_user'] ?? 'unbound';
        $this->runtimeGroup = $overrides['runtime_group'] ?? 'unbound';
        $this->storageUser = $overrides['storage_user'] ?? 'root';
        $this->storageGroup = $overrides['storage_group'] ?? 'wheel';
    }

    /**
     * Package Paths - List File.
     *
     * A stable list identifier determines the normalized copy's filename.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function listFile(string $identifier): string
    {
        $this->assertIdentifier($identifier);

        return $this->listDirectory . '/' . $identifier . '.domains';
    }

    /**
     * Package Paths - Metadata File.
     *
     * Each normalized list has a sibling metadata document keyed by the same ID.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function metadataFile(string $identifier): string
    {
        $this->assertIdentifier($identifier);

        return $this->listDirectory . '/' . $identifier . '.json';
    }

    /**
     * Package Paths - IP List File.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function ipListFile(string $identifier): string
    {
        $this->assertIdentifier($identifier);

        return $this->ipListDirectory . '/' . $identifier . '.networks';
    }

    /**
     * Package Paths - IP Metadata File.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function ipMetadataFile(string $identifier): string
    {
        $this->assertIdentifier($identifier);

        return $this->ipListDirectory . '/' . $identifier . '.json';
    }

    /**
     * Package Paths - Bypass List File.
     *
     * One atomic normalized stream contains both domain and network records.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function bypassListFile(string $identifier): string
    {
        $this->assertIdentifier($identifier);

        return $this->bypassListDirectory . '/' . $identifier . '.entries';
    }

    /**
     * Package Paths - Bypass Metadata File.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function bypassMetadataFile(string $identifier): string
    {
        $this->assertIdentifier($identifier);

        return $this->bypassListDirectory . '/' . $identifier . '.json';
    }

    /**
     * Package Paths - Early Shell Command.
     *
     * The fixed command restores the mirrored script and data before Unbound starts
     * when pfSense stores "/var" on a RAM disk.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function earlyShellCommand(): string
    {
        return $this->restoreScript;
    }

    /**
     * Package Paths - Assert Identifier.
     *
     * Rejecting path separators and arbitrary names keeps all list files inside the
     * package-owned directory.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return void
     *
     * @throws InvalidArgumentException When the identifier is invalid.
     *
     * @since 1.0.0
     * @private
     */
    private function assertIdentifier(string $identifier): void
    {
        if (preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1) {
            throw new InvalidArgumentException('Invalid list identifier.');
        }
    }
}
