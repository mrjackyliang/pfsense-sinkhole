<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\IpNetwork;
use RuntimeException;

require_once(__DIR__ . '/IpNetwork.php');

/**
 * GeoLite2 Country Importer.
 *
 * Verifies MaxMind's SHA-256 document and imports only the three named Country
 * CSV files. Tests can feed invented CSV fixtures directly without licensed data.
 *
 * @since 1.0.0
 */
final class GeoLite2
{
    /** @var int @since 1.0.0 */
    public const MAXIMUM_ARCHIVE_BYTES = 134217728;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_CSV_BYTES = 268435456;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_NETWORKS = 2000000;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_CSV_ROWS = 2000000;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_ARCHIVE_ENTRIES = 10000;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_CSV_ROW_BYTES = 1048576;

    /** @var int @since 1.0.0 */
    private const PROCESS_TIMEOUT_SECONDS = 600;

    /** @var list<string> @since 1.0.0 */
    private const CSV_FILES = [
        'GeoLite2-Country-Locations-en.csv',
        'GeoLite2-Country-Blocks-IPv4.csv',
        'GeoLite2-Country-Blocks-IPv6.csv',
    ];

    /**
     * GeoLite2 Country Importer - Checksum.
     *
     * @param string $document - MaxMind checksum response.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function checksum(string $document): string
    {
        $document = trim($document);

        if (preg_match('/^([a-fA-F0-9]{64})(?:\s+\*?.+)?$/D', $document, $matches) !== 1) {
            throw new RuntimeException('The GeoLite2 checksum document is invalid.');
        }

        return strtolower($matches[1]);
    }

    /**
     * GeoLite2 Country Importer - Verify Archive.
     *
     * @param string $archivePath - Downloaded archive path.
     * @param string $checksumDocument - Downloaded checksum response.
     *
     * @return string Verified SHA-256 value.
     *
     * @since 1.0.0
     */
    public static function verifyArchive(string $archivePath, string $checksumDocument): string
    {
        $size = filesize($archivePath);

        if (!is_int($size) || $size <= 0 || $size > self::MAXIMUM_ARCHIVE_BYTES) {
            throw new RuntimeException('The GeoLite2 archive is empty or exceeds the size limit.');
        }

        $expected = self::checksum($checksumDocument);
        $actual = hash_file('sha256', $archivePath);

        if (!is_string($actual) || !hash_equals($expected, strtolower($actual))) {
            throw new RuntimeException('The GeoLite2 archive checksum does not match.');
        }

        return $actual;
    }

    /**
     * GeoLite2 Country Importer - Import Files.
     *
     * @param string $locationsPath - Invented or extracted locations CSV.
     * @param string $ipv4Path - Invented or extracted IPv4 blocks CSV.
     * @param string $ipv6Path - Invented or extracted IPv6 blocks CSV.
     * @param list<string> $countryCodes - Requested ISO country codes.
     *
     * @return array{ipv4: list<string>, ipv6: list<string>, skipped: int}
     *
     * @since 1.0.0
     */
    public function importFiles(
        string $locationsPath,
        string $ipv4Path,
        string $ipv6Path,
        array $countryCodes,
    ): array {
        $wanted = [];

        foreach ($countryCodes as $countryCode) {
            if (!is_string($countryCode) || preg_match('/^[A-Z]{2}$/D', $countryCode) !== 1) {
                throw new RuntimeException('The requested GeoLite2 country code is invalid.');
            }

            $wanted[$countryCode] = true;
        }

        if ($wanted === []) {
            return ['ipv4' => [], 'ipv6' => [], 'skipped' => 0];
        }

        $locations = $this->locationMap($locationsPath, $wanted);
        $ipv4 = $this->blockNetworks($ipv4Path, $locations, 'ipv4');
        $ipv6 = $this->blockNetworks($ipv6Path, $locations, 'ipv6');

        return [
            'ipv4' => $ipv4['networks'],
            'ipv6' => $ipv6['networks'],
            'skipped' => $ipv4['skipped'] + $ipv6['skipped'],
        ];
    }

    /**
     * GeoLite2 Country Importer - Extract And Import.
     *
     * PHP's ZipArchive is preferred when available. pfSense's fixed unzip binary
     * is used otherwise, without passing archive content through a shell.
     *
     * @param string $archivePath - Verified archive path.
     * @param list<string> $countryCodes - Requested ISO country codes.
     *
     * @return array{ipv4: list<string>, ipv6: list<string>, skipped: int, extractor: string}
     *
     * @since 1.0.0
     */
    public function importArchive(string $archivePath, array $countryCodes): array
    {
        $directory = sys_get_temp_dir() . '/sinkhole-geolite2-' . bin2hex(random_bytes(12));

        if (mkdir($directory, 0700) === false) {
            throw new RuntimeException('Unable to create the GeoLite2 extraction directory.');
        }

        try {
            $extractor = class_exists('ZipArchive')
                ? $this->extractWithZipArchive($archivePath, $directory)
                : $this->extractWithUnzip($archivePath, $directory);
            $result = $this->importFiles(
                $directory . '/' . self::CSV_FILES[0],
                $directory . '/' . self::CSV_FILES[1],
                $directory . '/' . self::CSV_FILES[2],
                $countryCodes,
            );
            $result['extractor'] = $extractor;

            return $result;
        } finally {
            foreach (self::CSV_FILES as $filename) {
                $path = $directory . '/' . $filename;

                if (file_exists($path)) {
                    unlink($path);
                }
            }

            rmdir($directory);
        }
    }

    /** @since 1.0.0 */
    private function locationMap(string $path, array $wanted): array
    {
        [$handle, $header] = $this->openCsv($path);
        $geonameIndex = $this->columnIndex($header, 'geoname_id');
        $countryIndex = $this->columnIndex($header, 'country_iso_code');
        $locations = [];
        $rowCount = 0;

        try {
            while ((
                $row = fgetcsv(
                    $handle,
                    self::MAXIMUM_CSV_ROW_BYTES,
                    ',',
                    '"',
                    '',
                )
            ) !== false) {
                $rowCount++;

                if ($rowCount > self::MAXIMUM_CSV_ROWS) {
                    throw new RuntimeException('The GeoLite2 CSV row count limit was exceeded.');
                }

                $geonameId = trim((string) ($row[$geonameIndex] ?? ''));
                $countryCode = strtoupper(trim((string) ($row[$countryIndex] ?? '')));

                if ($geonameId !== '' && isset($wanted[$countryCode])) {
                    $locations[$geonameId] = true;
                }
            }
        } finally {
            fclose($handle);
        }

        return $locations;
    }

    /** @since 1.0.0 */
    private function blockNetworks(string $path, array $locations, string $family): array
    {
        [$handle, $header] = $this->openCsv($path);
        $networkIndex = $this->columnIndex($header, 'network');
        $geonameIndex = $this->columnIndex($header, 'geoname_id');
        $registeredIndex = $this->columnIndex($header, 'registered_country_geoname_id');
        $networks = [];
        $skipped = 0;
        $rowCount = 0;

        try {
            while ((
                $row = fgetcsv(
                    $handle,
                    self::MAXIMUM_CSV_ROW_BYTES,
                    ',',
                    '"',
                    '',
                )
            ) !== false) {
                $rowCount++;

                if ($rowCount > self::MAXIMUM_CSV_ROWS) {
                    throw new RuntimeException('The GeoLite2 CSV row count limit was exceeded.');
                }

                $geonameId = trim((string) ($row[$geonameIndex] ?? ''));

                if ($geonameId === '') {
                    $geonameId = trim((string) ($row[$registeredIndex] ?? ''));
                }

                if (!isset($locations[$geonameId])) {
                    continue;
                }

                try {
                    $network = IpNetwork::normalize((string) ($row[$networkIndex] ?? ''));

                    if (IpNetwork::family($network) !== $family) {
                        throw new \InvalidArgumentException();
                    }

                    $networks[] = $network;

                    if (count($networks) > self::MAXIMUM_NETWORKS) {
                        throw new RuntimeException('The GeoLite2 network count limit was exceeded.');
                    }
                } catch (\InvalidArgumentException) {
                    $skipped++;
                }
            }
        } finally {
            fclose($handle);
        }

        return ['networks' => IpNetwork::merge($networks), 'skipped' => $skipped];
    }

    /** @since 1.0.0 */
    private function openCsv(string $path): array
    {
        $size = filesize($path);

        if (!is_int($size) || $size <= 0 || $size > self::MAXIMUM_CSV_BYTES) {
            throw new RuntimeException('A GeoLite2 CSV file is empty or exceeds the size limit.');
        }

        $handle = fopen($path, 'rb');

        if ($handle === false) {
            throw new RuntimeException('Unable to read a GeoLite2 CSV file.');
        }

        $header = fgetcsv($handle, self::MAXIMUM_CSV_ROW_BYTES, ',', '"', '');

        if (!is_array($header)) {
            fclose($handle);
            throw new RuntimeException('A GeoLite2 CSV header is invalid.');
        }

        return [$handle, $header];
    }

    /** @since 1.0.0 */
    private function columnIndex(array $header, string $column): int
    {
        $index = array_search($column, $header, true);

        if (!is_int($index)) {
            throw new RuntimeException('A required GeoLite2 CSV column is missing.');
        }

        return $index;
    }

    /** @since 1.0.0 */
    private function extractWithZipArchive(string $archivePath, string $directory): string
    {
        $archive = new \ZipArchive();

        if ($archive->open($archivePath) !== true) {
            throw new RuntimeException('Unable to open the GeoLite2 archive.');
        }

        try {
            $entries = $this->archiveEntries(
                $archive->numFiles,
                static fn(int $index): string|false => $archive->getNameIndex($index),
            );

            foreach ($entries as $filename => $entryName) {
                $stream = $archive->getStream($entryName);

                if (!is_resource($stream)) {
                    throw new RuntimeException('Unable to read a GeoLite2 archive entry.');
                }

                try {
                    $this->copyBounded($stream, $directory . '/' . $filename);
                } finally {
                    fclose($stream);
                }
            }
        } finally {
            $archive->close();
        }

        return 'ZipArchive';
    }

    /** @since 1.0.0 */
    private function extractWithUnzip(string $archivePath, string $directory): string
    {
        $binary = is_executable('/usr/local/bin/unzip')
            ? '/usr/local/bin/unzip'
            : (is_executable('/usr/bin/unzip') ? '/usr/bin/unzip' : '');

        if ($binary === '') {
            throw new RuntimeException('Neither ZipArchive nor pfSense unzip is available.');
        }

        $listing = $this->runProcess([$binary, '-Z1', $archivePath]);
        $names = preg_split('/\r?\n/', trim($listing));
        $names = is_array($names) ? array_values(array_filter($names, 'strlen')) : [];
        $entries = $this->archiveEntries(
            count($names),
            static fn(int $index): string|false => $names[$index] ?? false,
        );

        foreach ($entries as $filename => $entryName) {
            $contents = $this->runProcess([$binary, '-p', $archivePath, $entryName], self::MAXIMUM_CSV_BYTES);
            $destination = $directory . '/' . $filename;

            if (file_put_contents($destination, $contents, LOCK_EX) !== strlen($contents)) {
                throw new RuntimeException('Unable to write a GeoLite2 archive entry.');
            }
        }

        return 'unzip';
    }

    /** @since 1.0.0 */
    private function archiveEntries(int $count, callable $nameAt): array
    {
        if ($count < 0 || $count > self::MAXIMUM_ARCHIVE_ENTRIES) {
            throw new RuntimeException('The GeoLite2 archive entry count limit was exceeded.');
        }

        $entries = [];

        for ($index = 0; $index < $count; $index++) {
            $name = $nameAt($index);

            if (!is_string($name) || str_contains($name, '..') || str_starts_with($name, '/')) {
                continue;
            }

            $basename = basename($name);

            if (in_array($basename, self::CSV_FILES, true)) {
                if (isset($entries[$basename])) {
                    throw new RuntimeException('The GeoLite2 archive contains a duplicate CSV file.');
                }

                $entries[$basename] = $name;
            }
        }

        foreach (self::CSV_FILES as $filename) {
            if (!isset($entries[$filename])) {
                throw new RuntimeException('The GeoLite2 archive is missing a required CSV file.');
            }
        }

        return $entries;
    }

    /** @since 1.0.0 */
    private function copyBounded(mixed $source, string $destination): void
    {
        $target = fopen($destination, 'xb');

        if ($target === false) {
            throw new RuntimeException('Unable to create a GeoLite2 CSV file.');
        }

        $bytes = 0;

        try {
            while (!feof($source)) {
                $chunk = fread($source, 1048576);

                if (!is_string($chunk)) {
                    throw new RuntimeException('Unable to read a GeoLite2 archive entry.');
                }

                if ($chunk === '' && !feof($source)) {
                    throw new RuntimeException('Unable to read a GeoLite2 archive entry.');
                }

                $bytes += strlen($chunk);

                if ($bytes > self::MAXIMUM_CSV_BYTES || fwrite($target, $chunk) !== strlen($chunk)) {
                    throw new RuntimeException('A GeoLite2 CSV file exceeds the size limit.');
                }
            }
        } finally {
            fclose($target);
        }
    }

    /** @since 1.0.0 */
    private function runProcess(array $command, int $maximumBytes = 1048576): string
    {
        if ($maximumBytes <= 0) {
            throw new RuntimeException('The pfSense unzip output limit is invalid.');
        }

        $pipes = [];
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);

        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start pfSense unzip.');
        }

        if (!is_resource($pipes[1] ?? null) || !is_resource($pipes[2] ?? null)) {
            foreach ($pipes as $pipe) {
                if (is_resource($pipe)) {
                    fclose($pipe);
                }
            }

            proc_terminate($process, 9);
            proc_close($process);

            throw new RuntimeException('Unable to read pfSense unzip output.');
        }

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $output = '';
        $error = '';
        $deadline = microtime(true) + self::PROCESS_TIMEOUT_SECONDS;
        $failure = null;

        try {
            while (!feof($pipes[1]) || !feof($pipes[2])) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('pfSense unzip exceeded the time limit.');
                }

                $read = [];

                foreach ([1, 2] as $index) {
                    if (!feof($pipes[$index])) {
                        $read[] = $pipes[$index];
                    }
                }

                if ($read === []) {
                    break;
                }

                $write = null;
                $except = null;
                $selected = stream_select($read, $write, $except, 1);

                if ($selected === false) {
                    throw new RuntimeException('Unable to read pfSense unzip output.');
                }

                if ($selected === 0) {
                    continue;
                }

                foreach ($read as $stream) {
                    do {
                        $chunk = fread($stream, 1048576);

                        if ($chunk === false) {
                            throw new RuntimeException('Unable to read pfSense unzip output.');
                        }

                        if ($stream === $pipes[1]) {
                            if (strlen($output) + strlen($chunk) > $maximumBytes) {
                                throw new RuntimeException(
                                    'A GeoLite2 CSV file exceeds the size limit.',
                                );
                            }

                            $output .= $chunk;
                        } elseif (strlen($error) < 4096) {
                            $error .= substr($chunk, 0, 4096 - strlen($error));
                        }
                    } while ($chunk !== '');
                }
            }
        } catch (\Throwable $throwable) {
            $failure = $throwable;
            proc_terminate($process, 9);
        } finally {
            fclose($pipes[1]);
            fclose($pipes[2]);
            $status = proc_close($process);
        }

        if ($failure !== null) {
            throw $failure;
        }

        if ($status !== 0) {
            throw new RuntimeException('pfSense unzip could not extract the GeoLite2 archive.');
        }

        unset($error);

        return $output;
    }
}
