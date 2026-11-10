<?php

declare(strict_types=1);

$classDirectory = __DIR__ . '/../port/files/usr/local/pkg/sinkhole';
$classFiles = glob($classDirectory . '/*.php');

if (!is_array($classFiles) || count($classFiles) === 0) {
    throw new RuntimeException('No Sinkhole class files were found.');
}

sort($classFiles, SORT_STRING);

foreach ($classFiles as $classFile) {
    require_once($classFile);
}

fwrite(STDOUT, 'PASS require every Sinkhole class file' . PHP_EOL);
