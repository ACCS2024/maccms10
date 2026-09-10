<?php
declare(strict_types=1);
namespace app\common\util;

/** Bounded XLSX import only. No archive extraction, formula evaluation or external XML loading. */
final class XlsxTableReader
{
    private const NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
    private const REL_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
    private const PACKAGE_NS = 'http://schemas.openxmlformats.org/package/2006/relationships';
    private const MAX_ENTRIES = 512;
    private const MAX_NODES = 1000000;
    private const MAX_CELL_BYTES = 8388608;
    private int $xmlRemaining = BulkTableIo::MAX_IMPORT_BYTES;
    private int $textRemaining = BulkTableIo::MAX_IMPORT_BYTES;

    public static function read(string $path): array
    {
        if (!class_exists(\ZipArchive::class) || !class_exists(\XMLReader::class)) {
            throw new \RuntimeException('XLSX import requires ZIP and XMLReader');
        }
        return (new self())->parse($path);
    }

    private function parse(string $path): array
    {
        if (str_contains($path, "\0") || str_contains($path, '://') || !is_file($path)) {
            throw new \RuntimeException('XLSX source must be a local regular file');
        }
        $directory = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR).'/maccms-xlsx-'.bin2hex(random_bytes(16));
        if (!@mkdir($directory, 0700)) { throw new \RuntimeException('Cannot prepare XLSX import'); }
        $snapshot = $directory.'/source.zip'; $zip = null; $opened = false;
        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();
        try {
            $input = @fopen($path, 'rb');
            if ($input === false) { throw new \RuntimeException('Cannot read XLSX'); }
            try {
                $stat = fstat($input);
                if ($stat === false || ($stat['mode'] & 0170000) !== 0100000 || $stat['size'] > BulkTableIo::MAX_IMPORT_BYTES) { throw new \RuntimeException('XLSX source is not a regular file'); }
                $output = @fopen($snapshot, 'xb');
                if ($output === false) { throw new \RuntimeException('Cannot snapshot XLSX'); }
                try {
                    $copied = @stream_copy_to_stream($input, $output, BulkTableIo::MAX_IMPORT_BYTES + 1);
                    if ($copied === false || $copied > BulkTableIo::MAX_IMPORT_BYTES || $copied < 22) {
                        throw new \RuntimeException('XLSX exceeds the archive byte budget or is incomplete');
                    }
                } finally { fclose($output); }
            } finally { fclose($input); }
            // Check the bounded directory count before libzip allocates its entry objects.
            self::checkDirectory($snapshot, $copied);
            $zip = new \ZipArchive();
            if (@$zip->open($snapshot, \ZipArchive::RDONLY | \ZipArchive::CHECKCONS) !== true) {
                throw new \RuntimeException('Cannot open XLSX archive');
            }
            $opened = true;
            if ($zip->numFiles > self::MAX_ENTRIES) { throw new \RuntimeException('XLSX has too many parts'); }
            $names = [];
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $name = $zip->getNameIndex($i);
                if ($name === false || strlen($name) > 1024 || isset($names[$name])) {
                    throw new \RuntimeException('Ambiguous XLSX part directory');
                }
                $names[$name] = true;
            }
            $sheet = 'xl/worksheets/sheet1.xml';
            if (!isset($names[$sheet])) { $sheet = $this->sheetPath($zip); }
            $sharedXml = $this->part($zip, 'xl/sharedStrings.xml', false);
            $shared = $sharedXml === null ? [] : $this->sharedStrings($sharedXml);
            unset($sharedXml);
            return $this->worksheet($this->part($zip, $sheet), $shared);
        } finally {
            try { if ($opened) { $zip->close(); } }
            finally {
                @unlink($snapshot); @rmdir($directory);
                libxml_clear_errors(); libxml_use_internal_errors($previous);
            }
        }
    }

    private static function checkDirectory(string $path, int $size): void
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) { throw new \RuntimeException('Cannot inspect XLSX directory'); }
        try {
            $length = min($size, 65557);
            if (fseek($handle, $size - $length) !== 0) { throw new \RuntimeException('Cannot seek XLSX directory'); }
            $tail = stream_get_contents($handle, $length);
        } finally { fclose($handle); }
        $offset = null; $search = 0;
        if ($tail !== false) {
            while (($candidate = strpos($tail, "PK\x05\x06", $search)) !== false) {
                $search = $candidate + 4;
                if (strlen($tail) - $candidate >= 22) {
                    $comment = unpack('vlength', substr($tail, $candidate + 20, 2));
                    if ($candidate + 22 + $comment['length'] === strlen($tail)) { $offset = $candidate; }
                }
            }
        }
        if ($offset === null) { throw new \RuntimeException('Missing XLSX directory'); }
        $end = unpack('vdisk/vcentral_disk/ventries_disk/ventries/Vcentral_size/Vcentral_offset/vcomment', substr($tail, $offset + 4, 18));
        if ($end === false || $end['disk'] !== 0 || $end['central_disk'] !== 0
            || $end['entries_disk'] !== $end['entries'] || $end['entries'] > self::MAX_ENTRIES
            || $end['central_size'] > 1024 * 1024 || $offset + 22 + $end['comment'] !== strlen($tail)
            || $end['central_offset'] + $end['central_size'] !== $size - $length + $offset) {
            throw new \RuntimeException('Unsupported or oversized XLSX directory');
        }
        $handle = fopen($path, 'rb');
        if ($handle === false) { throw new \RuntimeException('Cannot inspect XLSX entries'); }
        try {
            if (fseek($handle, $end['central_offset']) !== 0) { throw new \RuntimeException('Cannot seek XLSX entries'); }
            $central = stream_get_contents($handle, $end['central_size']);
        } finally { fclose($handle); }
        if ($central === false || strlen($central) !== $end['central_size']) { throw new \RuntimeException('Incomplete XLSX entries'); }
        $cursor = 0; $count = 0; $names = [];
        while ($cursor < strlen($central)) {
            if (++$count > $end['entries'] || $count > self::MAX_ENTRIES || strlen($central) - $cursor < 46
                || substr($central, $cursor, 4) !== "PK\x01\x02") { throw new \RuntimeException('Invalid XLSX entry count or signature'); }
            $lengths = unpack('vname/vextra/vcomment/vdisk', substr($central, $cursor + 28, 8));
            $local = unpack('Voffset', substr($central, $cursor + 42, 4));
            $next = $cursor + 46 + $lengths['name'] + $lengths['extra'] + $lengths['comment'];
            if ($lengths['name'] < 1 || $lengths['name'] > 1024 || $lengths['disk'] !== 0
                || $next > strlen($central) || $local['offset'] >= $end['central_offset']) {
                throw new \RuntimeException('Invalid XLSX entry bounds');
            }
            $name = substr($central, $cursor + 46, $lengths['name']);
            if (isset($names[$name])) { throw new \RuntimeException('Duplicate XLSX part'); }
            $names[$name] = true; $cursor = $next;
        }
        if ($count !== $end['entries']) { throw new \RuntimeException('XLSX directory count does not match its entries'); }
    }

    private function part(\ZipArchive $zip, string $name, bool $required = true): ?string
    {
        $stat = $zip->statName($name);
        if ($stat === false) {
            if (!$required) { return null; }
            throw new \RuntimeException('Missing XLSX part');
        }
        if (!is_int($stat['size']) || $stat['size'] < 1 || $stat['size'] > $this->xmlRemaining
            || ($stat['encryption_method'] ?? 0) !== 0) {
            throw new \RuntimeException('XLSX XML part exceeds its budget or is encrypted');
        }
        $stream = $zip->getStream($name);
        if ($stream === false) { throw new \RuntimeException('Cannot read XLSX part'); }
        try { $xml = @stream_get_contents($stream, $this->xmlRemaining + 1); }
        finally { fclose($stream); }
        if ($xml === false || strlen($xml) !== $stat['size']
            || hash('crc32b', $xml) !== sprintf('%08x', $stat['crc'] & 0xffffffff)) {
            throw new \RuntimeException('XLSX part bytes do not match its directory');
        }
        $this->xmlRemaining -= strlen($xml);
        return $xml;
    }

    /** Reject declarations before libxml can allocate a DTD; normalize the XML byte encoding first. */
    private static function prepareXml(string $xml): string
    {
        $encoding = 'UTF-8'; $bom = 0;
        foreach (["\x00\x00\xFE\xFF"=>'UTF-32BE', "\xFF\xFE\x00\x00"=>'UTF-32LE',
            "\xFE\xFF"=>'UTF-16BE', "\xFF\xFE"=>'UTF-16LE', "\xEF\xBB\xBF"=>'UTF-8'] as $prefix=>$candidate) {
            if (str_starts_with($xml, $prefix)) { $encoding = $candidate; $bom = strlen($prefix); break; }
        }
        if ($bom === 0) {
            foreach (["\x00\x00\x00<"=>'UTF-32BE', "<\x00\x00\x00"=>'UTF-32LE',
                "\x00<"=>'UTF-16BE', "<\x00"=>'UTF-16LE'] as $prefix=>$candidate) {
                if (str_starts_with($xml, $prefix)) { $encoding = $candidate; break; }
            }
        }
        if ($bom > 0) { $xml = substr($xml, $bom); }
        if ($encoding !== 'UTF-8') {
            if (!function_exists('iconv') || ($converted = @iconv($encoding, 'UTF-8', $xml)) === false) {
                throw new \RuntimeException('Cannot decode XLSX XML encoding');
            }
            $xml = $converted;
        }
        if (strlen($xml) > BulkTableIo::MAX_IMPORT_BYTES || str_contains($xml, "\0") || preg_match('//u', $xml) !== 1) {
            throw new \RuntimeException('Invalid or oversized XLSX XML text');
        }
        if (preg_match('/\A<\?xml(?:\s|\?)/', $xml)) {
            $end = strpos($xml, '?>');
            if ($end === false || $end > 8192) { throw new \RuntimeException('Invalid XLSX XML declaration'); }
            if (preg_match('/\bencoding\s*=\s*([\'"])([^\'"]+)\1/i', substr($xml, 0, $end), $match, PREG_OFFSET_CAPTURE)) {
                $declared = strtoupper($match[2][0]);
                $allowed = $encoding === 'UTF-8' ? ['UTF-8', 'UTF8', 'US-ASCII'] : [$encoding, substr($encoding, 0, 6)];
                if (!in_array($declared, $allowed, true) || ($declared === 'US-ASCII' && preg_match('/[\x80-\xFF]/', $xml))) {
                    throw new \RuntimeException('Unsupported or mismatched XLSX XML encoding');
                }
                // The bytes are now UTF-8; keep the declaration consistent for native readers.
                $xml = substr_replace($xml, 'UTF-8', $match[2][1], strlen($match[2][0]));
            }
        }
        if (strlen($xml) > BulkTableIo::MAX_IMPORT_BYTES) { throw new \RuntimeException('Normalized XLSX XML exceeds its budget'); }
        $offset = 0;
        while (($start = strpos($xml, '<', $offset)) !== false) {
            $offset = $start + 1;
            foreach (['<!--'=>'-->', '<![CDATA['=>']]>', '<?'=>'?>'] as $opening=>$closing) {
                if (substr_compare($xml, $opening, $start, strlen($opening)) === 0) {
                    $end = strpos($xml, $closing, $start + strlen($opening));
                    if ($end === false) { throw new \RuntimeException('Unclosed XLSX XML markup'); }
                    $offset = $end + strlen($closing); continue 2;
                }
            }
            if (substr($xml, $start, 2) === '<!') { throw new \RuntimeException('XLSX XML declarations are disabled'); }
        }
        return $xml;
    }

    /** Walk every node without expanding a DOM or skipping uninspected subtrees. */
    private function xml(string $xml, string $root, string $namespace, callable $visit): void
    {
        $xml = self::prepareXml($xml);
        $reader = new \XMLReader(); $nodes = 0; $seenRoot = false; $path = [];
        try {
            if (!$reader->XML($xml, 'UTF-8', LIBXML_NONET | LIBXML_COMPACT)) { throw new \RuntimeException('Invalid XLSX XML'); }
            foreach ([\XMLReader::LOADDTD, \XMLReader::DEFAULTATTRS, \XMLReader::VALIDATE, \XMLReader::SUBST_ENTITIES] as $property) {
                if (!$reader->setParserProperty($property, false)) { throw new \RuntimeException('Cannot restrict XLSX XML parser'); }
            }
            while ($reader->read()) {
                if (++$nodes > self::MAX_NODES || $reader->depth > 32 || $reader->attributeCount > 64
                    || in_array($reader->nodeType, [\XMLReader::DOC_TYPE, \XMLReader::ENTITY_REF, \XMLReader::ENTITY], true)) {
                    throw new \RuntimeException('Unsupported or oversized XLSX XML structure');
                }
                if ($reader->nodeType === \XMLReader::ELEMENT) {
                    if ($reader->depth === 0) {
                        if ($seenRoot || $reader->localName !== $root || $reader->namespaceURI !== $namespace) {
                            throw new \RuntimeException('Unexpected XLSX XML root');
                        }
                        $seenRoot = true;
                    }
                    $path[$reader->depth] = $reader->namespaceURI === $namespace ? $reader->localName : '';
                    if ($reader->moveToFirstAttribute()) {
                        do { if (strlen($reader->value) > 8192) { throw new \RuntimeException('Oversized XLSX XML attribute'); } }
                        while ($reader->moveToNextAttribute());
                        $reader->moveToElement();
                    }
                }
                $visit($reader, $path);
            }
            if (!$seenRoot || libxml_get_errors() !== []) { throw new \RuntimeException('Incomplete XLSX XML'); }
        } finally { $reader->close(); libxml_clear_errors(); }
    }

    private function append(string &$value, string $text): void
    {
        $length = strlen($text);
        if ($length > $this->textRemaining || strlen($value) + $length > self::MAX_CELL_BYTES) {
            throw new \RuntimeException('XLSX decoded text exceeds its budget');
        }
        $this->textRemaining -= $length; $value .= $text;
    }

    private static function isText(\XMLReader $reader): bool
    {
        return in_array($reader->nodeType, [\XMLReader::TEXT, \XMLReader::CDATA, \XMLReader::WHITESPACE, \XMLReader::SIGNIFICANT_WHITESPACE], true);
    }

    private function sharedStrings(string $xml): array
    {
        $shared = []; $item = null; $textDepth = null;
        $this->xml($xml, 'sst', self::NS, function (\XMLReader $reader, array $path) use (&$shared, &$item, &$textDepth): void {
            if ($reader->nodeType === \XMLReader::ELEMENT && $reader->namespaceURI === self::NS) {
                if ($reader->depth === 1 && $reader->localName === 'si') {
                    if (count($shared) >= BulkTableIo::MAX_IMPORT_CELLS) { throw new \RuntimeException('Too many XLSX shared strings'); }
                    $item = ''; $textDepth = null;
                    if ($reader->isEmptyElement) { $shared[] = ''; $item = null; }
                } elseif ($item !== null && $reader->localName === 't'
                    && ($reader->depth === 2 || ($reader->depth === 3 && ($path[2] ?? null) === 'r'))) {
                    $textDepth = $reader->isEmptyElement ? null : $reader->depth;
                }
            } elseif ($item !== null && self::isText($reader) && $textDepth !== null && $reader->depth === $textDepth + 1) {
                $this->append($item, $reader->value);
            } elseif ($reader->nodeType === \XMLReader::END_ELEMENT) {
                if ($reader->depth === 1 && $reader->localName === 'si' && $reader->namespaceURI === self::NS) {
                    $shared[] = $item; $item = null; $textDepth = null;
                } elseif ($reader->depth === $textDepth) { $textDepth = null; }
            }
        });
        return $shared;
    }

    private function worksheet(string $xml, array $shared): array
    {
        $grid = []; $rowIds = []; $row = null; $nextRow = 0; $cell = null;
        $value = ''; $captureDepth = null; $cells = 0; $maxCol = 0; $valueSeen = false;
        $finish = function () use (&$grid, &$cell, &$value, &$captureDepth, &$maxCol, &$valueSeen, $shared): void {
            if ($cell['type'] === 's') {
                if (!$valueSeen || !preg_match('/^(0|[1-9][0-9]{0,5})$/D', $value) || !array_key_exists((int)$value, $shared)) {
                    throw new \RuntimeException('Invalid XLSX shared-string reference');
                }
                $value = $shared[(int)$value];
                if (strlen($value) > $this->textRemaining) { throw new \RuntimeException('XLSX string references exceed the text budget'); }
                $this->textRemaining -= strlen($value);
            }
            if (isset($grid[$cell['row']]) && array_key_exists($cell['col'], $grid[$cell['row']])) {
                throw new \RuntimeException('Duplicate XLSX cell coordinate');
            }
            $grid[$cell['row']][$cell['col']] = $value;
            $maxCol = max($maxCol, $cell['col']); $cell = null; $captureDepth = null;
        };
        $this->xml($xml, 'worksheet', self::NS, function (\XMLReader $reader, array $path) use (
            &$grid, &$rowIds, &$row, &$nextRow, &$cell, &$value, &$captureDepth, &$cells, &$valueSeen, $finish): void {
            if ($reader->nodeType === \XMLReader::ELEMENT && $reader->namespaceURI === self::NS) {
                if ($reader->depth === 2 && $reader->localName === 'row' && ($path[1] ?? null) === 'sheetData') {
                    $reference = $reader->getAttribute('r');
                    if ($reference !== null && !preg_match('/^[1-9][0-9]{0,3}$/D', $reference)) { throw new \RuntimeException('Invalid XLSX row'); }
                    $row = $reference === null ? $nextRow : (int)$reference - 1;
                    if ($row > BulkTableIo::MAX_IMPORT_ROWS || isset($rowIds[$row])) { throw new \RuntimeException('Duplicate or oversized XLSX row'); }
                    $rowIds[$row] = true; $nextRow = $row + 1;
                    if ($reader->isEmptyElement) { $row = null; }
                } elseif ($reader->depth === 3 && $reader->localName === 'c' && $row !== null) {
                    if (++$cells > BulkTableIo::MAX_IMPORT_CELLS) { throw new \RuntimeException('Too many XLSX cells'); }
                    [$col, $cellRow] = BulkTableIo::parseCellRef($reader->getAttribute('r'));
                    if ($col >= BulkTableIo::MAX_IMPORT_COLUMNS || $cellRow !== $row) { throw new \RuntimeException('XLSX cell is outside its import row or column budget'); }
                    $type = $reader->getAttribute('t') ?? '';
                    if (!in_array($type, ['', 'n', 's', 'inlineStr', 'b', 'str', 'e'], true)) { throw new \RuntimeException('Unsupported XLSX cell type'); }
                    $cell = ['row'=>$row, 'col'=>$col, 'type'=>$type]; $value = ''; $valueSeen = false; $captureDepth = null;
                    if ($reader->isEmptyElement) { $finish(); }
                } elseif ($cell !== null && $reader->localName === 'v' && $reader->depth === 4 && $cell['type'] !== 'inlineStr') {
                    if ($valueSeen) { throw new \RuntimeException('Duplicate XLSX cell value'); }
                    $valueSeen = true; $captureDepth = $reader->isEmptyElement ? null : $reader->depth;
                } elseif ($cell !== null && $cell['type'] === 'inlineStr' && $reader->localName === 't'
                    && ($path[4] ?? null) === 'is' && ($reader->depth === 5 || ($reader->depth === 6 && ($path[5] ?? null) === 'r'))) {
                    $captureDepth = $reader->isEmptyElement ? null : $reader->depth;
                }
            } elseif ($cell !== null && self::isText($reader) && $captureDepth !== null && $reader->depth === $captureDepth + 1) {
                $this->append($value, $reader->value);
            } elseif ($reader->nodeType === \XMLReader::END_ELEMENT) {
                if ($cell !== null && $reader->depth === 3 && $reader->localName === 'c' && $reader->namespaceURI === self::NS) { $finish(); }
                if ($reader->depth === $captureDepth) { $captureDepth = null; }
                if ($reader->depth === 2 && $reader->localName === 'row' && $reader->namespaceURI === self::NS) { $row = null; }
            }
        });
        if ($grid === []) { return ['headers'=>[], 'rows'=>[]]; }
        if (!isset($grid[0]) || (count($grid) - 1) * ($maxCol + 1) > BulkTableIo::MAX_IMPORT_CELLS) {
            throw new \RuntimeException('Missing XLSX header or oversized output matrix');
        }
        $headers = [];
        for ($col = 0; $col <= $maxCol; $col++) { $headers[] = trim($grid[0][$col] ?? ''); }
        unset($grid[0]); ksort($grid); $rows = [];
        foreach ($grid as $columns) {
            $data = []; $nonempty = false;
            foreach ($headers as $col => $header) {
                if ($header !== '') { $data[$header] = $columns[$col] ?? ''; $nonempty = $nonempty || $data[$header] !== ''; }
            }
            if ($nonempty) { $rows[] = $data; }
        }
        return ['headers'=>$headers, 'rows'=>$rows];
    }

    private function sheetPath(\ZipArchive $zip): string
    {
        $id = null; $seen = false;
        $this->xml($this->part($zip, 'xl/workbook.xml'), 'workbook', self::NS,
            static function (\XMLReader $reader, array $path) use (&$id, &$seen): void {
                if (!$seen && $reader->nodeType === \XMLReader::ELEMENT && $reader->namespaceURI === self::NS
                    && $reader->localName === 'sheet' && $reader->depth === 2 && ($path[1] ?? null) === 'sheets') {
                    $seen = true; $id = $reader->getAttributeNs('id', self::REL_NS);
                }
            });
        if ($id === null || $id === '') { throw new \RuntimeException('Missing XLSX sheet relationship'); }
        $target = null; $matched = false;
        $this->xml($this->part($zip, 'xl/_rels/workbook.xml.rels'), 'Relationships', self::PACKAGE_NS,
            static function (\XMLReader $reader) use ($id, &$target, &$matched): void {
                if ($reader->nodeType === \XMLReader::ELEMENT && $reader->namespaceURI === self::PACKAGE_NS
                    && $reader->localName === 'Relationship' && $reader->depth === 1 && $reader->getAttribute('Id') === $id) {
                    if ($matched || ($reader->getAttribute('TargetMode') ?? 'Internal') !== 'Internal'
                        || $reader->getAttribute('Type') !== self::REL_NS.'/worksheet') {
                        throw new \RuntimeException('Ambiguous or external XLSX sheet relationship');
                    }
                    $matched = true; $target = $reader->getAttribute('Target');
                }
            });
        if (!is_string($target) || $target === '' || strlen($target) > 1024 || !preg_match('/^[A-Za-z0-9_.\/ -]+$/D', $target)) {
            throw new \RuntimeException('Unsupported XLSX sheet target');
        }
        $parts = str_starts_with($target, '/') ? [] : ['xl'];
        foreach (explode('/', $target) as $part) {
            if ($part === '' || $part === '.') { continue; }
            if ($part === '..') {
                if ($parts === []) { throw new \RuntimeException('XLSX sheet target leaves its package'); }
                array_pop($parts);
            } else { $parts[] = $part; }
        }
        return implode('/', $parts);
    }
}
