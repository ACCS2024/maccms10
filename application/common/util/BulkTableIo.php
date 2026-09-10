<?php
namespace app\common\util;

/**
 * CSV / XLSX 批量导入导出（无第三方依赖，xlsx 依赖 ZipArchive）
 */
class BulkTableIo
{
    const MAX_IMPORT_ROWS = 2000;
    const MAX_EXPORT_ROWS = 10000;
    const MAX_IMPORT_BYTES = 20971520;
    const MAX_CSV_RECORD_BYTES = 8388608;
    const MAX_IMPORT_COLUMNS = 256;
    const MAX_IMPORT_CELLS = 100000;

    public static function colName($index)
    {
        $n = (int)$index;
        $s = '';
        while ($n >= 0) {
            $s = chr(65 + ($n % 26)) . $s;
            $n = intdiv($n, 26) - 1;
        }
        return $s;
    }

    public static function xmlEsc($str)
    {
        return htmlspecialchars((string)$str, ENT_XML1 | ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function filterRowKeys(array $row, array $allowedKeys)
    {
        $allowed = array_flip($allowedKeys);
        $out = [];
        foreach ($row as $k => $v) {
            if (isset($allowed[$k])) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    /** Preserve omitted/empty/already-joined fields for the content model's bounded normalization. */
    public static function prepareGenericForSave(array $data, $prefix)
    {
        if (!is_string($prefix) || !in_array($prefix, ['art', 'manga', 'vod'], true)
            || count($data) > self::MAX_IMPORT_COLUMNS) { throw new \InvalidArgumentException('Unsupported content import row'); }
        $idKey = $prefix . '_id';
        $id = $data[$idKey] ?? '';
        $id = $id === '' ? 0 : PointsBalance::amount($id, true);
        $type = PointsBalance::amount($data['type_id'] ?? null);
        if ($id === null || $type === null || $type > ($prefix === 'vod' ? 32767 : 65535)) {
            throw new \InvalidArgumentException('Invalid content import identity');
        }
        if ($id === 0) { unset($data[$idKey]); }
        else { $data[$idKey] = $id; }
        $data['type_id'] = $type;
        foreach (['uptime', 'uptag'] as $field) {
            $value = $data[$field] ?? 0;
            if (!in_array($value, [0, 1, '0', '1'], true)) { throw new \InvalidArgumentException('Invalid content import flag'); }
            $data[$field] = (int)$value;
        }
        // Never explode arbitrary input before each model applies its byte/group/page budget.
        // An explicit empty column is a clear operation; an omitted column remains omitted.
        return $data;
    }

    public static function parseFile($path, $ext)
    {
        $ext = strtolower($ext);
        if ($ext === 'csv' || $ext === 'txt') {
            return self::parseCsv($path);
        }
        if (in_array($ext, ['xlsx', 'xlsm'], true)) {
            return self::parseXlsx($path);
        }
        throw new \InvalidArgumentException('unsupported format');
    }

    public static function parseCsv($path)
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) { throw new \RuntimeException('Cannot read CSV'); }
        try {
            $stat = fstat($handle);
            if ($stat !== false && $stat['size'] > self::MAX_IMPORT_BYTES) {
                throw new \RuntimeException('CSV exceeds the import byte limit');
            }
            // Parse these same bounded bytes, never reread a file that may have changed after inspection.
            $source = stream_get_contents($handle, self::MAX_IMPORT_BYTES + 1);
            if ($source === false || strlen($source) > self::MAX_IMPORT_BYTES) {
                throw new \RuntimeException('CSV exceeds the import byte limit');
            }
        } finally { fclose($handle); }
        $size = strlen($source);
        $start = str_starts_with($source, "\xEF\xBB\xBF") ? 3 : 0;
        $quoted = false; $afterQuote = false; $fieldStart = true;
        $columns = 1; $records = 0; $cells = 0; $headerRead = false;
        $headers = []; $rows = [];
        for ($i = $start; $i < $size; $i++) {
            if ($i - $start > self::MAX_CSV_RECORD_BYTES) {
                throw new \RuntimeException('CSV record exceeds the byte limit');
            }
            $char = $source[$i];
            if ($quoted) {
                if ($char === '"') {
                    if ($i + 1 < $size && $source[$i + 1] === '"') { $i++; }
                    else { $quoted = false; $afterQuote = true; }
                }
                continue;
            }
            if ($char === ',') {
                if (++$columns > self::MAX_IMPORT_COLUMNS) {
                    throw new \RuntimeException('CSV exceeds the column limit');
                }
                $fieldStart = true; $afterQuote = false;
            } elseif ($char === "\r" || $char === "\n") {
                self::appendCsvRecord($source, $start, $i - $start, $columns, $headers, $rows, $headerRead, $records, $cells);
                if ($char === "\r" && $i + 1 < $size && $source[$i + 1] === "\n") { $i++; }
                $start = $i + 1; $columns = 1; $fieldStart = true; $afterQuote = false;
            } elseif ($fieldStart && $char === '"') {
                $quoted = true; $fieldStart = false;
            } elseif ($char !== ' ' && $char !== "\t") {
                if ($afterQuote) { throw new \RuntimeException('Unexpected data after a quoted CSV field'); }
                $fieldStart = false;
            }
        }
        if ($quoted) { throw new \RuntimeException('Unclosed quoted CSV field'); }
        if ($start < $size) {
            self::appendCsvRecord($source, $start, $size - $start, $columns, $headers, $rows, $headerRead, $records, $cells);
        }
        return ['headers'=>$headers, 'rows'=>$rows];
    }

    /** Bound native CSV allocation and the eventual header-to-row matrix before parsing this record. */
    private static function appendCsvRecord(string $source, int $start, int $length, int $columns,
        array &$headers, array &$rows, bool &$headerRead, int &$records, int &$cells): void
    {
        $records++; $cells += $columns;
        if ($length > self::MAX_CSV_RECORD_BYTES || $records > self::MAX_IMPORT_ROWS + 1
            || $cells > self::MAX_IMPORT_CELLS
            || ($headerRead && ($records - 1) * count($headers) > self::MAX_IMPORT_CELLS)) {
            throw new \RuntimeException('CSV exceeds the record or cell budget');
        }
        $line = str_getcsv(substr($source, $start, $length), ',', '"', '');
        if (count($line) !== $columns) { throw new \RuntimeException('CSV field boundaries are inconsistent'); }
        if (!$headerRead) {
            $headers = array_map(static fn($header) => trim((string)$header), $line);
            $headerRead = true;
            return;
        }
        $allEmpty = true;
        foreach ($line as $cell) {
            if ($cell !== '' && $cell !== null) { $allEmpty = false; break; }
        }
        if ($allEmpty) { return; }
        $row = [];
        foreach ($headers as $index => $header) {
            if ($header !== '') { $row[$header] = $line[$index] ?? ''; }
        }
        $rows[] = $row;
    }

    public static function parseCellRef($ref)
    {
        if (!is_string($ref) || !preg_match('/^([A-Z]{1,3})([1-9][0-9]{0,6})$/Di', $ref, $match)) {
            throw new \InvalidArgumentException('Invalid spreadsheet cell reference');
        }
        $column = 0;
        foreach (str_split(strtoupper($match[1])) as $letter) { $column = $column * 26 + ord($letter) - 64; }
        $row = (int)$match[2];
        if ($column > 16384 || $row > 1048576) { throw new \InvalidArgumentException('Spreadsheet reference exceeds worksheet bounds'); }
        return [$column - 1, $row - 1];
    }

    public static function parseXlsx($path)
    {
        require_once __DIR__ . '/XlsxTableReader.php';
        return XlsxTableReader::read($path);
    }

    public static function exportCsvDownload($basename, array $headers, array $list)
    {
        $filename = preg_replace('/[^a-zA-Z0-9_\-\x{4e00}-\x{9fa5}]/u', '_', $basename) . '.csv';
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        echo "\xEF\xBB\xBF";
        $out = fopen('php://output', 'w');
        fputcsv($out, $headers, ',', '"', '');
        foreach ($list as $row) {
            $line = [];
            foreach ($headers as $h) {
                $line[] = isset($row[$h]) ? $row[$h] : '';
            }
            fputcsv($out, $line, ',', '"', '');
        }
        fclose($out);
    }

    public static function exportXlsxDownload($basename, array $headers, array $list)
    {
        if (!class_exists('ZipArchive')) {
            throw new \RuntimeException('zip');
        }
        $filename = preg_replace('/[^a-zA-Z0-9_\-\x{4e00}-\x{9fa5}]/u', '_', $basename) . '.xlsx';
        $tmp = tempnam(sys_get_temp_dir(), 'macxlsx');
        if ($tmp === false) {
            throw new \RuntimeException('temp');
        }
        $zip = new \ZipArchive();
        if ($zip->open($tmp, \ZipArchive::OVERWRITE | \ZipArchive::CREATE) !== true) {
            @unlink($tmp);
            throw new \RuntimeException('zip');
        }
        $zip->addFromString('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            . '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            . '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            . '<Default Extension="xml" ContentType="application/xml"/>'
            . '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            . '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            . '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            . '</Types>');
        $zip->addFromString('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            . '</Relationships>');
        $zip->addFromString('xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            . '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            . 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            . '<sheets><sheet name="data" sheetId="1" r:id="rId1"/></sheets></workbook>');
        $zip->addFromString('xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            . '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            . '</Relationships>');
        $zip->addFromString('xl/styles.xml', '<?xml version="1.0" encoding="UTF-8"?>'
            . '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            . '<fonts count="1"><font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font></fonts>'
            . '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
            . '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
            . '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            . '<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>'
            . '</styleSheet>');

        $sheetBody = '<sheetData>';
        $rowNum = 1;
        $sheetBody .= '<row r="' . $rowNum . '">';
        foreach ($headers as $ci => $h) {
            $cn = self::colName($ci);
            $sheetBody .= '<c r="' . $cn . $rowNum . '" t="inlineStr"><is><t xml:space="preserve">' . self::xmlEsc($h) . '</t></is></c>';
        }
        $sheetBody .= '</row>';
        foreach ($list as $row) {
            $rowNum++;
            $sheetBody .= '<row r="' . $rowNum . '">';
            foreach ($headers as $ci => $h) {
                $cn = self::colName($ci);
                $v = isset($row[$h]) ? $row[$h] : '';
                $sheetBody .= '<c r="' . $cn . $rowNum . '" t="inlineStr"><is><t xml:space="preserve">' . self::xmlEsc($v) . '</t></is></c>';
            }
            $sheetBody .= '</row>';
        }
        $sheetBody .= '</sheetData>';
        $sheetXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            . '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            . 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            . $sheetBody . '</worksheet>';
        $zip->addFromString('xl/worksheets/sheet1.xml', $sheetXml);
        $zip->close();

        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . filesize($tmp));
        readfile($tmp);
        @unlink($tmp);
    }
}
