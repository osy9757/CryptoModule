<?php

ini_set('memory_limit', '2G'); // 메모리 제한을 2G로 설정

require '../vendor/autoload.php';

use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;

// 암호화키(디비명)|포트
$crypt_keyData = array(
    'test_demo' => '12334556&^1230809|6601'
);

$crypt_realKey = explode("|", $crypt_keyData['test_demo']);
$crypt_passwd = $crypt_realKey[0]; // 암호화 키
$crypt_port = $crypt_realKey[1]; // 통신 포트
$iv = "0123456789012345"; // 초기화 벡터

// FFI를 사용하여 .so 파일 로드
$ffi = FFI::cdef("
    const char* encrypt(const char* plaintext, const char* key, const char* iv, int key_length);
    const char* decrypt(const char* ciphertext, const char* key, const char* iv, int key_length);
", "../build/libaes_crypt.so");

// 엑셀 파일 로드
$inputFileName = './sample.xlsx';
$spreadsheet = IOFactory::load($inputFileName);
$sheet = $spreadsheet->getActiveSheet();

// 암호화 시간 측정
$startEncryptTime = microtime(true);

foreach ($sheet->getRowIterator() as $row) {
    $cellIterator = $row->getCellIterator();
    $cellIterator->setIterateOnlyExistingCells(false); // 모든 셀을 반복

    foreach ($cellIterator as $cell) {
        $originalValue = $cell->getValue();
        if (!empty($originalValue)) {
            // 각 셀의 데이터를 문자열로 변환하여 암호화
            $originalValueStr = (string)$originalValue;
            $encryptedValue = $ffi->encrypt($originalValueStr, $crypt_passwd, $iv, 256);
            $cell->setValue($encryptedValue);
        }
    }
}

$endEncryptTime = microtime(true);
$encryptTime = $endEncryptTime - $startEncryptTime;
echo "Time taken to encrypt the spreadsheet: " . $encryptTime . " seconds\n";

// 엑셀 파일을 다시 저장 (Chunked Writing)
$outputFileName = './encrypted_file.xlsx';
$writer = new Xlsx($spreadsheet);

// Chunked writing 설정
$writer->setPreCalculateFormulas(false);

$chunkSize = 1000; // Chunk 크기 설정
$sheetIndex = $spreadsheet->getActiveSheetIndex();

for ($startRow = 1; $startRow <= $sheet->getHighestRow(); $startRow += $chunkSize) {
    $writer->setWriteType(\PhpOffice\PhpSpreadsheet\Writer\BaseWriter::WRITE_MODE_APPEND);
    $writer->setWriteBuffer($chunkSize);
    $writer->save($outputFileName);
}

echo "File saved to " . $outputFileName . "\n";

?>
