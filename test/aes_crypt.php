<?php

// FFI를 사용하여 .so 파일 로드
$ffi = FFI::cdef("
    const char* encrypt(const char* plaintext, const char* key, const char* iv, int key_length);
    const char* decrypt(const char* ciphertext, const char* key, const char* iv, int key_length);
", "../build/libaes_crypt.so");

// 암호화할 데이터
$phoneNumber = "0123456789"; // 10자리 전화번호
$key = "01234567890123456789012345678901"; // 32 bytes for AES-256
$iv = "0123456789012345"; // 16 bytes for AES block size

// 암호화 시간 측정
$startEncryptTime = microtime(true);

for ($i = 0; $i < 20000; $i++) {
    $ciphertext = $ffi->encrypt($phoneNumber, $key, $iv, 256);
}

$endEncryptTime = microtime(true);
$encryptTime = $endEncryptTime - $startEncryptTime;
echo "Time taken to encrypt 20000 times: " . $encryptTime . " seconds\n";

// 복호화 시간 측정
$startDecryptTime = microtime(true);

for ($i = 0; $i < 20000; $i++) {
    $decrypted = $ffi->decrypt($ciphertext, $key, $iv, 256);
}

$endDecryptTime = microtime(true);
$decryptTime = $endDecryptTime - $startDecryptTime;
echo "Time taken to decrypt 20000 times: " . $decryptTime . " seconds\n";

// 최종 복호화 결과 출력
echo "Final decrypted value: " . $decrypted . "\n";

?>
