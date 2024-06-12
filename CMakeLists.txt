cmake_minimum_required(VERSION 3.10)
project(CryptoModule)

set(CMAKE_CXX_STANDARD 11)
set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
set(OPENSSL_INCLUDE_DIR /opt/homebrew/opt/openssl@3/include)
set(OPENSSL_LIBRARIES /opt/homebrew/opt/openssl@3/lib)

include_directories(${OPENSSL_INCLUDE_DIR} ${PROJECT_SOURCE_DIR}/include)

set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")

# 암호화 라이브러리 생성
add_library(aes_crypt SHARED src/aesCrypt.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(aes_crypt OpenSSL::SSL OpenSSL::Crypto)

# 테스트 파일 빌드 설정
add_executable(test_so test/test_so.cpp)
target_link_libraries(test_so aes_crypt dl)
