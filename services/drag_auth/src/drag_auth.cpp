/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "drag_auth.h"
#include "fi_log.h"
#include <algorithm>
#include <chrono>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <securec.h>
#include <vector>
#include <cstring>

#undef LOG_TAG
#define LOG_TAG "DragAuth"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

namespace {
    const int32_t RAND_BYTES_SUCCESS { 1 };
    constexpr uint64_t NONCE_TIMEOUT_MS { 3000 }; // drag timeout
    const int32_t MAX_BASE64_LENGTH { 1024 };
    const int32_t SECURITY_DATA_LEN { 17 };
}

DragAuth& DragAuth::GetInstance()
{
    static DragAuth instance;
    return instance;
}

DragAuth::DragAuth() {}

std::string DragAuth::GenerateNonce()
{
    CALL_INFO_TRACE;
    constexpr size_t NONCE_LEN = NONCE_SIZE;
    nonceBin_.resize(NONCE_LEN);
    if (RAND_bytes(nonceBin_.data(), static_cast<int>(nonceBin_.size())) != RAND_BYTES_SUCCESS) {
        FI_HILOGE("RAND_bytes failed");
        ResetNonce();
        return "";
    }
    nonceB64_ = Base64Encode(nonceBin_);
    return nonceB64_;
}
 
std::vector<uint8_t> DragAuth::GenerateSignature(const std::vector<uint8_t>& nonce,
    const DragEventData& dragSecurityData)
{
    CALL_INFO_TRACE;
    if (nonce.empty()) {
        FI_HILOGE("Empty nonce provided");
        return {};
    }
    auto dataStr = SerializeDragEventData(dragSecurityData);
    if (dataStr.empty()) {
        FI_HILOGE("Failed to serialize event data");
        return {};
    }
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int len = 0;
    HMAC(EVP_sha384(),
        nonce.data(),
        static_cast<int>(nonce.size()),
        reinterpret_cast<const unsigned char*>(dataStr.data()), dataStr.size(),
        digest,
        &len);
    return std::vector<uint8_t>(digest, digest + len);
}
 
bool DragAuth::VerifySignature(const DragEventData& dragSecurityData, const std::string signature)
{
    CALL_INFO_TRACE;
    if (signature.empty()) {
        FI_HILOGE("Invalid nonce");
        return false;
    }
    if (!VerifyDragEventInterval(dragSecurityData)) {
        FI_HILOGE("VerifyDragEventInterval failed");
        return false;
    }
    std::vector<uint8_t> externalSignature = Base64Decode(signature);
    if (externalSignature.size() != HMAC_SHA384_SIZE) {
        FI_HILOGE("ExternalSignature size failed");
        return false;
    }
    std::vector<uint8_t> expectedSignature = GenerateSignature(nonceBin_, dragSecurityData);
    if (expectedSignature.empty() || expectedSignature.size() != HMAC_SHA384_SIZE) {
        FI_HILOGE("Failed to generate expected signature");
        return false;
    }
    return ConstantTimeCompare(externalSignature.data(), expectedSignature.data(), HMAC_SHA384_SIZE);
}
 
void DragAuth::ResetNonce()
{
    nonceBin_.clear();
    nonceB64_ = "";
}
 
std::string DragAuth::SerializeDragEventData(const DragEventData& data)
{
    std::ostringstream oss;
    oss.precision(SECURITY_DATA_LEN);
    oss << data.timestampMs << '|' << data.coordinateX << '|' << data.coordinateY;
    return oss.str();
}
 
bool DragAuth::VerifyDragEventInterval(const DragEventData& dragSecurityData)
{
    CALL_INFO_TRACE;
    uint64_t currentTime = GetCurrentTimestampMs();
    uint64_t dragEventTimestamp = dragSecurityData.timestampMs;
    if (dragEventTimestamp > currentTime) {
        FI_HILOGE("Invalid timestamp: future time %{public}" PRId64, dragEventTimestamp);
        return false;
    }
    if ((currentTime - dragEventTimestamp) > NONCE_TIMEOUT_MS) {
        FI_HILOGE("timestamp timeout, currentTime:%{public}" PRId64 "DragEventtimestamp:%{public}" PRId64,
        currentTime, dragEventTimestamp);
        return false;
    }
    return true;
}
 
uint64_t DragAuth::GetCurrentTimestampMs() const
{
    auto now = std::chrono::steady_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}
 
bool DragAuth::ConstantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len)
{
    CALL_INFO_TRACE;
    if (!a || !b || len == 0) {
        return false;
    }
    if (CRYPTO_memcmp(a, b, len) != 0) {
        FI_HILOGE("ConstantTimeCompare failed");
        return false;
    }
    return true;
}
 
std::string DragAuth::Base64Encode(const uint8_t* data, size_t len)
{
    if (!data || (len == 0)) {
        FI_HILOGE("data or len error");
        return "";
    }
    // CHECK Base64encode formula for calculating length
    if (len > (SIZE_MAX - 2) / 4 * 3) {
        FI_HILOGE("Len too large");
        return "";
    }
    // Base64encode formula for calculating length
    size_t outLen = 4 * ((len + 2) / 3);
    std::vector<unsigned char> outBuf(outLen + 1);
    int encodedLen = EVP_EncodeBlock(outBuf.data(), data, static_cast<int>(len));
    if (encodedLen <= 0) {
        FI_HILOGE("Base64Encode error");
        return "";
    }
    return std::string(reinterpret_cast<char*>(outBuf.data()), encodedLen);
}
 
std::string DragAuth::Base64Encode(const std::vector<uint8_t>& vec)
{
    return Base64Encode(vec.data(), vec.size());
}
 
std::vector<uint8_t> DragAuth::Base64Decode(const std::string& b64)
{
    if (b64.empty() || (b64.length() > MAX_BASE64_LENGTH)) {
        FI_HILOGE("B64 is empty or too long");
        return {};
    }
    
    BIO* b64Bio = BIO_new(BIO_f_base64());
    if (!b64Bio) {
        FI_HILOGE("Failed to create base64 BIO");
        return {};
    }
    
    BIO* memBio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    if (!memBio) {
        BIO_free(b64Bio);
        FI_HILOGE("Failed to create memory BIO");
        return {};
    }
    BIO_push(b64Bio, memBio);
    BIO_set_flags(b64Bio, BIO_FLAGS_BASE64_NO_NL);
 
    std::vector<uint8_t> result;
    uint8_t buf[256];
    int bytesRead = 0;
 
    while ((bytesRead = BIO_read(b64Bio, buf, sizeof(buf))) > 0) {
        result.insert(result.end(), buf, buf + bytesRead);
    }
 
    BIO_free_all(b64Bio);
    return result;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
