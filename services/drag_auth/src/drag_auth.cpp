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
#include <securec.h>
#include <vector>
#include <cstring>

#include "bsl_base64.h"
#include "bsl_errno.h"
#include "crypt_eal_init.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"

#undef LOG_TAG
#define LOG_TAG "DragAuth"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

namespace {
    constexpr uint64_t NONCE_TIMEOUT_MS { 3000 }; // drag timeout
    const int32_t MAX_BASE64_LENGTH { 1024 };
    const int32_t SECURITY_DATA_LEN { 17 };
}

DragAuth& DragAuth::GetInstance()
{
    static DragAuth instance;
    return instance;
}

DragAuth::DragAuth()
{
    // The shared library constructor of openHiTLS only initializes CPU capability detection.
    // BSL/LOCK/RAND modules must be initialized explicitly and idempotently by bits.
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        FI_HILOGE("CRYPT_EAL_Init failed, ret:%{public}d", ret);
    }
}

std::string DragAuth::GenerateNonce()
{
    CALL_INFO_TRACE;
    constexpr size_t NONCE_LEN = NONCE_SIZE;
    nonceBin_.resize(NONCE_LEN);
    if (CRYPT_EAL_Randbytes(nonceBin_.data(), static_cast<uint32_t>(nonceBin_.size())) != CRYPT_SUCCESS) {
        FI_HILOGE("CRYPT_EAL_Randbytes failed");
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
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SHA384);
    if (ctx == nullptr) {
        FI_HILOGE("CRYPT_EAL_MacNewCtx failed");
        return {};
    }
    uint8_t digest[HMAC_SHA384_SIZE] = {0};
    uint32_t len = HMAC_SHA384_SIZE;
    int32_t ret = CRYPT_EAL_MacInit(ctx, nonce.data(), static_cast<uint32_t>(nonce.size()));
    if (ret != CRYPT_SUCCESS) {
        FI_HILOGE("CRYPT_EAL_MacInit failed, ret:%{public}d", ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return {};
    }
    ret = CRYPT_EAL_MacUpdate(ctx, reinterpret_cast<const uint8_t*>(dataStr.data()),
        static_cast<uint32_t>(dataStr.size()));
    if (ret != CRYPT_SUCCESS) {
        FI_HILOGE("CRYPT_EAL_MacUpdate failed, ret:%{public}d", ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return {};
    }
    ret = CRYPT_EAL_MacFinal(ctx, digest, &len);
    if (ret != CRYPT_SUCCESS) {
        FI_HILOGE("CRYPT_EAL_MacFinal failed, ret:%{public}d", ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return {};
    }
    CRYPT_EAL_MacFreeCtx(ctx);
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
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    if (diff != 0) {
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
    // CHECK Base64encode formula for calculating length, BSL_BASE64_Encode uses uint32_t length
    if (len > static_cast<size_t>((UINT32_MAX - 4) / 4 * 3)) {
        FI_HILOGE("Len too large");
        return "";
    }
    // Base64encode formula for calculating length
    size_t outLen = 4 * ((len + 2) / 3);
    std::vector<char> outBuf(outLen + 1);
    uint32_t encodedLen = static_cast<uint32_t>(outBuf.size());
    int32_t ret = BSL_BASE64_Encode(data, static_cast<uint32_t>(len), outBuf.data(), &encodedLen);
    if (ret != BSL_SUCCESS) {
        FI_HILOGE("BSL_BASE64_Encode failed, ret:%{public}d", ret);
        return "";
    }
    return std::string(outBuf.data(), encodedLen);
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
    std::vector<uint8_t> outBuf(HITLS_BASE64_DECODE_LENGTH(b64.length()));
    uint32_t outLen = static_cast<uint32_t>(outBuf.size());
    int32_t ret = BSL_BASE64_Decode(b64.data(), static_cast<uint32_t>(b64.size()), outBuf.data(), &outLen);
    if (ret != BSL_SUCCESS) {
        FI_HILOGE("BSL_BASE64_Decode failed, ret:%{public}d", ret);
        return {};
    }
    outBuf.resize(outLen);
    return outBuf;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
