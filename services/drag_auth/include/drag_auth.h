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

#ifndef DRAG_AUTH_H
#define DRAG_AUTH_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

#include "drag_data.h"


namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

constexpr size_t NONCE_SIZE = 32;
constexpr size_t HMAC_SHA384_SIZE = 48;

class DragAuth {
public:
    DragAuth(const DragAuth&) = delete;
    DragAuth& operator=(const DragAuth&) = delete;
    static DragAuth& GetInstance();

    std::string GenerateNonce();
    std::vector<uint8_t> GenerateSignature(const std::vector<uint8_t>& nonce,
        const DragEventData& dragEventData);
    bool VerifySignature(const DragEventData& dragEventData,
        const std::string signature);
    void ResetNonce();
    std::string Base64Encode(const uint8_t* data, size_t len);
    std::string Base64Encode(const std::vector<uint8_t>& vec);
    std::vector<uint8_t> Base64Decode(const std::string& b64);
private:
    DragAuth();
    ~DragAuth() = default;

    std::string SerializeDragEventData(const DragEventData& data);
    bool VerifyDragEventInterval(const DragEventData& data);
    uint64_t GetCurrentTimestampMs() const;
    bool ConstantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len);
    std::string nonceB64_;
    std::vector<uint8_t> nonceBin_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#define DRAG_AUTH OHOS::Msdp::DeviceStatus::DragAuth::GetInstance()
#endif // DRAG_AUTH_H