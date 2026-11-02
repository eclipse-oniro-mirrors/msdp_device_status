/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "submitfeedback_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include <fuzzer/FuzzedDataProvider.h>

#include "accesstoken_kit.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "parameters.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "SubmitFeedbackFuzzer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
namespace {
constexpr size_t MAX_EVENT_ID_LEN = 256;

bool g_tokenInitialized = false;

void InitNativeToken()
{
    if (g_tokenInitialized) {
        return;
    }
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };
    infoInstance.processName = "SubmitFeedbackFuzzer";
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    g_tokenInitialized = true;
}

CallingContext MakeSystemContext()
{
    InitNativeToken();
    return CallingContext {
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
}
} // namespace

void SubmitFeedbackFuzzer::FuzzSubmitFeedback(const uint8_t *data, size_t size)
{
    if (size < sizeof(int32_t) + sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    std::string eventId = provider.ConsumeRandomLengthString(MAX_EVENT_ID_LEN);
    int32_t feedbackTypeRaw = provider.ConsumeIntegral<int32_t>();
    int64_t feedbackTime = provider.ConsumeIntegral<int64_t>();

    CallingContext ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = eventId,
        .feedbackType = static_cast<FeedbackType>(feedbackTypeRaw),
        .feedbackTime = feedbackTime,
    };
    BehaviorAwarenessServer server;
    server.SubmitFeedback(ctx, feedback);
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Msdp::DeviceStatus::BehaviorAwareness::SubmitFeedbackFuzzer fuzzer;
    fuzzer.FuzzSubmitFeedback(data, size);
    return 0;
}
