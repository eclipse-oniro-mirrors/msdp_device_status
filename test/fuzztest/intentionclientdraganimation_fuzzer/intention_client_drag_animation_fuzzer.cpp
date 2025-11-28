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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <nocopyable.h>

#include "boomerang_callback_stub.h"
#include "devicestatus_callback_stub.h"
#include "intention_client.h"
#include "intention_client_drag_animation_fuzzer.h"

#undef LOG_TAG
#define LOG_TAG "IntentionClientDragAnimationFuzzTest"

namespace {
constexpr size_t THRESHOLD = 5;
constexpr int32_t TIME_WAIT_FOR_DS_MS { 1000 };
}
using namespace OHOS::Media;
using namespace OHOS::Msdp;

class BoomerangClientTestCallback : public OHOS::Msdp::DeviceStatus::BoomerangCallbackStub {
public:

private:
    OHOS::Msdp::DeviceStatus::BoomerangData data_;
};

namespace OHOS {

void IntentionClientDragAnimationFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string animationInfo = provider.ConsumeBytesAsString(10); // test value
    uint64_t displayId = provider.ConsumeIntegral<uint64_t >();
    uint64_t screenId = provider.ConsumeIntegral<uint64_t >();
    std::map<std::string, int64_t> summarys = { {
        provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}}; // test value
    bool isJsCaller = provider.ConsumeBool();
    bool enable = provider.ConsumeBool();
    std::string pkgName = provider.ConsumeRandomLengthString();
    Msdp::DeviceStatus::DragState dragState = static_cast<Msdp::DeviceStatus::DragState>(
        provider.ConsumeIntegralInRange<int32_t>(0, 4));
    Msdp::DeviceStatus::DragAction dragAction = static_cast<Msdp::DeviceStatus::DragAction>(
        provider.ConsumeIntegralInRange<int32_t>(-1, 1));
    std::string extraInfo = provider.ConsumeRandomLengthString();
    bool state = provider.ConsumeBool();
    int64_t downTime = provider.ConsumeIntegral<int64_t >();
    bool isStart = provider.ConsumeBool();
    INTENTION_CLIENT->EnableInternalDropAnimation(animationInfo);
    INTENTION_CLIENT->ResetDragWindowScreenId(displayId, screenId);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_DS_MS));
    INTENTION_CLIENT->GetDragSummary(summarys, isJsCaller);
    INTENTION_CLIENT->SetDragSwitchState(enable, isJsCaller);
    INTENTION_CLIENT->SetAppDragSwitchState(enable, pkgName, isJsCaller);
    INTENTION_CLIENT->GetDragState(dragState);
    INTENTION_CLIENT->EnableUpperCenterMode(enable);
    INTENTION_CLIENT->GetDragAction(dragAction);
    INTENTION_CLIENT->GetExtraInfo(extraInfo);
    INTENTION_CLIENT->SetMouseDragMonitorState(state);
    INTENTION_CLIENT->SetDraggableState(state);
    INTENTION_CLIENT->GetAppDragSwitchState(state);
    INTENTION_CLIENT->SetDraggableStateAsync(state, downTime);
    INTENTION_CLIENT->IsDragStart(isStart);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::IntentionClientDragAnimationFuzzTest(data, size);

    return 0;
}
