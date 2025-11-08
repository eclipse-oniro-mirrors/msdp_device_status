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
#include "intention_bundle_info_fuzzer.h"
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "IntentionBundleInfoFuzzTest"

namespace {
    constexpr size_t THRESHOLD = 5;
}
using namespace OHOS::Media;
using namespace OHOS::Msdp;

class BoomerangClientTestCallback : public OHOS::Msdp::DeviceStatus::BoomerangCallbackStub {
public:

private:
    OHOS::Msdp::DeviceStatus::BoomerangData data_;
};

namespace OHOS {

void IntentionBundleInfoFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Msdp::DeviceStatus::DragBundleInfo dragBundleInfo = {
        .bundleName = provider.ConsumeBytesAsString(10), // test value
        .isCrossDevice = provider.ConsumeBool()
    };
    bool isStart = provider.ConsumeBool();
        Msdp::DeviceStatus::DragCursorStyle style = static_cast<Msdp::DeviceStatus::DragCursorStyle>(
        provider.ConsumeIntegralInRange<int32_t>(0, 3));
    int32_t eventId = provider.ConsumeIntegral<int32_t>();
    int32_t targetPid = provider.ConsumeIntegral<int32_t>();
    std::string udKey = provider.ConsumeBytesAsString(10);
    Msdp::DeviceStatus::ShadowOffset shadowOffset = {
        .offsetX = provider.ConsumeIntegral<int32_t>(),
        .offsetY = provider.ConsumeIntegral<int32_t>(),
        .width = provider.ConsumeIntegral<int32_t>(),
        .height = provider.ConsumeIntegral<int32_t>()
    };
    Msdp::DeviceStatus::PreviewStyle previewStyle = {
    .foregroundColor = provider.ConsumeIntegralInRange<uint32_t>(0, 5),
    .opacity = provider.ConsumeIntegralInRange<int32_t>(0, 5),
    .radius = provider.ConsumeFloatingPointInRange<float>(0, 1),
    .scale = provider.ConsumeFloatingPointInRange<float>(0, 1)
    };
    Msdp::DeviceStatus::PreviewAnimation animation = {
        .curveName = provider.ConsumeRandomLengthString(),
        .duration = provider.ConsumeIntegralInRange<int32_t>(1, 5)
    };
    std::shared_ptr<Rosen::RSTransaction> rsTransaction = nullptr;
    uint64_t displayId = provider.ConsumeIntegral<int64_t >();
    uint64_t screenId =  provider.ConsumeIntegral<int64_t >();
    INTENTION_CLIENT->RemoveSubscriptListener();
    INTENTION_CLIENT->UpdateDragStyle(style, eventId);
    INTENTION_CLIENT->GetDragTargetPid(targetPid);
    INTENTION_CLIENT->GetUdKey(udKey);
    INTENTION_CLIENT->UpdatePreviewStyle(previewStyle);
    INTENTION_CLIENT->UpdatePreviewStyleWithAnimation(previewStyle, animation);
    INTENTION_CLIENT->RotateDragWindowSync(rsTransaction);
    INTENTION_CLIENT->SetDragWindowScreenId(displayId, screenId);
    INTENTION_CLIENT->GetDragBundleInfo(dragBundleInfo);
    INTENTION_CLIENT->GetShadowOffset(shadowOffset);
    INTENTION_CLIENT->IsDragStart(isStart);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */

    OHOS::IntentionBundleInfoFuzzTest(data, size);

    return 0;
}
