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

#include "intention_client_fuzzer.h"

#include "boomerang_callback_stub.h"
#include "devicestatus_callback_stub.h"

#include <cstddef>
#include <cstdint>
#include <map>

#include <nocopyable.h>

#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "MsdpIntentionClientFuzzTest"

namespace {
    constexpr size_t THRESHOLD = 5;
}
using namespace OHOS::Media;
using namespace OHOS::Msdp;

uint32_t ConvertToUint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    uint32_t bigVar = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
    return bigVar;
}

class BoomerangClientTestCallback : public OHOS::Msdp::DeviceStatus::BoomerangCallbackStub {
public:

private:
    OHOS::Msdp::DeviceStatus::BoomerangData data_;
};

namespace OHOS {

void FuzzIntentionClientSocket(const uint8_t *rawData, size_t size)
{
    uint32_t integer = ConvertToUint32(rawData);
    int32_t integer32 = static_cast<int32_t>(integer);
    std::string str(reinterpret_cast<const char *>(rawData), size);
    INTENTION_CLIENT->Socket(str, integer, integer32, integer32);
}

void FuzzIntentionClientCooperate(const uint8_t *rawData, size_t size)
{
    uint32_t integer = ConvertToUint32(rawData);
    std::string str(reinterpret_cast<const char *>(rawData), size);
    bool boolean = static_cast<bool>(*rawData);
    double doubleNum = static_cast<double>(*rawData);
    CooperateOptions options {
            .displayX = 500,
            .displayY = 500,
            .displayId = 1
    };
    INTENTION_CLIENT->EnableCooperate(integer);
    INTENTION_CLIENT->DisableCooperate(integer);
    INTENTION_CLIENT->StartCooperate(str, integer, integer, boolean);
    INTENTION_CLIENT->StartCooperateWithOptions(str, integer, integer, boolean, options);
    INTENTION_CLIENT->StopCooperate(integer, boolean, boolean);
    INTENTION_CLIENT->RegisterCooperateListener();
    INTENTION_CLIENT->UnregisterCooperateListener();
    INTENTION_CLIENT->RegisterHotAreaListener(integer, boolean);
    INTENTION_CLIENT->UnregisterHotAreaListener(integer, boolean);
    INTENTION_CLIENT->RegisterMouseEventListener(str);
    INTENTION_CLIENT->UnregisterMouseEventListener(str);
    bool state { false };
    INTENTION_CLIENT->GetCooperateStateSync(str, state);
    INTENTION_CLIENT->GetCooperateStateAsync(str, integer, boolean);
    INTENTION_CLIENT->SetDamplingCoefficient(integer, doubleNum);
}

void FuzzIntentionClientDrag(const uint8_t *rawData, size_t size)
{
    uint32_t integer = ConvertToUint32(rawData);
    int32_t integer32 = static_cast<int32_t>(integer);
    uint64_t integerU64 = static_cast<uint64_t>(integer);
    std::string str(reinterpret_cast<const char *>(rawData), size);
    bool boolean = static_cast<bool>(*rawData);
    float floatNum = static_cast<float>(*rawData);

    uint32_t color[100] = { integer };
    InitializationOptions opts = { { 5, 7}, PixelFormat::ARGB_8888 };
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(color, sizeof(color)/sizeof(color[0]), opts);
    std::shared_ptr<PixelMap> pixelMapIn = move(pixelMap);

    Msdp::DeviceStatus::ShadowInfo shadowInfo {
        .pixelMap = pixelMapIn,
        .x = integer32,
        .y = integer32
    };

    Msdp::DeviceStatus::DragData dragData {
        .shadowInfos = { shadowInfo },
        .buffer = {rawData, rawData + size},
        .udKey = str,
        .extraInfo = str,
        .filterInfo = str,
        .sourceType = integer32,
        .dragNum = integer32,
        .pointerId = integer32,
        .displayId = integer32,
        .mainWindow = integer32,
        .hasCanceledAnimation = boolean,
        .hasCoordinateCorrected = boolean,
        .isDragDelay = boolean,
        .appCallee = str,
        .appCaller = str
    };
    Msdp::DeviceStatus::DragDropResult dragDropResult {
        .hasCustomAnimation = boolean,
        .mainWindow = integer32
    };

    Msdp::DeviceStatus::PreviewStyle previewStyle {
        .foregroundColor = integer,
        .opacity = integer32,
        .radius = floatNum,
        .scale = floatNum
    };

    Msdp::DeviceStatus::PreviewAnimation previewAnimation {
        .duration = integer32,
        .curveName = str,
        .curve = { floatNum, floatNum }
    };

    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction { nullptr };

    INTENTION_CLIENT->StopDrag(dragDropResult);
    INTENTION_CLIENT->StartDrag(dragData);
    INTENTION_CLIENT->EnableInternalDropAnimation(str);
    INTENTION_CLIENT->AddDraglistener(boolean);
    INTENTION_CLIENT->RemoveDraglistener(boolean);
    INTENTION_CLIENT->AddSubscriptListener();
    INTENTION_CLIENT->RemoveSubscriptListener();
    INTENTION_CLIENT->SetDragWindowVisible(boolean, boolean, rsTransaction);
    Msdp::DeviceStatus::DragCursorStyle dragCursorStyle { Msdp::DeviceStatus::DragCursorStyle::DEFAULT };
    INTENTION_CLIENT->UpdateDragStyle(dragCursorStyle, integer32);
    INTENTION_CLIENT->UpdateShadowPic(shadowInfo);
    INTENTION_CLIENT->GetDragTargetPid(integer32);
    INTENTION_CLIENT->GetUdKey(str);
    Msdp::DeviceStatus::ShadowOffset shadowOffset;
    INTENTION_CLIENT->GetShadowOffset(shadowOffset);
    Msdp::DeviceStatus::DragData dragDataGet;
    INTENTION_CLIENT->GetDragData(dragDataGet);

    INTENTION_CLIENT->UpdatePreviewStyle(previewStyle);
    INTENTION_CLIENT->UpdatePreviewStyleWithAnimation(previewStyle, previewAnimation);
    INTENTION_CLIENT->RotateDragWindowSync(rsTransaction);
    INTENTION_CLIENT->SetDragWindowScreenId(integerU64, integerU64);
    std::map<std::string, int64_t> summarys;
    INTENTION_CLIENT->GetDragSummary(summarys, boolean);
    INTENTION_CLIENT->SetDragSwitchState(boolean, boolean);
    INTENTION_CLIENT->SetAppDragSwitchState(boolean, str, boolean);
    Msdp::DeviceStatus::DragState dragState;
    INTENTION_CLIENT->GetDragState(dragState);
    INTENTION_CLIENT->EnableUpperCenterMode(boolean);
    Msdp::DeviceStatus::DragAction dragAction;
    INTENTION_CLIENT->GetDragAction(dragAction);
    INTENTION_CLIENT->GetExtraInfo(str);
    INTENTION_CLIENT->AddPrivilege();
    INTENTION_CLIENT->EraseMouseIcon();
    INTENTION_CLIENT->SetMouseDragMonitorState(boolean);
    INTENTION_CLIENT->SetDraggableState(boolean);
    INTENTION_CLIENT->GetAppDragSwitchState(boolean);
    INTENTION_CLIENT->SetDraggableStateAsync(boolean, integer32);
    Msdp::DeviceStatus::DragBundleInfo dragBundleInfo;
    INTENTION_CLIENT->GetDragBundleInfo(dragBundleInfo);
    bool isStart = false;
    INTENTION_CLIENT->IsDragStart(isStart);
}

void FuzzIntentionClientBoomerang(const uint8_t *rawData, size_t size)
{
    uint32_t integer = ConvertToUint32(rawData);
    int32_t integer32 = static_cast<int32_t>(integer);
    std::string str(reinterpret_cast<const char *>(rawData), size);

    uint32_t color[100] = { integer };
    InitializationOptions opts = { { 5, 7}, PixelFormat::ARGB_8888 };
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(color, sizeof(color)/sizeof(color[0]), opts);
    std::shared_ptr<PixelMap> pixelMapIn = move(pixelMap);

    sptr<Msdp::DeviceStatus::IRemoteBoomerangCallback> callback =
        sptr<BoomerangClientTestCallback>::MakeSptr();
    INTENTION_CLIENT->SubscribeCallback(integer32, str, callback);
    INTENTION_CLIENT->UnsubscribeCallback(integer32, str, callback);
    INTENTION_CLIENT->NotifyMetadataBindingEvent(str, callback);
    INTENTION_CLIENT->SubmitMetadata(str);
    INTENTION_CLIENT->BoomerangEncodeImage(pixelMapIn, str, callback);
    INTENTION_CLIENT->BoomerangDecodeImage(pixelMapIn, callback);
}

void FuzzIntentionClientStationary(const uint8_t *rawData, size_t size)
{
    uint32_t integer = ConvertToUint32(rawData);
    int32_t integer32 = static_cast<int32_t>(integer);

    sptr<Msdp::DeviceStatus::IRemoteDevStaCallback> callback =
        sptr<Msdp::DeviceStatus::DeviceStatusCallbackStub>::MakeSptr();

    INTENTION_CLIENT->SubscribeStationaryCallback(integer32, integer32, integer32, callback);
    INTENTION_CLIENT->UnsubscribeStationaryCallback(integer32, integer32, callback);
    INTENTION_CLIENT->GetDeviceStatusData(integer32, integer32, integer32);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::FuzzIntentionClientSocket(data, size);
    OHOS::FuzzIntentionClientCooperate(data, size);
    OHOS::FuzzIntentionClientDrag(data, size);
    OHOS::FuzzIntentionClientBoomerang(data, size);
    OHOS::FuzzIntentionClientStationary(data, size);
    return 0;
}
