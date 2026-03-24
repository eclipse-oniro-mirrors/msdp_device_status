/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "drag_test_common.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

std::shared_ptr<Media::PixelMap> DragTestHelper::CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        FI_HILOGE("Invalid, height:%{public}d, width:%{public}d", height, width);
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;
 
    int32_t colorLen = width * height;
    uint32_t *pixelColors = new (std::nothrow) uint32_t[BUFF_SIZE];
    CHKPP(pixelColors);
    int32_t colorByteCount = colorLen * INT32_BYTE;
    errno_t ret = memset_s(pixelColors, BUFF_SIZE, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        FI_HILOGE("memset_s failed");
        delete[] pixelColors;
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(pixelColors, colorLen, opts);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelMap failed");
        delete[] pixelColors;
        return nullptr;
    }
    delete[] pixelColors;
    return pixelMap;
}

std::optional<DragData> DragTestHelper::CreateDragData(int32_t sourceType,
    int32_t pointerId, int32_t dragNum, bool hasCoordinateCorrected, int32_t shadowNum)
{
    CALL_DEBUG_ENTER;
    DragData dragData;
    for (int32_t i = 0; i < shadowNum; i++) {
        std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
        if (pixelMap == nullptr) {
            FI_HILOGE("pixelMap nullptr");
            return std::nullopt;
        }
        dragData.shadowInfos.push_back({ pixelMap, g_shadowinfo_x, g_shadowinfo_y });
    }
    dragData.buffer = std::vector<uint8_t>(MAX_BUFFER_SIZE, 0);
    dragData.filterInfo = FILTER_INFO;
    dragData.udKey = UD_KEY;
    dragData.sourceType = sourceType;
    dragData.extraInfo = EXTRA_INFO;
    dragData.displayId = DISPLAY_ID;
    dragData.pointerId = pointerId;
    dragData.dragNum = dragNum;
    dragData.displayX = DISPLAY_X;
    dragData.displayY = DISPLAY_Y;
    dragData.hasCoordinateCorrected = hasCoordinateCorrected;
    dragData.hasCanceledAnimation = HAS_CANCELED_ANIMATION;
    return dragData;
}

void DragTestHelper::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}

void TestStartDragListener::OnDragEndMessage(const DragNotifyMsg &msg)
{
    FI_HILOGD("DisplayX:%{public}d, displayY:%{public}d, targetPid:%{public}d, result:%{public}d",
        msg.displayX, msg.displayY, msg.targetPid, static_cast<int32_t>(msg.result));
    if (function_ != nullptr) {
        function_(msg);
    }
    FI_HILOGD("Test OnDragEndMessage");
}

void TestStartDragListener::OnHideIconMessage()
{
    FI_HILOGD("Test OnHideIconMessage");
}

void DragListenerTest::OnDragMessage(DragState state)
{
    if (moduleName_.empty()) {
        moduleName_ = std::string("DragListenerTest");
    }
    FI_HILOGD("%{public}s, state:%{public}s", moduleName_.c_str(), PrintDragMessage(state).c_str());
}

std::string DragListenerTest::PrintDragMessage(DragState state)
{
    std::string type = "unknow";
    const std::map<DragState, std::string> stateType = {
        { DragState::ERROR, "error"},
        { DragState::START, "start"},
        { DragState::STOP, "stop"},
        { DragState::CANCEL, "cancel"}
    };
    auto item = stateType.find(state);
    if (item != stateType.end()) {
        type = item->second;
    }
    return type;
}

void SubscriptListenerTest::OnMessage(DragCursorStyle style)
{
    SetDragSyle(style);
    if (moduleName_.empty()) {
        moduleName_ = std::string("SubscriptListenerTest");
    }
    FI_HILOGD("SubscriptListener, %{public}s, state:%{public}s",
        moduleName_.c_str(), PrintStyleMessage(style).c_str());
}

DragCursorStyle SubscriptListenerTest::GetDragStyle()
{
    return dragStyle_;
}

void SubscriptListenerTest::SetDragSyle(DragCursorStyle style)
{
    dragStyle_ = style;
}

std::string SubscriptListenerTest::PrintStyleMessage(DragCursorStyle style)
{
    std::string type = "unknow";
    const std::map<DragCursorStyle, std::string> cursorStyles = {
        { DragCursorStyle::DEFAULT, "default"},
        { DragCursorStyle::FORBIDDEN, "forbidden"},
        { DragCursorStyle::COPY, "copy"},
        { DragCursorStyle::MOVE, "move"}
    };
    auto item = cursorStyles.find(style);
    if (item != cursorStyles.end()) {
        type = item->second;
    }
    return type;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS