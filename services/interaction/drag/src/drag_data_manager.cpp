/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "drag_data_manager.h"

#include "hitrace_meter.h"

#include "devicestatus_define.h"
#include "drag_data.h"
#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MSDP_DOMAIN_ID, "DragDataManager" };
constexpr int32_t DEFAULT_DISPLAY_ID { 0 };
} // namespace

DragDataManager::DragDataManager() = default;
DragDataManager::~DragDataManager() = default;

void DragDataManager::SetDragStyle(DragCursorStyle style)
{
    dragStyle_ = style;
}

void DragDataManager::Init(const DragData &dragData)
{
    dragData_ = dragData;
    if (dragData.displayId < DEFAULT_DISPLAY_ID) {
        dragData_.displayId = DEFAULT_DISPLAY_ID;
        FI_HILOGW("Correct the value of displayId(%{public}d) to 0", dragData.displayId);
    }
    targetPid_ = -1;
    targetTid_ = -1;
}

void DragDataManager::SetShadowInfos(const std::vector<ShadowInfo> &shadowInfos)
{
    dragData_.shadowInfos = shadowInfos;
}

DragCursorStyle DragDataManager::GetDragStyle() const
{
    return dragStyle_;
}

DragData DragDataManager::GetDragData() const
{
    return dragData_;
}

void DragDataManager::SetDragWindowVisible(bool visible)
{
    visible_ = visible;
}

bool DragDataManager::GetDragWindowVisible() const
{
    return visible_;
}

void DragDataManager::SetTargetTid(int32_t targetTid)
{
    targetTid_ = targetTid;
}

int32_t DragDataManager::GetTargetTid() const
{
    return targetTid_;
}

void DragDataManager::SetTargetPid(int32_t pid)
{
    targetPid_ = pid;
}

int32_t DragDataManager::GetTargetPid() const
{
    return targetPid_;
}

int32_t DragDataManager::GetShadowOffset(int32_t& offsetX, int32_t& offsetY, int32_t& width, int32_t& height) const
{
    if (dragData_.shadowInfos.empty()) {
        FI_HILOGE("ShadowInfos is empty");
        return  RET_ERR;
    }
    offsetX = dragData_.shadowInfos.front().x;
    offsetY = dragData_.shadowInfos.front().y;
    auto pixelMap = dragData_.shadowInfos.front().pixelMap;
    CHKPR(pixelMap, RET_ERR);
    width = pixelMap->GetWidth();
    height = pixelMap->GetHeight();
    FI_HILOGD("offsetX:%{public}d, offsetY:%{public}d, width:%{public}d, height:%{public}d",
        offsetX, offsetY, width, height);
    return RET_OK;
}

void DragDataManager::ResetDragData()
{
    CALL_DEBUG_ENTER;
    dragData_ = { };
    previewStyle_ = { };
    dragStyle_ = DragCursorStyle::DEFAULT;
    visible_ = false;
    targetTid_ = -1;
    targetPid_ = -1;
    isMotionDrag_ = false;
}

void DragDataManager::SetMotionDrag(bool isMotionDrag)
{
    isMotionDrag_ = isMotionDrag;
    FI_HILOGD("isMotionDrag_:%{public}d", isMotionDrag_);
}

bool DragDataManager::IsMotionDrag() const
{
    FI_HILOGD("isMotionDrag_:%{public}d", isMotionDrag_);
    return isMotionDrag_;
}

void DragDataManager::SetPreviewStyle(const PreviewStyle &previewStyle)
{
    previewStyle_ = previewStyle;
}

PreviewStyle DragDataManager::GetPreviewStyle()
{
    return previewStyle_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS