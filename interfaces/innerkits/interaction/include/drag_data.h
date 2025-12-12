/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef DRAG_DATA_H
#define DRAG_DATA_H

#include <cmath>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ui/rs_node.h"
#include "pixel_map.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr size_t MAX_BUFFER_SIZE { 512 };
constexpr size_t MAX_UDKEY_SIZE { 100 };
constexpr size_t MAX_SUMMARY_SIZE { 200 };
constexpr int32_t SHADOW_NUM_LIMIT { 3 };
constexpr float EPSILON { 1E-6 };
constexpr int32_t MAX_ANIMATION_DURATION_MS { 1000 };

struct ShadowInfo {
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap { nullptr };
    int32_t x { -1 };
    int32_t y { -1 };

    bool operator == (const ShadowInfo &other) const
    {
        if (pixelMap == nullptr && other.pixelMap == nullptr) {
            return x == other.x && y == other.y;
        }
        if (pixelMap == nullptr || other.pixelMap == nullptr) {
            return false;
        }
        return pixelMap->IsSameImage(*(other.pixelMap)) && x == other.x && y == other.y;
    }

    bool operator != (const ShadowInfo &other) const
    {
        return !(*this == other);
    }
};

struct DragData {
    std::vector<ShadowInfo> shadowInfos;
    std::vector<uint8_t> buffer;
    std::string udKey;
    std::string extraInfo;
    std::string filterInfo;
    int32_t sourceType { -1 };
    int32_t dragNum { -1 };
    int32_t pointerId { -1 };
    int32_t displayX { -1 };
    int32_t displayY { -1 };
    int32_t displayId { -1 };
    int32_t mainWindow { -1 };
    bool hasCanceledAnimation { false };
    bool hasCoordinateCorrected { false };
    std::map<std::string, int64_t> summarys;
    bool isDragDelay { false };
    std::map<std::string, int64_t> detailedSummarys;
    std::map<std::string, std::vector<int32_t>> summaryFormat;
    int32_t summaryVersion { 0 };
    int64_t summaryTotalSize { -1 };
    std::string summaryTag;
    int32_t materialId { -1 };
    bool isSetMaterialFilter { false };
    std::shared_ptr<Rosen::Filter> materialFilter { nullptr };
    std::string appCallee;
    std::string appCaller;

    bool operator == (const DragData &other) const
    {
        return shadowInfos == other.shadowInfos && buffer == other.buffer && udKey == other.udKey &&
               filterInfo == other.filterInfo && extraInfo == other.extraInfo && sourceType == other.sourceType &&
               dragNum == other.dragNum && pointerId == other.pointerId && displayX == other.displayX &&
               displayY == other.displayY && displayId == other.displayId &&
               hasCanceledAnimation == other.hasCanceledAnimation &&
               hasCoordinateCorrected == other.hasCoordinateCorrected && summarys == other.summarys &&
               appCallee == other.appCallee && appCaller == other.appCaller && isDragDelay == other.isDragDelay &&
               detailedSummarys == other.detailedSummarys && summaryFormat == other.summaryFormat &&
               summaryTotalSize == other.summaryTotalSize && summaryVersion == other.summaryVersion &&
               summaryTag == other.summaryTag && materialId == other.materialId &&
               isSetMaterialFilter == other.isSetMaterialFilter;
    }

    bool operator != (const DragData &other) const
    {
        return !(*this == other);
    }
};

enum class DragState {
    ERROR = 0,
    START = 1,
    STOP = 2,
    CANCEL = 3,
    MOTION_DRAGGING = 4
};

enum class DragResult {
    DRAG_SUCCESS = 0,
    DRAG_FAIL = 1,
    DRAG_CANCEL = 2,
    DRAG_EXCEPTION = 3
};

struct DragEventInfo {
    std::string sourcePkgName;
    std::string targetPkgName;
};

enum class DragBehavior {
    UNKNOWN = -1,
    COPY = 0,
    MOVE = 1
};

struct DragDropResult {
    DragResult result { DragResult::DRAG_FAIL };
    bool hasCustomAnimation { false };
    int32_t mainWindow { -1 };
    DragBehavior dragBehavior { DragBehavior::UNKNOWN };
};

struct DragAnimationData {
    int32_t displayX { -1 };
    int32_t displayY { -1 };
    int32_t offsetX { -1 };
    int32_t offsetY { -1 };
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap { nullptr };
};

struct DragNotifyMsg {
    int32_t displayX { -1 };
    int32_t displayY { -1 };
    int32_t targetPid { -1 };
    DragResult result { DragResult::DRAG_FAIL };
    DragBehavior dragBehavior { DragBehavior::UNKNOWN };
};

struct DragItemStyle {
    uint32_t foregroundColor { 0 };
    int32_t radius { 0 };
    uint32_t alpha { 0 };

    bool operator == (const DragItemStyle &style) const
    {
        return foregroundColor == style.foregroundColor &&
               radius == style.radius && alpha == style.alpha;
    }

    bool operator!=(const DragItemStyle &style) const
    {
        return !(*this == style);
    }
};

enum class PreviewType {
    FOREGROUND_COLOR = 0,
    OPACITY = 1,
    RADIUS = 2,
    SCALE = 3
};

struct PreviewStyle {
    std::vector<PreviewType> types;
    uint32_t foregroundColor { 0 };
    int32_t opacity { -1 };
    float radius { -1.0F };
    float scale { -1.0F };

    bool operator == (const PreviewStyle &other) const
    {
        return types == other.types && foregroundColor == other.foregroundColor && opacity == other.opacity &&
               radius == other.radius && fabsf(scale - other.scale) < EPSILON;
    }

    bool operator != (const PreviewStyle &other) const
    {
        return !(*this == other);
    }
};

struct ShadowOffset {
    int32_t offsetX { -1 };
    int32_t offsetY { -1 };
    int32_t width { -1 };
    int32_t height { -1 };

    bool operator == (const ShadowOffset &other) const
    {
        return offsetX == other.offsetX && offsetY == other.offsetY &&
               width == other.width && height == other.height;
    }

    bool operator != (const ShadowOffset &other) const
    {
        return !(*this == other);
    }
};

struct PreviewAnimation {
    int32_t duration { -1 };
    std::string curveName;
    std::vector<float> curve;
};

enum class DragCursorStyle {
    DEFAULT = 0,
    FORBIDDEN,
    COPY,
    MOVE
};

enum class DragAction {
    INVALID = -1,
    MOVE = 0,
    COPY = 1
};

struct DragBundleInfo {
    std::string bundleName;
    bool isCrossDevice { false };
};

struct DragRadarPackageName {
    std::string packageName;
    std::string appCallee;
    std::string appCaller;
    std::string peerNetId;
    int32_t dragNum { -1 };
};

struct DragSummaryInfo {
    std::map<std::string, int64_t> summarys;
    std::map<std::string, int64_t> detailedSummarys;
    std::map<std::string, std::vector<int32_t>> summaryFormat;
    int32_t version { 0 };
    int64_t totalSize { -1 };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_DATA_H