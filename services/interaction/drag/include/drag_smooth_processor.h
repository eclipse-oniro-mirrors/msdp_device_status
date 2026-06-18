/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DRAG_SMOOTH_PROCESSOR_H
#define DRAG_SMOOTH_PROCESSOR_H

#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct DragMoveEvent {
    float displayX { 0.0f };
    float displayY { 0.0f };
    int32_t displayId { -1 };
    uint64_t timestamp { 0 };
};

class DragSmoothProcessor {
public:
    void InsertEvent(const DragMoveEvent &event);
    DragMoveEvent SmoothMoveEvent(uint64_t nanoTimestamp, uint64_t vSyncPeriod);
    void ResetParameters();

private:
    std::optional<DragMoveEvent> GetInterpolatedEvent(const DragMoveEvent &historyAvgEvent,
        const DragMoveEvent &currentAvgEvent, uint64_t nanoTimestamp);
    std::optional<DragMoveEvent> Resample(const std::vector<DragMoveEvent>& history,
        const std::vector<DragMoveEvent>& current, uint64_t nanoTimestamp);
    void DumpMoveEvent(const std::vector<DragMoveEvent>& history,
        const std::vector<DragMoveEvent>& current, const DragMoveEvent &historyAvgEvent,
        const DragMoveEvent &currentAvgEvent, const DragMoveEvent &latestEvent);
    DragMoveEvent GetNearestEvent(const std::vector<DragMoveEvent>& events, uint64_t nanoTimestamp);
    DragMoveEvent GetAvgCoordinate(const std::vector<DragMoveEvent>& events);
    std::optional<DragMoveEvent> GetResampleEvent(const std::vector<DragMoveEvent>& history,
        const std::vector<DragMoveEvent>& current, uint64_t nanoTimestamp);
    std::vector<DragMoveEvent> moveEvents_;
    std::vector<DragMoveEvent> historyEvents_;
    std::mutex mtx_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_SMOOTH_PROCESSOR_H