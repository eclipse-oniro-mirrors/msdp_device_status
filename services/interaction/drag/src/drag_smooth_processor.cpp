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

#include "drag_smooth_processor.h"

#include <utility>

#include "devicestatus_common.h"
#include "include/util.h"

#undef LOG_TAG
#define LOG_TAG "DragSmoothProcessor"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr uint64_t ONE_MS_IN_NS { 1 * 1000 * 1000 }; // 1ms
constexpr int32_t RESAMPLE_COORD_TIME_THRESHOLD { 20 * 1000 * 1000 };  // 20ms
constexpr uint64_t INTERPOLATION_THRESHOLD { 100 * 1000 * 1000 }; // 100ms
constexpr size_t PREVIOUS_HISTORY_EVENT { 2 };
}
void DragSmoothProcessor::InsertEvent(const DragMoveEvent &event)
{
    std::lock_guard<std::mutex> lock(mtx_);
    moveEvents_.emplace_back(event);
}

DragMoveEvent DragSmoothProcessor::SmoothMoveEvent(uint64_t nanoTimestamp, uint64_t vSyncPeriod)
{
    std::lock_guard<std::mutex> lock(mtx_);
    resampleTimeStamp_ = nanoTimestamp - vSyncPeriod + ONE_MS_IN_NS;
    auto targetTimeStamp = resampleTimeStamp_;
    std::vector<DragMoveEvent> currentEvents;
    currentEvents.swap(moveEvents_);
    size_t historyEventSize = historyEvents_.size();
    if (currentEvents.empty() && historyEventSize > 0) {
        if (historyEventSize > 1) {
            auto event = GetInterpolatedEvent(historyEvents_.at(historyEventSize - PREVIOUS_HISTORY_EVENT),
                historyEvents_.back(), targetTimeStamp);
            auto resampleEvent = event.has_value() ? event.value() : historyEvents_.back();
            historyEvents_ = currentEvents;
            historyEvents_.emplace_back(resampleEvent);
            return resampleEvent;
        } else {
            DragMoveEvent event = historyEvents_.back();
            event.timestamp = targetTimeStamp;
            historyEvents_ = currentEvents;
            historyEvents_.emplace_back(event);
            return event;
        }
    }
    DragMoveEvent latestEvent = currentEvents.back();
    auto resampleEvent = GetResampleEvent(historyEvents_, currentEvents, targetTimeStamp);
    historyEvents_ = currentEvents;
    return resampleEvent.has_value() ? resampleEvent.value() : latestEvent;
}

void DragSmoothProcessor::ResetParameters()
{
    std::lock_guard<std::mutex> lock(mtx_);
    moveEvents_.clear();
    historyEvents_.clear();
    resampleTimeStamp_ = 0;
}

std::optional<DragMoveEvent> DragSmoothProcessor::GetResampleEvent(const std::vector<DragMoveEvent>& history,
    const std::vector<DragMoveEvent>& current, uint64_t nanoTimestamp)
{
    auto event = Resample(history, current, nanoTimestamp);
    DragMoveEvent nearestEvent = GetNearestEvent(current, nanoTimestamp);
    return event.has_value() ? event.value() : nearestEvent;
}

DragMoveEvent DragSmoothProcessor::GetNearestEvent(const std::vector<DragMoveEvent>& events, uint64_t nanoTimestamp)
{
    DragMoveEvent nearestEvent;
    uint64_t gap = UINT64_MAX;
    for (const auto &event : events) {
        if (event.timestamp == nanoTimestamp) {
            nearestEvent = event;
            return nearestEvent;
        }
        if (event.timestamp > nanoTimestamp) {
            if (event.timestamp - nanoTimestamp < gap) {
                gap = event.timestamp - nanoTimestamp;
                nearestEvent = event;
            }
        } else {
            if (nanoTimestamp - event.timestamp < gap) {
                gap = nanoTimestamp - event.timestamp;
                nearestEvent = event;
            }
        }
    }
    return nearestEvent;
}

std::optional<DragMoveEvent> DragSmoothProcessor::Resample(const std::vector<DragMoveEvent>& history,
    const std::vector<DragMoveEvent>& current, uint64_t nanoTimestamp)
{
    if (history.empty() || current.empty()) {
        FI_HILOGW("history or current is empty, history size:%{public}zu, current size:%{public}zu,"
            "nanoTimestamp:%{public}" PRId64, history.size(), current.size(), nanoTimestamp);
        return std::nullopt;
    }
    DragMoveEvent latestEvent;
    for (auto const &event : current) {
        if (latestEvent.timestamp < event.timestamp) {
            latestEvent = event;
        }
    }
    if (nanoTimestamp > RESAMPLE_COORD_TIME_THRESHOLD + latestEvent.timestamp) {
        FI_HILOGW("latestEvent is beyond the sampling range, use this this latest event, x:%{private}f, "
            "y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d, sampling nanoTimestamp:%{public}" PRId64,
            latestEvent.displayX, latestEvent.displayY, latestEvent.timestamp, latestEvent.displayId, nanoTimestamp);
        return latestEvent;
    }
    auto historyAvgEvent = GetAvgCoordinate(history);
    auto currentAvgEvent = GetAvgCoordinate(current);
    DumpMoveEvent(history, current, historyAvgEvent, currentAvgEvent, latestEvent);
    return GetInterpolatedEvent(historyAvgEvent, currentAvgEvent, nanoTimestamp);
}

std::optional<DragMoveEvent> DragSmoothProcessor::GetInterpolatedEvent(const DragMoveEvent &historyAvgEvent,
    const DragMoveEvent &currentAvgEvent, uint64_t nanoTimestamp)
{
    if ((nanoTimestamp <= historyAvgEvent.timestamp) || (nanoTimestamp == currentAvgEvent.timestamp) ||
        (currentAvgEvent.timestamp <= historyAvgEvent.timestamp) ||
        ((currentAvgEvent.timestamp - historyAvgEvent.timestamp) > INTERPOLATION_THRESHOLD)) {
            FI_HILOGW("No need linear interpolation, historyAvgEvent x:%{private}f, "
            "y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d, currentAvgEvent x:%{private}f"
            "y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d, nanoTimestamp: %{public}" PRId64,
            historyAvgEvent.displayX, historyAvgEvent.displayY, historyAvgEvent.timestamp, historyAvgEvent.displayId,
            currentAvgEvent.displayX, currentAvgEvent.displayY, currentAvgEvent.timestamp, currentAvgEvent.displayId,
            nanoTimestamp);
        return std::nullopt;
    }
    DragMoveEvent event;
    if (nanoTimestamp < currentAvgEvent.timestamp) {
        float alpha = static_cast<float>(nanoTimestamp - historyAvgEvent.timestamp) /
            (currentAvgEvent.timestamp - historyAvgEvent.timestamp);
        event.displayX = historyAvgEvent.displayX + alpha * (currentAvgEvent.displayX - historyAvgEvent.displayX);
        event.displayY = historyAvgEvent.displayY + alpha * (currentAvgEvent.displayY - historyAvgEvent.displayY);
        event.timestamp = nanoTimestamp;
        event.displayId = currentAvgEvent.displayId;
    } else if (nanoTimestamp > currentAvgEvent.timestamp) {
        float alpha = static_cast<float>(nanoTimestamp - currentAvgEvent.timestamp) /
            (currentAvgEvent.timestamp - historyAvgEvent.timestamp);
        event.displayX = currentAvgEvent.displayX + alpha * (currentAvgEvent.displayX - historyAvgEvent.displayX);
        event.displayY = currentAvgEvent.displayY + alpha * (currentAvgEvent.displayY - historyAvgEvent.displayY);
        event.timestamp = nanoTimestamp;
        event.displayId = currentAvgEvent.displayId;
    }
    return event;
}

void DragSmoothProcessor::DumpMoveEvent(const std::vector<DragMoveEvent>& history,
    const std::vector<DragMoveEvent>& current, const DragMoveEvent &historyAvgEvent,
    const DragMoveEvent &currentAvgEvent, const DragMoveEvent &latestEvent)
{
    for (const auto &event : history) {
        FI_HILOGD("history event, x:%{private}f, y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d",
            event.displayX, event.displayY, event.timestamp, event.displayId);
    }
    for (const auto &event : current) {
        FI_HILOGD("current event, x:%{private}f, y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d",
            event.displayX, event.displayY, event.timestamp, event.displayId);
    }
    FI_HILOGD("history average event, x:%{private}f, y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d",
        historyAvgEvent.displayX, historyAvgEvent.displayY, historyAvgEvent.timestamp, historyAvgEvent.displayId);
    FI_HILOGD("current average event, x:%{private}f, y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d",
        currentAvgEvent.displayX, currentAvgEvent.displayY, currentAvgEvent.timestamp, currentAvgEvent.displayId);
    FI_HILOGD("latest event, x:%{private}f, y:%{private}f, timestamp:%{public}" PRId64 "displayId:%{public}d",
        latestEvent.displayX, latestEvent.displayY, latestEvent.timestamp, latestEvent.displayId);
}

DragMoveEvent DragSmoothProcessor::GetAvgCoordinate(const std::vector<DragMoveEvent>& events)
{
    DragMoveEvent avgEvent;
    if (events.empty()) {
        FI_HILOGW("events is empty");
        return avgEvent;
    }
    int32_t i = 0;
    uint64_t lastTime = 0;
    for (const auto &event : events) {
        if ((lastTime == 0) || (lastTime != event.timestamp)) {
            avgEvent.displayX += event.displayX;
            avgEvent.displayY += event.displayY;
            avgEvent.timestamp += event.timestamp;
            avgEvent.displayId = event.displayId;
            lastTime = event.timestamp;
            i++;
        }
    }
    if (i != 0) {
        avgEvent.displayX /= i;
        avgEvent.displayY /= i;
        avgEvent.timestamp /= static_cast<uint64_t>(i);
    }
    return avgEvent;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS