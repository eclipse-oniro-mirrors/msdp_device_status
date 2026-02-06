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

#include "drag_vsync_station.h"

#include <cstdint>

#include "concurrent_task_client.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "include/util.h"
#include "qos.h"
#include "transaction/rs_interfaces.h"
#undef LOG_TAG
#define LOG_TAG "DragVSyncStation"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::string THREAD_NAME { "os_dragRenderRunner" };
constexpr int32_t INVALID_VALUE { -1 };
}

int32_t DragVSyncStation::RequestFrame(int32_t frameType, std::shared_ptr<DragFrameCallback> callback)
{
    CHKPR(callback, RET_ERR);
    if (frameType < TYPE_FLUSH_DRAG_POSITION || frameType >= REQUEST_TYPE_MAX) {
        FI_HILOGE("Frame callback type is invalid, type:%{public}d", frameType);
        return RET_ERR;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    int32_t ret = Init();
    if (ret != RET_OK) {
        FI_HILOGE("Init receiver failed");
        return RET_ERR;
    }
    ret = receiver_->RequestNextVSync(frameCallback_);
    if (ret != RET_OK) {
        FI_HILOGE("Request next vSync failed");
        return RET_ERR;
    }
    vSyncCallbacks_.emplace(frameType, callback);
    return RET_OK;
}

void DragVSyncStation::StopVSyncRequest()
{
    FI_HILOGI("StopVSyncRequest in");
    std::lock_guard<std::mutex> lock(mtx_);
    vSyncCallbacks_.erase(vSyncCallbacks_.begin(), vSyncCallbacks_.end());
    if (handler_ != nullptr) {
        handler_->RemoveAllEvents();
        handler_->RemoveAllFileDescriptorListeners();
        handler_ = nullptr;
    }
    receiver_ = nullptr;
    vSyncPeriod_ = 0;
    if (mmiHandleTid_ > 0) {
        OHOS::QOS::ResetQosForOtherThread(mmiHandleTid_);
        mmiHandleTid_ = INVALID_VALUE;
    }
}

uint64_t DragVSyncStation::GetVSyncPeriod()
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (vSyncPeriod_ != 0) {
        return vSyncPeriod_;
    }
    int64_t period = 0;
    if (receiver_ != nullptr) {
        int32_t ret = receiver_->GetVSyncPeriod(period);
        if (ret != RET_OK) {
            FI_HILOGE("GetVSyncPeriod failed");
        }
    }
    vSyncPeriod_ = (period <= 0 ? 0 : static_cast<uint64_t>(period));
    return vSyncPeriod_;
}

int32_t DragVSyncStation::Init()
{
    FI_HILOGD("Init receiver in");
    if (receiver_ != nullptr) {
        return RET_OK;
    }
    if (handler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
        CHKPR(runner, RET_ERR);
        handler_ = std::make_shared<AppExecFwk::EventHandler>(std::move(runner));
        SetThreadQosLevel(handler_);
    }
    mmiHandleTid_ = gettid();
    SetQosForOtherThread(mmiHandleTid_);
    CHKPR(handler_, RET_ERR);
    receiver_ = Rosen::RSInterfaces::GetInstance().CreateVSyncReceiver("DragVSyncStation", handler_);
    CHKPR(receiver_, RET_ERR);
    int32_t ret = receiver_->Init();
    if (ret != RET_OK) {
        FI_HILOGE("Init receiver, %{public}d", ret);
        return RET_ERR;
    }
    frameCallback_ = {
        .userData_ = this,
        .callback_ = OnVSync,
    };
    FI_HILOGI("Init receiver success");
    return RET_OK;
}

void DragVSyncStation::SetThreadQosLevel(std::shared_ptr<AppExecFwk::EventHandler> handler)
{
    if (handler != nullptr) {
        handler->PostTask([]() {
            std::unordered_map<std::string, std::string> payload;
            payload["pid"] = std::to_string(getpid());
            OHOS::ConcurrentTask::ConcurrentTaskClient::GetInstance().RequestAuth(payload);
            auto ret = OHOS::QOS::SetThreadQos(OHOS::QOS::QosLevel::QOS_USER_INTERACTIVE);
            if (ret != 0) {
                FI_HILOGE("SetThreadQos failed, ret:%{public}d", ret);
            } else {
                FI_HILOGE("SetThreadQos success");
            }
        });
    }
}

void DragVSyncStation::SetQosForOtherThread(int32_t tid)
{
    std::unordered_map<std::string, std::string> payload;
    payload["pid"] = std::to_string(getpid());
    OHOS::ConcurrentTask::ConcurrentTaskClient::GetInstance().RequestAuth(payload);
    auto ret = OHOS::QOS::SetQosForOtherThread(OHOS::QOS::QosLevel::QOS_USER_INTERACTIVE, tid);
    if (ret != 0) {
        FI_HILOGE("Set mmi thread qos failed, ret:%{public}d", ret);
    } else {
        FI_HILOGI("Set mmi thread qos success");
    }
}

void DragVSyncStation::OnVSyncInner(uint64_t nanoTimestamp)
{
    std::map<int32_t, std::shared_ptr<DragFrameCallback>> vSyncCallbacks;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        vSyncCallbacks.swap(vSyncCallbacks_);
    }
    for (auto const &callback : vSyncCallbacks) {
        if (callback.second != nullptr) {
            (*callback.second)(nanoTimestamp);
        }
    }
}

void DragVSyncStation::OnVSync(uint64_t nanoTimestamp, void *client)
{
    auto vSyncClient = static_cast<DragVSyncStation *>(client);
    if (vSyncClient != nullptr) {
        vSyncClient->OnVSyncInner(nanoTimestamp);
    } else {
        FI_HILOGE("VSync client is null");
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS