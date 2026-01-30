/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_MSDP_CLIENT_IMPL_H
#define DEVICESTATUS_MSDP_CLIENT_IMPL_H

#include <memory>
#include <mutex>
#include <map>

#include "devicestatus_msdp_interface.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DeviceStatusMsdpClientImpl : public IMsdp::MsdpAlgoCallback,
    public std::enable_shared_from_this<DeviceStatusMsdpClientImpl> {
public:
    using CallbackManager = std::function<int32_t(const Data&)>;
    using LoadMockLibraryFunc = IMsdp* (*)();
    using LoadMockLibraryPtr = void *(*)(IMsdp*);
    DeviceStatusMsdpClientImpl();
    ErrCode InitMsdpImpl(Type type);
    ErrCode Disable(Type type);
    ErrCode GetSensorHdi(Type type);
    ErrCode GetAlgoAbility(Type type);
    ErrCode RegisterImpl(const CallbackManager &callback);
    int32_t MsdpCallback(const Data &data);
    ErrCode StartMock(Type type);
    ErrCode RegisterMock();
    ErrCode UnregisterMock();
    ErrCode RegisterAlgo();
    ErrCode UnregisterAlgo();
    Data SaveObserverData(const Data &data);
    std::map<Type, OnChangedValue> GetObserverData() const;
    void GetDeviceStatusTimestamp();
    void GetLongtitude();
    void GetLatitude();
    ErrCode LoadAlgoLibrary();
    ErrCode UnloadAlgoLibrary();
    ErrCode LoadMockLibrary();
    ErrCode UnloadMockLibrary();
    ErrCode MockHandle(Type type);
    ErrCode AlgoHandle(Type type);
    ErrCode StartAlgo(Type type);
    ErrCode AlgoDisable(Type type);
    ErrCode MockDisable(Type type);
    ErrCode SensorHdiDisable(Type type);

private:
    ErrCode ImplCallback(const Data &data);
    IMsdp* GetAlgoInst(Type type);
    IMsdp* GetMockInst(Type type);
    void OnResult(const Data &data) override;

private:
    std::shared_ptr<MsdpAlgoCallback> callback_ { nullptr };
    MsdpAlgoHandle mock_;
    MsdpAlgoHandle algo_;
    std::map<Type, uint32_t> algoCallCounts_;
    std::map<Type, uint32_t> mockCallCounts_;
    std::map<Type, OnChangedValue> deviceStatusDatas_;
    DeviceStatusMsdpClientImpl::CallbackManager callBacksMgr_;
    IMsdp* iAlgo_ { nullptr };
    IMsdp* iMock_ { nullptr };
    std::mutex mutex_;
    bool notifyManagerFlag_ { false };
    mutable std::mutex callMutex_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_MSDP_CLIENT_IMPL_H
