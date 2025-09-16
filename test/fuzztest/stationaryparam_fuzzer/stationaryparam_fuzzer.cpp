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

#include "stationaryparam_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "singleton.h"

#define private public
#include "stationary_params.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "StationaryParamFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OHOS {
const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };

bool StationaryParamFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    int32_t type = provider.PickValueInArray({-1,0, 1, 2, 3, 4, 5, 6, 7, 8});
    int32_t event = provider.PickValueInArray({0, 1, 2, 3});
    int32_t latency = provider.PickValueInArray({-1, 1, 2, 3});
    MessageParcel parcel;
    if (!parcel.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !parcel.WriteBuffer(data, size) || !parcel.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    sptr<IRemoteDevStaCallback> callback = nullptr;
    SubscribeStationaryParam Param = { static_cast<Type>(type), static_cast<ActivityEvent>(event),
        static_cast<ReportLatencyNs>(latency), callback };
    Param.Marshalling(parcel);
    Param.Unmarshalling(parcel);
    GetStaionaryDataParam param1;
    param1.Marshalling(parcel);
    param1.Unmarshalling(parcel);
    GetStaionaryDataReply param2;
    bool ret = param2.Marshalling(parcel);
    ret = param2.Unmarshalling(parcel);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::StationaryParamFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS