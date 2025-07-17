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

#include "boomerangsubscribe_fuzzer.h"

#include "singleton.h"

#define private public
#include "boomerang_callback_stub.h"
#include "devicestatus_service.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangSubscribeFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangClientTestCallback : public BoomerangCallbackStub {
    public:
    private:
    BoomerangData data_;
};
namespace OHOS {
const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.msdp.Idevicestatus" };

bool BoomerangSubscribeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0) || !datas.WriteRemoteObject(callback->AsObject())) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::IIntentionIpcCode::COMMAND_SUBSCRIBE_CALLBACK), datas, reply, option);
    return true;
}
} // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::BoomerangSubscribeFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
