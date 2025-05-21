/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MESSAGE_PARCEL_MOCK_H
#define MESSAGE_PARCEL_MOCK_H

#include <memory>
#include <string>
#include <gmock/gmock.h>

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "utility.h"
#include "nocopyable.h"

#include "message_parcel.h"
#include "intention_identity.h"
#include "iremote_boomerang_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangParamMock : public ParamBase {
public:
    static BoomerangParamMock& GetMock()
    {
        return *g_mock;
    }

    BoomerangParamMock();
    ~BoomerangParamMock();

    MOCK_METHOD(bool, Marshalling, (MessageParcel &parcel), (const, override));
    MOCK_METHOD(bool, Unmarshalling, (MessageParcel &parcel), (override));

private:
    static BoomerangParamMock *g_mock;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif