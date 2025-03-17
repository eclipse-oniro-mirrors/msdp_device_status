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
 
#include "coordination_message.h"
#include "i_coordination_listener.h"
#include "i_event_listener.h"
#include "i_hotarea_listener.h"
#include "i_tunnel_client.h"
#include "net_packet.h"
#include "socket_client.h"
#include "stream_client.h"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
 
class BoomerangClientInterface {
public:
    virtual ~BoomerangClientInterface() = default;
public:
    virtual int32_t Enable(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t Disable(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t Start(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t Stop(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t AddWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t RemoveWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t SetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t GetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    virtual int32_t Control(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
};
 
class BoomerangClientMock : public BoomerangClientInterface {
public:
    static BoomerangClientMock& GetMock()
    {
        return *g_mock;
    }
 
    BoomerangClientMock();
    ~BoomerangClientMock();
 
    MOCK_METHOD(int32_t, Enable, (Intention intention, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, Disable, (Intention intention, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, Start, (Intention intention, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, Stop, (Intention intention, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, AddWatch, (Intention intention, uint32_t id, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, RemoveWatch,
                (Intention intention, uint32_t id, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, SetParam, (Intention intention, uint32_t id, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, GetParam, (Intention intention, uint32_t id, ParamBase &data, ParamBase &reply), (override));
    MOCK_METHOD(int32_t, Control, (Intention intention, uint32_t id, ParamBase &data, ParamBase &reply), (override));
 
private:
    static BoomerangClientMock *g_mock;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif