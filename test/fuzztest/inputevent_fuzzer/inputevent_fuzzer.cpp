/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "inputevent_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

#include "net_packet.h"
#include "input_event_transmission/input_event_serialization.h"
#include "input_event_transmission/input_event_sampler.h"

namespace {
    constexpr size_t THRESHOLD = 4;
    constexpr int32_t MAX_POINTER_ITEMS = 10;
    constexpr int32_t MAX_KEY_ITEMS = 10;
    constexpr int32_t MAX_BUFFER_SIZE = 100;
    constexpr uint32_t MAX_TEST_CASE = 3;

    enum class TestCase : uint32_t {
        InputEventSerialization = 0,
        KeyEventSerialization = 1,
        InputEventSampler = 2,
        NetPacketOperations = 3,
    };
}

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

void FuzzInputEventSerialization(FuzzedDataProvider &provider)
{
    auto pointerEvent = MMI::PointerEvent::Create();
    if (pointerEvent == nullptr) {
        return;
    }

    pointerEvent->SetId(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetActionTime(provider.ConsumeIntegral<int64_t>());
    pointerEvent->SetAction(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetActionStartTime(provider.ConsumeIntegral<int64_t>());
    pointerEvent->SetDeviceId(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetTargetDisplayId(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetPointerAction(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetPointerId(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetSourceType(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetButtonId(provider.ConsumeIntegral<int32_t>());

    int32_t numPointerItems = provider.ConsumeIntegralInRange<int32_t>(1, MAX_POINTER_ITEMS);
    for (int32_t i = 0; i < numPointerItems; ++i) {
        MMI::PointerEvent::PointerItem item;
        item.SetPointerId(provider.ConsumeIntegral<int32_t>());
        item.SetDisplayX(provider.ConsumeIntegral<int32_t>());
        item.SetDisplayY(provider.ConsumeIntegral<int32_t>());
        item.SetRawDx(provider.ConsumeIntegral<int32_t>());
        item.SetRawDy(provider.ConsumeIntegral<int32_t>());
        item.SetPressed(provider.ConsumeBool());
        pointerEvent->AddPointerItem(item);
    }

    NetPacket pkt(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    int64_t interceptorTime = provider.ConsumeIntegral<int64_t>();

    InputEventSerialization::Marshalling(pointerEvent, pkt, interceptorTime);

    auto pointerEvent2 = MMI::PointerEvent::Create();
    int64_t interceptorTime2 = 0;
    InputEventSerialization::Unmarshalling(pkt, pointerEvent2, interceptorTime2);
}

void FuzzKeyEventSerialization(FuzzedDataProvider &provider)
{
    auto keyEvent = MMI::KeyEvent::Create();
    if (keyEvent == nullptr) {
        return;
    }

    keyEvent->SetId(provider.ConsumeIntegral<int32_t>());
    keyEvent->SetActionTime(provider.ConsumeIntegral<int64_t>());
    keyEvent->SetAction(provider.ConsumeIntegral<int32_t>());
    keyEvent->SetKeyCode(provider.ConsumeIntegral<int32_t>());
    keyEvent->SetKeyAction(provider.ConsumeIntegral<int32_t>());
    keyEvent->SetDeviceId(provider.ConsumeIntegral<int32_t>());

    int32_t numKeyItems = provider.ConsumeIntegralInRange<int32_t>(1, MAX_KEY_ITEMS);
    for (int32_t i = 0; i < numKeyItems; ++i) {
        MMI::KeyEvent::KeyItem keyItem;
        keyItem.SetKeyCode(provider.ConsumeIntegral<int32_t>());
        keyItem.SetDownTime(provider.ConsumeIntegral<int64_t>());
        keyItem.SetDeviceId(provider.ConsumeIntegral<int32_t>());
        keyItem.SetPressed(provider.ConsumeBool());
        keyEvent->AddKeyItem(keyItem);
    }

    NetPacket pkt(MessageId::DSOFTBUS_INPUT_KEY_EVENT);
    InputEventSerialization::KeyEventToNetPacket(keyEvent, pkt);

    auto keyEvent2 = MMI::KeyEvent::Create();
    InputEventSerialization::NetPacketToKeyEvent(pkt, keyEvent2);
}

void FuzzInputEventSampler(FuzzedDataProvider &provider)
{
    InputEventSampler sampler;

    auto pointerEvent = MMI::PointerEvent::Create();
    if (pointerEvent == nullptr) {
        return;
    }

    pointerEvent->SetPointerAction(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetPointerId(provider.ConsumeIntegral<int32_t>());
    pointerEvent->SetSourceType(provider.ConsumeIntegral<int32_t>());

    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(provider.ConsumeIntegral<int32_t>());
    item.SetDisplayX(provider.ConsumeIntegral<int32_t>());
    item.SetDisplayY(provider.ConsumeIntegral<int32_t>());
    item.SetRawDx(provider.ConsumeIntegral<int32_t>());
    item.SetRawDy(provider.ConsumeIntegral<int32_t>());
    item.SetToolType(provider.ConsumeIntegral<int32_t>());
    pointerEvent->AddPointerItem(item);

    sampler.SetPointerEventHandler([](std::shared_ptr<MMI::PointerEvent> event) {
        FI_HILOGD("Sampler received pointer event");
    });

    sampler.OnPointerEvent(pointerEvent);
}

void FuzzNetPacketOperations(FuzzedDataProvider &provider)
{
    NetPacket pkt(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);

    pkt << provider.ConsumeIntegral<int32_t>();
    pkt << provider.ConsumeIntegral<int64_t>();
    pkt << provider.ConsumeIntegral<uint32_t>();
    pkt << provider.ConsumeBool();
    pkt << provider.ConsumeFloatingPoint<double>();
    pkt << provider.ConsumeFloatingPoint<float>();

    size_t bufferSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
    std::vector<uint8_t> buffer = provider.ConsumeBytes<uint8_t>(bufferSize);
    for (uint8_t byte : buffer) {
        pkt << byte;
    }

    int32_t intVal;
    int64_t int64Val;
    uint32_t uint32Val;
    bool boolVal;
    double doubleVal;
    float floatVal;

    pkt >> intVal;
    pkt >> int64Val;
    pkt >> uint32Val;
    pkt >> boolVal;
    pkt >> doubleVal;
    pkt >> floatVal;

    pkt.ChkRWError();
}

bool InputEventFuzzTest(FuzzedDataProvider &provider)
{
    TestCase testCase = static_cast<TestCase>(provider.ConsumeIntegralInRange<uint32_t>(0, MAX_TEST_CASE));

    switch (testCase) {
        case TestCase::InputEventSerialization:
            FuzzInputEventSerialization(provider);
            break;
        case TestCase::KeyEventSerialization:
            FuzzKeyEventSerialization(provider);
            break;
        case TestCase::InputEventSampler:
            FuzzInputEventSampler(provider);
            break;
        case TestCase::NetPacketOperations:
            FuzzNetPacketOperations(provider);
            break;
        default:
            break;
    }

    return true;
}

} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::Msdp::DeviceStatus::Cooperate::InputEventFuzzTest(provider);
    return 0;
}

