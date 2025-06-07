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
#include "input_event_builder_test.h"
#include "ddm_adapter.h"

#undef LOG_TAG
#define LOG_TAG "InputEventBuilderTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
using namespace testing::ext;

namespace {
ContextService *g_instance = nullptr;
std::unique_ptr<IInputAdapter> input_;
std::unique_ptr<IPluginManager> pluginMgr_;
std::unique_ptr<IDSoftbusAdapter> dsoftbus_;
SocketSessionManager socketSessionMgr_;
InputEventBuilder *builder_ = {nullptr};
auto env_ = ContextService::GetInstance();
const std::string networkId_ = "1234";
constexpr int32_t LOC_INPUT_DEVICE_ID { 32 };
constexpr int32_t MIN_VIRTUAL_INPUT_DEVICE_ID { 1000 };
} // namespace

ContextService::ContextService()
{
    ddm_ = std::make_unique<DDMAdapter>();
}

ContextService::~ContextService() {}

IDelegateTasks& ContextService::GetDelegateTasks()
{
    return delegateTasks_;
}

IDeviceManager& ContextService::GetDeviceManager()
{
    return devMgr_;
}

ITimerManager& ContextService::GetTimerManager()
{
    return timerMgr_;
}

IDragManager& ContextService::GetDragManager()
{
    return dragMgr_;
}

ContextService* ContextService::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        ContextService *cooContext = new (std::nothrow) ContextService();
        CHKPL(cooContext);
        g_instance = cooContext;
    });
    return g_instance;
}

ISocketSessionManager& ContextService::GetSocketSessionManager()
{
    return socketSessionMgr_;
}

IDDMAdapter& ContextService::GetDDM()
{
    return *ddm_;
}

IPluginManager& ContextService::GetPluginManager()
{
    return *pluginMgr_;
}

IInputAdapter& ContextService::GetInput()
{
    return *input_;
}

IDSoftbusAdapter& ContextService::GetDSoftbus()
{
    return *dsoftbus_;
}

void InputEventBuilderTest::SetUpTestCase()
{
    ASSERT_NE(env_, nullptr);
    builder_ = new InputEventBuilder(env_);
    ASSERT_NE(builder_, nullptr);
    dsoftbus_ = std::make_unique<DSoftbusAdapter>();
    input_ = std::make_unique<InputAdapter>();
}

void InputEventBuilderTest::TearDownTestCase()
{
    delete builder_;
    builder_ = nullptr;
}

void InputEventBuilderTest::SetUp() {}
void InputEventBuilderTest::TearDown() {}

/**
 * @tc.name: EnableTest001
 * @tc.desc: Test EnableTest001
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, EnableTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Context context(env_);
    ASSERT_NO_FATAL_FAILURE(builder_->Enable(context));
}

/**
 * @tc.name: UpdateTest001
 * @tc.desc: Test UpdateTest001
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, UpdateTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Context context(env_);
    ASSERT_NO_FATAL_FAILURE(builder_->Update(context));
}

/**
 * @tc.name: OnPacketTest001
 * @tc.desc: Test OnPacketTest001
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, OnPacketTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->remoteNetworkId_ = "12345";
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    bool ret = builder_->OnPacket(networkId_, packet);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: OnPacketTest002
 * @tc.desc: Test OnPacketTest002
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, OnPacketTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->remoteNetworkId_ = "1234";
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    bool ret = builder_->OnPacket(networkId_, packet);
    ASSERT_EQ(ret, true);
    NetPacket packet1(MessageId::DSOFTBUS_INPUT_KEY_EVENT);
    ret = builder_->OnPacket(networkId_, packet1);
    ASSERT_EQ(ret, true);
    NetPacket packet2(MessageId::DSOFTBUS_RELAY_COOPERATE);
    ret = builder_->OnPacket(networkId_, packet2);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: OnPacketTest003
 * @tc.desc: Test OnPacketTest003
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, OnPacketTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->remoteNetworkId_ = "1234";
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    int32_t ret1 = InputEventSerialization::Marshalling(builder_->pointerEvent_, packet);
    ASSERT_EQ(ret1, RET_OK);
    bool ret = builder_->OnPacket(networkId_, packet);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: InputEventBuilderTest_Freeze_001
 * @tc.desc: Test the funcation Freeze
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_Freeze_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->enable_ = false;
    ASSERT_NO_FATAL_FAILURE(builder_->Freeze());
    builder_->enable_ = true;
    ASSERT_NO_FATAL_FAILURE(builder_->Freeze());
}

/**
 * @tc.name: InputEventBuilderTest_Thaw_001
 * @tc.desc: Test the funcation Thaw
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_Thaw_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->enable_ = false;
    ASSERT_NO_FATAL_FAILURE(builder_->Thaw());
    builder_->enable_ = true;
    ASSERT_NO_FATAL_FAILURE(builder_->Thaw());
}

/**
 * @tc.name: InputEventBuilderTest_Enable_001
 * @tc.desc: Test the funcation Enable
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_Enable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Context context(env_);
    builder_->enable_ = true;
    ASSERT_NO_FATAL_FAILURE(builder_->Enable(context));
    builder_->enable_ = false;
    ASSERT_NO_FATAL_FAILURE(builder_->Enable(context));
}

/**
 * @tc.name: InputEventBuilderTest_UpdatePointerEvent_001
 * @tc.desc: Test the funcation UpdatePointerEvent
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_UpdatePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    bool ret = builder_->UpdatePointerEvent(pointerEvent);
    ASSERT_FALSE(ret);
}


/**
 * @tc.name: InputEventBuilderTest_IsActive_001
 * @tc.desc: Test the funcation IsActive
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_IsActive_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    builder_->freezing_ = true;
    builder_->IsActive(pointerEvent);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_MOVE);
    builder_->IsActive(pointerEvent);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_CANCEL);
    bool ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_IsActive_002
 * @tc.desc: Test the funcation IsActive
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_IsActive_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    builder_->freezing_ = true;
    bool ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_MOVE);
    ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_IsActive_003
 * @tc.desc: Test the funcation IsActive
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_IsActive_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(1);
    pointerEvent->AddPointerItem(pointerItem);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    bool ret = builder_->IsActive(pointerEvent);
    ASSERT_FALSE(ret);
    builder_->xDir_ = 1;
    builder_->IsActive(pointerEvent);
    builder_->movement_ = -1;
    ret = builder_->IsActive(pointerEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_SetDamplingCoefficient
 * @tc.desc: Test the funcation SetDamplingCoefficient
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_SetDamplingCoefficient, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t direction = COORDINATION_DAMPLING_UP;
    double coefficient = 0.5;
    ASSERT_NO_FATAL_FAILURE(builder_->SetDamplingCoefficient(direction, coefficient));
    direction = COORDINATION_DAMPLING_DOWN;
    ASSERT_NO_FATAL_FAILURE(builder_->SetDamplingCoefficient(direction, coefficient));
    direction = COORDINATION_DAMPLING_RIGHT;
    ASSERT_NO_FATAL_FAILURE(builder_->SetDamplingCoefficient(direction, coefficient));
    direction = COORDINATION_DAMPLING_LEFT;
    ASSERT_NO_FATAL_FAILURE(builder_->SetDamplingCoefficient(direction, coefficient));
    direction = COORDINATION_DAMPLING_UP;
    coefficient = 1.5;
    ASSERT_NO_FATAL_FAILURE(builder_->SetDamplingCoefficient(direction, coefficient));
}
/**
 * @tc.name: InputEventBuilderTest_DampPointerMotion_001
 * @tc.desc: Test the funcation DampPointerMotion
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_DampPointerMotion_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int64_t downTime = GetMillisTime();
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);
    item.SetRawDx(60);
    item.SetRawDy(60);
    pointerEvent->AddPointerItem(item);
    bool ret = builder_->DampPointerMotion(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_DampPointerMotion_002
 * @tc.desc: Test the funcation DampPointerMotion
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_DampPointerMotion_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int64_t downTime = GetMillisTime();
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    bool ret = builder_->DampPointerMotion(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_UpdatePointerEvent_002
 * @tc.desc: Test the funcation UpdatePointerEvent
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_UpdatePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    bool ret = builder_->UpdatePointerEvent(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_IsActive_004
 * @tc.desc: Test the funcation IsActive
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_IsActive_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    builder_->xDir_ = 1;
    builder_->movement_ = -1;
    bool ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
    item.SetRawDx(60);
    item.SetRawDy(60);
    pointerEvent->AddPointerItem(item);
    builder_->movement_ = 1;
    ret = builder_->IsActive(pointerEvent);
    ASSERT_FALSE(ret);
    item.SetRawDx(0);
    item.SetRawDy(0);
    builder_->movement_ = 1;
    pointerEvent->AddPointerItem(item);
    builder_->movement_ = 0;
    ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_IsActive_005
 * @tc.desc: Test the funcation IsActive
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_IsActive_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    builder_->xDir_ = 0;
    builder_->movement_ = -1;
    bool  ret = builder_->IsActive(pointerEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputEventBuilderTest_IsActive_006
 * @tc.desc: Test the funcation IsActive
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, InputEventBuilderTest_IsActive_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    builder_->xDir_ = -1;
    builder_->movement_ = -1;
    bool ret = builder_->IsActive(pointerEvent);
    ASSERT_FALSE(ret);
    item.SetRawDx(60);
    item.SetRawDy(60);
    pointerEvent->AddPointerItem(item);
    builder_->movement_ = 1;
    ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
    item.SetRawDx(0);
    item.SetRawDy(0);
    pointerEvent->AddPointerItem(item);
    builder_->movement_ = 0;
    ret = builder_->IsActive(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: ResetPressedEventsTest001
 * @tc.desc: Test ResetPressedEventsTest001
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, ResetPressedEventsTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->remoteNetworkId_ = "1234";
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    int32_t ret1 = InputEventSerialization::Marshalling(pointerEvent, packet);
    ASSERT_EQ(ret1, RET_OK);
    bool ret = builder_->OnPacket(networkId_, packet);
    ASSERT_EQ(ret, true);
    builder_->ResetPressedEvents();
    env_->GetDragManager().SetDragState(DragState::START);
}

/**
 * @tc.name: ResetPressedEventsTest002
 * @tc.desc: Test ResetPressedEventsTest002
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, ResetPressedEventsTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->remoteNetworkId_ = "1234";
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    int32_t ret1 = InputEventSerialization::Marshalling(pointerEvent, packet);
    ASSERT_EQ(ret1, RET_OK);
    bool ret = builder_->OnPacket(networkId_, packet);
    ASSERT_EQ(ret, true);
    env_->GetDragManager().SetDragState(DragState::START);
    builder_->ResetPressedEvents();
}

/**
 * @tc.name: ResetPressedEventsTest003
 * @tc.desc: Test ResetPressedEventsTest003
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, ResetPressedEventsTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->remoteNetworkId_ = "1234";
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::POINTER_ACTION_BUTTON_UP);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    int32_t ret1 = InputEventSerialization::Marshalling(pointerEvent, packet);
    ASSERT_EQ(ret1, RET_OK);
    bool ret = builder_->OnPacket(networkId_, packet);
    ASSERT_EQ(ret, true);
    env_->GetDragManager().SetDragState(DragState::START);
    builder_->ResetPressedEvents();
}

/**
 * @tc.name: ResetPressedEventsTest004
 * @tc.desc: Test ResetPressedEventsTest004
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, ResetPressedEventsTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    builder_->remoteNetworkId_ = "1234";
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    builder_->freezing_ = true;
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_MOVE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::POINTER_ACTION_BUTTON_UP);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetRawDx(-60);
    item.SetRawDy(-60);
    pointerEvent->AddPointerItem(item);
    int32_t ret1 = InputEventSerialization::Marshalling(pointerEvent, packet);
    ASSERT_EQ(ret1, RET_OK);
    bool ret = builder_->OnPacket(networkId_, packet);
    ASSERT_EQ(ret, true);
    env_->GetDragManager().SetDragState(DragState::MOTION_DRAGGING);
    builder_->ResetPressedEvents();
}

/**
 * @tc.name: TagRemoteEvent_keyEvent_001
 * @tc.desc: Test TagRemoteEvent_keyEvent_001
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, TagRemoteEvent_keyEvent_001, TestSize.Level1)
{
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int64_t time = GetMillisTime();
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_A);
    keyEvent->SetActionTime(time);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
    MMI::KeyEvent::KeyItem item1;
    item1.SetPressed(true);
    item1.SetKeyCode(MMI::KeyEvent::KEYCODE_A);
    item1.SetDownTime(time);
    keyEvent->AddKeyItem(item1);
    int32_t deviceId = LOC_INPUT_DEVICE_ID;
    int32_t locVirDeviceId = -(deviceId + 1);
    keyEvent->SetDeviceId(deviceId);
    // builder_->remote2VirtualIds_[1] = 100;
    builder_->TagRemoteEvent(keyEvent);
    ASSERT_EQ(keyEvent->GetDeviceId(), locVirDeviceId);
}

/**
 * @tc.name: TagRemoteEvent_keyEvent_002
 * @tc.desc: Test TagRemoteEvent_keyEvent_002
 * @tc.type: FUNC
 */
HWTEST_F(InputEventBuilderTest, TagRemoteEvent_keyEvent_002, TestSize.Level1)
{
    auto keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int64_t time = GetMillisTime();
    keyEvent->SetKeyCode(MMI::KeyEvent::KEYCODE_A);
    keyEvent->SetActionTime(time);
    keyEvent->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
    MMI::KeyEvent::KeyItem item1;
    item1.SetPressed(true);
    item1.SetKeyCode(MMI::KeyEvent::KEYCODE_A);
    item1.SetDownTime(time);
    keyEvent->AddKeyItem(item1);
    int32_t deviceId = LOC_INPUT_DEVICE_ID;
    int32_t locVirDeviceId = deviceId + MIN_VIRTUAL_INPUT_DEVICE_ID;
    keyEvent->SetDeviceId(deviceId);
    builder_->remote2VirtualIds_[deviceId] = locVirDeviceId;
    builder_->TagRemoteEvent(keyEvent);
    ASSERT_EQ(keyEvent->GetDeviceId(), locVirDeviceId);
    builder_->remote2VirtualIds_.erase(deviceId);
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS